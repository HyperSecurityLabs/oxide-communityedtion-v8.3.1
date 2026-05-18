use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};

/// Adaptive rate limiter with circuit breaker pattern
pub struct AdaptiveRateLimiter {
    config: Arc<RwLock<RateLimitConfig>>,
    request_history: Arc<Mutex<VecDeque<RequestRecord>>>,
    circuit_state: Arc<RwLock<CircuitState>>,
    consecutive_failures: Arc<RwLock<u32>>,
    last_failure: Arc<RwLock<Option<Instant>>>,
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Base requests per second
    pub base_rps: f64,
    /// Maximum requests per second (burst)
    pub max_rps: f64,
    /// Minimum requests per second (circuit open)
    pub min_rps: f64,
    /// Adaptive multiplier when target is responsive
    pub adaptive_multiplier: f64,
    /// Window size for statistics
    pub window_size: Duration,
    /// Circuit breaker threshold
    pub circuit_threshold: u32,
    /// Circuit breaker timeout
    pub circuit_timeout: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            base_rps: 10.0,
            max_rps: 100.0,
            min_rps: 1.0,
            adaptive_multiplier: 1.5,
            window_size: Duration::from_secs(60),
            circuit_threshold: 5,
            circuit_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CircuitState {
    Closed,      // Normal operation
    Open,        // Circuit open, rate limited
    HalfOpen,    // Testing if target recovered
}

#[derive(Debug)]
struct RequestRecord {
    timestamp: Instant,
    success: bool,
    response_time: Duration,
}

impl AdaptiveRateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            request_history: Arc::new(Mutex::new(VecDeque::new())),
            circuit_state: Arc::new(RwLock::new(CircuitState::Closed)),
            consecutive_failures: Arc::new(RwLock::new(0)),
            last_failure: Arc::new(RwLock::new(None)),
        }
    }

    /// Check if request should be allowed
    pub async fn allow_request(&self) -> bool {
        let config = self.config.read().await;
        let circuit = *self.circuit_state.read().await;
        
        // Check circuit breaker state
        match circuit {
            CircuitState::Open => {
                // Check if we can transition to half-open
                let last_fail = *self.last_failure.read().await;
                if let Some(last) = last_fail {
                    if last.elapsed() > config.circuit_timeout {
                        println!("[RATE] Circuit breaker entering half-open state");
                        *self.circuit_state.write().await = CircuitState::HalfOpen;
                        *self.consecutive_failures.write().await = 0;
                        return true;
                    }
                }
                return false;
            }
            CircuitState::HalfOpen => {
                // Allow limited requests in half-open
                return true;
            }
            CircuitState::Closed => {
                // Continue with normal rate limiting
            }
        }
        
        // Calculate current request rate
        let current_rps = self.calculate_current_rps().await;
        let target_rps = self.calculate_target_rps().await;
        
        current_rps < target_rps
    }

    /// Record successful request
    pub async fn record_success(&self, response_time: Duration) {
        let record = RequestRecord {
            timestamp: Instant::now(),
            success: true,
            response_time,
        };
        
        let mut history = self.request_history.lock().await;
        history.push_back(record);
        self.cleanup_old_records(&mut history).await;
        
        // Reset circuit breaker on success
        *self.consecutive_failures.write().await = 0;
        
        let circuit = *self.circuit_state.read().await;
        if circuit == CircuitState::HalfOpen {
            println!("[RATE] Target responsive, closing circuit breaker");
            *self.circuit_state.write().await = CircuitState::Closed;
        }
    }

    /// Record failed request
    pub async fn record_failure(&self) {
        let record = RequestRecord {
            timestamp: Instant::now(),
            success: false,
            response_time: Duration::from_secs(0),
        };
        
        let mut history = self.request_history.lock().await;
        history.push_back(record);
        self.cleanup_old_records(&mut history).await;
        
        // Update consecutive failures
        let mut failures = self.consecutive_failures.write().await;
        *failures += 1;
        
        let config = self.config.read().await;
        
        // Check if we should open circuit
        if *failures >= config.circuit_threshold {
            let circuit = *self.circuit_state.read().await;
            if circuit == CircuitState::Closed {
                println!("[RATE] Circuit breaker opened after {} consecutive failures", failures);
                *self.circuit_state.write().await = CircuitState::Open;
                *self.last_failure.write().await = Some(Instant::now());
            }
        }
    }

    /// Calculate current requests per second
    async fn calculate_current_rps(&self) -> f64 {
        let history = self.request_history.lock().await;
        let window_start = Instant::now() - Duration::from_secs(1);
        
        let recent_count = history.iter()
            .filter(|r| r.timestamp > window_start)
            .count();
        
        recent_count as f64
    }

    /// Calculate target rate based on recent performance
    async fn calculate_target_rps(&self) -> f64 {
        let config = self.config.read().await;
        let history = self.request_history.lock().await;
        
        if history.is_empty() {
            return config.base_rps;
        }
        
        // Calculate success rate
        let window_start = Instant::now() - config.window_size;
        let window_requests: Vec<_> = history.iter()
            .filter(|r| r.timestamp > window_start)
            .collect();
        
        let total = window_requests.len() as f64;
        let success_count = window_requests.iter().filter(|r| r.success).count() as f64;
        
        if total == 0.0 {
            return config.base_rps;
        }
        
        let success_rate = success_count / total;
        let avg_response_time = if success_count > 0.0 {
            let total_time: u128 = window_requests.iter()
                .filter(|r| r.success)
                .map(|r| r.response_time.as_millis())
                .sum();
            (total_time as f64) / success_count
        } else {
            1000.0 // Default to slow if no successful requests
        };
        
        // Adaptive rate calculation
        let mut target_rps = config.base_rps;
        
        if success_rate > 0.95 && avg_response_time < 500.0 {
            // Good performance, increase rate
            target_rps = (target_rps * config.adaptive_multiplier).min(config.max_rps);
            println!("[RATE] Performance good, increasing to {:.1} rps", target_rps);
        } else if success_rate < 0.8 || avg_response_time > 2000.0 {
            // Poor performance, decrease rate
            target_rps = (target_rps / config.adaptive_multiplier).max(config.min_rps);
            println!("[RATE] Performance poor, decreasing to {:.1} rps", target_rps);
        }
        
        target_rps
    }

    /// Cleanup old records outside window
    async fn cleanup_old_records(&self, history: &mut VecDeque<RequestRecord>) {
        let config = self.config.read().await;
        let cutoff = Instant::now() - config.window_size;
        
        while let Some(front) = history.front() {
            if front.timestamp < cutoff {
                history.pop_front();
            } else {
                break;
            }
        }
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> RateLimitStats {
        let config = self.config.read().await;
        let history = self.request_history.lock().await;
        let circuit = *self.circuit_state.read().await;
        
        let window_start = Instant::now() - config.window_size;
        let window_requests: Vec<_> = history.iter()
            .filter(|r| r.timestamp > window_start)
            .collect();
        
        let total = window_requests.len();
        let success_count = window_requests.iter().filter(|r| r.success).count();
        let failure_count = total - success_count;
        
        let avg_response_time = if success_count > 0 {
            let total_time: u128 = window_requests.iter()
                .filter(|r| r.success)
                .map(|r| r.response_time.as_millis())
                .sum();
            (total_time as f64) / success_count as f64
        } else {
            0.0
        };
        
        RateLimitStats {
            current_rps: self.calculate_current_rps().await,
            target_rps: self.calculate_target_rps().await,
            total_requests: total,
            success_count,
            failure_count,
            success_rate: if total > 0 { success_count as f64 / total as f64 } else { 1.0 },
            avg_response_ms: avg_response_time,
            circuit_state: circuit,
            consecutive_failures: *self.consecutive_failures.read().await,
        }
    }

    /// Update configuration
    pub async fn update_config(&self, new_config: RateLimitConfig) {
        *self.config.write().await = new_config;
    }

    /// Manually reset circuit breaker
    pub async fn reset_circuit(&self) {
        println!("[RATE] Manually resetting circuit breaker");
        *self.circuit_state.write().await = CircuitState::Closed;
        *self.consecutive_failures.write().await = 0;
        *self.last_failure.write().await = None;
    }
}

#[derive(Debug)]
pub struct RateLimitStats {
    pub current_rps: f64,
    pub target_rps: f64,
    pub total_requests: usize,
    pub success_count: usize,
    pub failure_count: usize,
    pub success_rate: f64,
    pub avg_response_ms: f64,
    pub circuit_state: CircuitState,
    pub consecutive_failures: u32,
}

/// Simple token bucket rate limiter for burst control
pub struct TokenBucket {
    tokens: Arc<Mutex<f64>>,
    max_tokens: f64,
    refill_rate: f64,
    last_refill: Arc<Mutex<Instant>>,
}

impl TokenBucket {
    pub fn new(max_tokens: f64, refill_rate: f64) -> Self {
        Self {
            tokens: Arc::new(Mutex::new(max_tokens)),
            max_tokens,
            refill_rate,
            last_refill: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// Try to consume a token
    pub async fn consume(&self, count: f64) -> bool {
        self.refill().await;
        
        let mut tokens = self.tokens.lock().await;
        if *tokens >= count {
            *tokens -= count;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time
    async fn refill(&self) {
        let mut last_refill = self.last_refill.lock().await;
        let mut tokens = self.tokens.lock().await;
        
        let elapsed = last_refill.elapsed().as_secs_f64();
        let new_tokens = elapsed * self.refill_rate;
        
        *tokens = (*tokens + new_tokens).min(self.max_tokens);
        *last_refill = Instant::now();
    }

    /// Get current token count
    pub async fn available(&self) -> f64 {
        self.refill().await;
        *self.tokens.lock().await
    }
}
