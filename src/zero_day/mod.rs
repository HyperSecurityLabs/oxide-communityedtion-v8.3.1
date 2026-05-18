//! Zero-Day Detection Module
//! AI-powered vulnerability detection using statistical ML
//! 
//! Uses real ML libraries:
//! - smartcore: Machine learning algorithms (Random Forest, SVM)
//! - linfa: Clustering and preprocessing
//! - ndarray: N-dimensional arrays for ML data
//! - statrs: Statistical distributions and tests

pub mod features;
pub mod classifier;
pub mod baseline;
pub mod anomaly;
pub mod engine;
pub mod trainer;
