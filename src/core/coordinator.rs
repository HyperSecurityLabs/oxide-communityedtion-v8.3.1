use std::sync::atomic::{AtomicUsize, Ordering};

pub struct Coordinator {
    total_tasks: AtomicUsize,
}

impl Coordinator {
    pub fn new(total: usize) -> Self {
        Self {
            total_tasks: AtomicUsize::new(total),
        }
    }
}

impl Clone for Coordinator {
    fn clone(&self) -> Self {
        Self {
            total_tasks: AtomicUsize::new(self.total_tasks.load(Ordering::SeqCst)),
        }
    }
}
