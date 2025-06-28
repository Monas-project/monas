use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Storage {
    total_capacity: u64,
    used_capacity: u64,
}

#[derive(Debug, PartialEq)]
pub enum StorageError {
    InsufficientCapacity {
        required: u64,
        available: u64,
    },
    InvalidCapacity,
}

impl Storage {
    pub fn new(total_capacity: u64) -> Result<Self, StorageError> {
        if total_capacity == 0 {
            return Err(StorageError::InvalidCapacity);
        }
        
        Ok(Self {
            total_capacity,
            used_capacity: 0,
        })
    }

    pub fn allocate(&self, amount: u64) -> Result<Self, StorageError> {
        if self.available_capacity() < amount {
            return Err(StorageError::InsufficientCapacity {
                required: amount,
                available: self.available_capacity(),
            });
        }

        Ok(Self {
            total_capacity: self.total_capacity,
            used_capacity: self.used_capacity + amount,
        })
    }

    pub fn deallocate(&self, amount: u64) -> Self {
        let new_used = self.used_capacity.saturating_sub(amount);
        Self {
            total_capacity: self.total_capacity,
            used_capacity: new_used,
        }
    }

    pub fn available_capacity(&self) -> u64 {
        self.total_capacity.saturating_sub(self.used_capacity)
    }

    pub fn total_capacity(&self) -> u64 {
        self.total_capacity
    }

    pub fn used_capacity(&self) -> u64 {
        self.used_capacity
    }

    pub fn utilization_percentage(&self) -> f64 {
        if self.total_capacity == 0 {
            0.0
        } else {
            (self.used_capacity as f64 / self.total_capacity as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_creation() {
        let storage = Storage::new(1000).unwrap();
        assert_eq!(storage.total_capacity(), 1000);
        assert_eq!(storage.used_capacity(), 0);
        assert_eq!(storage.available_capacity(), 1000);
    }

    #[test]
    fn test_storage_allocation() {
        let storage = Storage::new(1000).unwrap();
        let allocated = storage.allocate(300).unwrap();
        
        assert_eq!(allocated.used_capacity(), 300);
        assert_eq!(allocated.available_capacity(), 700);
    }

    #[test]
    fn test_insufficient_capacity() {
        let storage = Storage::new(100).unwrap();
        let result = storage.allocate(200);
        
        assert!(matches!(result, Err(StorageError::InsufficientCapacity { .. })));
    }

    #[test]
    fn test_deallocation() {
        let storage = Storage::new(1000).unwrap();
        let allocated = storage.allocate(300).unwrap();
        let deallocated = allocated.deallocate(100);
        
        assert_eq!(deallocated.used_capacity(), 200);
        assert_eq!(deallocated.available_capacity(), 800);
    }
} 