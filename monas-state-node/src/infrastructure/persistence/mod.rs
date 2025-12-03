//! Persistence implementations for data storage.
//!
//! This module provides persistent storage implementations using sled.
//!
//! ## Future WASM Support
//!
//! IndexedDB implementations are prepared in separate files for future browser support:
//! - `indexeddb_node_registry.rs` - Node registry using IndexedDB
//! - `indexeddb_content_repository.rs` - Content repository using IndexedDB
//!
//! These use `WasmNodeRegistry` and `WasmContentRepository` traits which are
//! `?Send` to accommodate browser's single-threaded nature.

pub mod sled_content_network_repository;
pub mod sled_node_registry;

// Re-export sled implementations
pub use sled_content_network_repository::SledContentNetworkRepository;
pub use sled_node_registry::SledNodeRegistry;

// Future WASM implementations (prepared but not compiled by default)
// To enable, add cfg(target_arch = "wasm32") and required dependencies
// pub mod indexeddb_node_registry;
// pub mod indexeddb_content_repository;
