//! # Permission Translation Library
//!
//! A Rust library for translating hexadecimal permission values into human-readable capability sets.
//! This library provides functionality to define permission descriptors, validate permission values,
//! and extract individual capabilities from combined permission hex values.
//!
//! ## Features
//!
//! - **Permission Validation**: Validate hex permission values against capability descriptors
//! - **Capability Extraction**: Extract individual capabilities from combined permission values
//! - **Human-Readable Translation**: Convert hex values to readable capability names
//! - **Flexible Descriptors**: Define custom capability descriptors for different permission systems
//!
//! ## Example Usage
//!
//! ```rust
//! use permission_translation::{
//!     models::{CapabilityDescriptor, CapilityHexValue},
//!     role_capability::RoleCapability,
//!     checks::is_valid_hex,
//! };
//!
//! // Create a capability descriptor
//! let mut descriptor = CapabilityDescriptor::new();
//! descriptor.insert("Administrator".to_string(), 0x1);
//! descriptor.insert("ManageServer".to_string(), 0x2);
//! descriptor.insert("ManageRoles".to_string(), 0x4);
//!
//! // Create a role with combined permissions
//! let permission_value: CapilityHexValue = 0x3; // Administrator + ManageServer
//! let role = RoleCapability::new(descriptor.clone(), permission_value);
//!
//! // Validate the permission value
//! assert!(is_valid_hex(permission_value, &descriptor));
//!
//! // Get human-readable capabilities
//! let capabilities = role.to_name_set();
//! assert!(capabilities.contains("Administrator"));
//! assert!(capabilities.contains("ManageServer"));
//! ```
//!
//! ## Examples
//!
//! The library comes with several examples demonstrating different use cases:
//!
//! - **Quick Start**: `cargo run --example quick_start`
//!   - Minimal example showing the most common usage patterns
//!
//! - **Basic Usage**: `cargo run --example basic_usage`
//!   - Comprehensive demonstration of all library features
//!
//! - **Validation Showcase**: `cargo run --example validation_showcase`
//!   - Advanced validation features and edge cases
//!
//! ## Modules
//!
//! - [`models`]: Core type definitions and data structures
//! - [`checks`]: Validation functions for permission values and descriptors
//! - [`role_capability`]: Main struct for working with role permissions

pub mod checks;
pub mod models;
pub mod role_capability;
