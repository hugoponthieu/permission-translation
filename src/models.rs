//! # Models Module
//!
//! This module defines the core data types and structures used throughout the permission translation library.
//! All types are designed to provide type safety and clarity when working with permission systems.
//!
//! ## Type Overview
//!
//! The types in this module follow a hierarchical structure:
//! - Individual capabilities are represented by names and hex values
//! - Descriptors map capability names to their hex values
//! - Combined permission values represent multiple capabilities
//! - Sets provide collections of capabilities in different formats

use std::collections::{HashMap, HashSet};

/// A human-readable name for a capability or permission.
///
/// This type represents capability names such as "SendMessage", "ManageChannel",
/// "Administrator", etc. Using a type alias improves code readability and
/// provides a clear semantic meaning.
///
/// # Examples
///
/// ```rust
/// use permission_translation::models::CapabilityName;
///
/// let capability: CapabilityName = "Administrator".to_string();
/// let another_capability: CapabilityName = "ManageServer".to_string();
/// ```
pub type CapabilityName = String;

/// A hexadecimal value representing a single capability unit.
///
/// Each capability is assigned a unique power-of-2 hex value to enable
/// bitwise operations. This allows multiple capabilities to be combined
/// using bitwise OR operations.
///
/// # Examples
///
/// ```rust
/// use permission_translation::models::CapabilityHexUnitValue;
///
/// let admin_permission: CapabilityHexUnitValue = 0x1;        // Binary: 0001
/// let manage_server: CapabilityHexUnitValue = 0x2;          // Binary: 0010
/// let manage_roles: CapabilityHexUnitValue = 0x4;           // Binary: 0100
/// ```
pub type CapabilityHexUnitValue = i32;

/// A mapping between capability names and their corresponding hexadecimal values.
///
/// This descriptor defines the available capabilities in a permission system
/// and their associated hex values. It serves as the authoritative source
/// for validating and translating permission values.
///
/// # Design Notes
///
/// - Each capability should have a unique power-of-2 hex value
/// - The descriptor is flexible and doesn't predefine specific capabilities
/// - This allows the library to work with different permission systems
///
/// # Examples
///
/// ```rust
/// use permission_translation::models::{CapabilityDescriptor, CapabilityHexUnitValue};
///
/// let mut descriptor = CapabilityDescriptor::new();
/// descriptor.insert("Administrator".to_string(), 0x1);
/// descriptor.insert("ManageServer".to_string(), 0x2);
/// descriptor.insert("ManageRoles".to_string(), 0x4);
/// descriptor.insert("CreateInvitation".to_string(), 0x8);
/// ```
pub type CapabilityDescriptor = HashMap<CapabilityName, CapabilityHexUnitValue>;

/// A combined permission value representing multiple capabilities.
///
/// This value is typically stored in user roles or permission records and
/// represents the bitwise OR combination of multiple capability hex values.
/// The library can extract individual capabilities from this combined value.
///
/// # Examples
///
/// ```rust
/// use permission_translation::models::CapilityHexValue;
///
/// // Administrator (0x1) + ManageServer (0x2) = 0x3
/// let combined_permissions: CapilityHexValue = 0x1 | 0x2; // = 0x3
///
/// // Administrator + ManageServer + ManageRoles = 0x7
/// let full_permissions: CapilityHexValue = 0x1 | 0x2 | 0x4; // = 0x7
/// ```
pub type CapilityHexValue = i32;

/// A set of individual capability hex values extracted from a combined permission.
///
/// This type represents a collection of unique capability hex values that
/// have been extracted from a combined permission value. It's useful for
/// programmatic processing of capabilities.
///
/// # Examples
///
/// ```rust
/// use permission_translation::models::{CapabilityHexUnitSet, CapabilityHexUnitValue};
///
/// let mut hex_set = CapabilityHexUnitSet::new();
/// hex_set.insert(0x1); // Administrator
/// hex_set.insert(0x2); // ManageServer
/// hex_set.insert(0x4); // ManageRoles
/// ```
pub type CapabilityHexUnitSet = HashSet<CapabilityHexUnitValue>;

/// A set of human-readable capability names extracted from a combined permission.
///
/// This type represents a collection of capability names that have been
/// extracted from a combined permission value. It's the most user-friendly
/// representation of a role's capabilities.
///
/// # Examples
///
/// ```rust
/// use permission_translation::models::CapabilityNameSet;
///
/// let mut name_set = CapabilityNameSet::new();
/// name_set.insert("Administrator".to_string());
/// name_set.insert("ManageServer".to_string());
/// name_set.insert("ManageRoles".to_string());
/// ```
pub type CapabilityNameSet = HashSet<CapabilityName>;
