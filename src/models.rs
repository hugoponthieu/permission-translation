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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_descriptor_creation() {
        let mut descriptor = CapabilityDescriptor::new();
        assert!(descriptor.is_empty());

        descriptor.insert("Read".to_string(), 0x1);
        descriptor.insert("Write".to_string(), 0x2);

        assert_eq!(descriptor.len(), 2);
        assert_eq!(descriptor.get("Read"), Some(&0x1));
        assert_eq!(descriptor.get("Write"), Some(&0x2));
        assert_eq!(descriptor.get("NonExistent"), None);
    }

    #[test]
    fn test_capability_hex_unit_set_operations() {
        let mut hex_set = CapabilityHexUnitSet::new();
        assert!(hex_set.is_empty());

        hex_set.insert(0x1);
        hex_set.insert(0x2);
        hex_set.insert(0x4);

        assert_eq!(hex_set.len(), 3);
        assert!(hex_set.contains(&0x1));
        assert!(hex_set.contains(&0x2));
        assert!(hex_set.contains(&0x4));
        assert!(!hex_set.contains(&0x8));

        // Test deduplication
        hex_set.insert(0x1); // Already exists
        assert_eq!(hex_set.len(), 3); // Should still be 3
    }

    #[test]
    fn test_capability_name_set_operations() {
        let mut name_set = CapabilityNameSet::new();
        assert!(name_set.is_empty());

        name_set.insert("Read".to_string());
        name_set.insert("Write".to_string());
        name_set.insert("Execute".to_string());

        assert_eq!(name_set.len(), 3);
        assert!(name_set.contains("Read"));
        assert!(name_set.contains("Write"));
        assert!(name_set.contains("Execute"));
        assert!(!name_set.contains("Admin"));

        // Test deduplication
        name_set.insert("Read".to_string()); // Already exists
        assert_eq!(name_set.len(), 3); // Should still be 3
    }

    #[test]
    fn test_capability_name_type() {
        let capability: CapabilityName = "Administrator".to_string();
        assert_eq!(capability, "Administrator");

        let capability2: CapabilityName = String::from("ManageServer");
        assert_eq!(capability2, "ManageServer");

        // Test that it's actually a String
        assert_eq!(capability.len(), 13);
        assert!(capability.starts_with("Admin"));
    }

    #[test]
    fn test_capability_hex_unit_value_type() {
        let value: CapabilityHexUnitValue = 0x1;
        assert_eq!(value, 1);

        let value2: CapabilityHexUnitValue = 0x10;
        assert_eq!(value2, 16);

        // Test bitwise operations work
        let combined = value | value2;
        assert_eq!(combined, 0x11);

        // Test that it's actually an i32
        let max_value: CapabilityHexUnitValue = i32::MAX;
        assert_eq!(max_value, 2147483647);
    }

    #[test]
    fn test_capability_hex_value_type() {
        let value: CapilityHexValue = 0x7; // Multiple permissions combined
        assert_eq!(value, 7);

        // Test that it can represent combined permissions
        let read: CapabilityHexUnitValue = 0x1;
        let write: CapabilityHexUnitValue = 0x2;
        let execute: CapabilityHexUnitValue = 0x4;

        let combined: CapilityHexValue = read | write | execute;
        assert_eq!(combined, 0x7);
        assert_eq!(combined, value);
    }

    #[test]
    fn test_descriptor_with_power_of_two_values() {
        let mut descriptor = CapabilityDescriptor::new();

        // Add powers of 2 (typical permission pattern)
        descriptor.insert("Permission0".to_string(), 0x1); // 2^0 = 1
        descriptor.insert("Permission1".to_string(), 0x2); // 2^1 = 2
        descriptor.insert("Permission2".to_string(), 0x4); // 2^2 = 4
        descriptor.insert("Permission3".to_string(), 0x8); // 2^3 = 8
        descriptor.insert("Permission4".to_string(), 0x10); // 2^4 = 16

        assert_eq!(descriptor.len(), 5);

        // Test that all values are unique
        let values: Vec<&CapabilityHexUnitValue> = descriptor.values().collect();
        let mut sorted_values = values.clone();
        sorted_values.sort();

        assert_eq!(sorted_values, vec![&0x1, &0x2, &0x4, &0x8, &0x10]);
    }

    #[test]
    fn test_descriptor_with_overlapping_values() {
        let mut descriptor = CapabilityDescriptor::new();

        // Add overlapping bit patterns (unusual but possible)
        descriptor.insert("Permission1".to_string(), 0x3); // Binary: 11
        descriptor.insert("Permission2".to_string(), 0x1); // Binary: 01 (overlaps)
        descriptor.insert("Permission3".to_string(), 0x2); // Binary: 10 (overlaps)

        assert_eq!(descriptor.len(), 3);

        // All values should be retrievable
        assert_eq!(descriptor.get("Permission1"), Some(&0x3));
        assert_eq!(descriptor.get("Permission2"), Some(&0x1));
        assert_eq!(descriptor.get("Permission3"), Some(&0x2));
    }

    #[test]
    fn test_sets_with_real_world_data() {
        // Test with realistic server permission names
        let mut name_set = CapabilityNameSet::new();
        name_set.insert("SendMessage".to_string());
        name_set.insert("ManageChannel".to_string());
        name_set.insert("ManageServer".to_string());
        name_set.insert("Administrator".to_string());
        name_set.insert("CreateInvitation".to_string());
        name_set.insert("BanMembers".to_string());

        assert_eq!(name_set.len(), 6);

        // Test corresponding hex values
        let mut hex_set = CapabilityHexUnitSet::new();
        hex_set.insert(0x1); // SendMessage
        hex_set.insert(0x2); // ManageChannel
        hex_set.insert(0x4); // ManageServer
        hex_set.insert(0x8); // Administrator
        hex_set.insert(0x10); // CreateInvitation
        hex_set.insert(0x20); // BanMembers

        assert_eq!(hex_set.len(), 6);

        // Test that we can combine these values
        let all_permissions: CapilityHexValue = 0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x20;
        assert_eq!(all_permissions, 0x3F); // 111111 in binary = 63
    }

    #[test]
    fn test_type_aliases_are_correct_types() {
        // Ensure our type aliases are the expected underlying types
        let name: CapabilityName = String::new();
        let _: String = name; // Should compile without error

        let unit_value: CapabilityHexUnitValue = 0;
        let _: i32 = unit_value; // Should compile without error

        let hex_value: CapilityHexValue = 0;
        let _: i32 = hex_value; // Should compile without error

        let descriptor: CapabilityDescriptor = HashMap::new();
        let _: HashMap<String, i32> = descriptor; // Should compile without error

        let hex_set: CapabilityHexUnitSet = HashSet::new();
        let _: HashSet<i32> = hex_set; // Should compile without error

        let name_set: CapabilityNameSet = HashSet::new();
        let _: HashSet<String> = name_set; // Should compile without error
    }
}
