//! # Checks Module
//!
//! This module provides validation functions for permission values and capability descriptors.
//! It ensures data integrity and validates that permission values conform to their descriptors.
//!
//! ## Validation Functions
//!
//! - [`is_valid_hex`]: Validates a permission value against a capability descriptor
//! - [`get_max_hex_value_descriptor`]: Calculates the maximum possible permission value for a descriptor
//!
//! ## Validation Rules
//!
//! The validation functions enforce several important rules:
//! 1. **Descriptor Integrity**: The OR mask of descriptor values must not exceed their sum
//! 2. **Valid Bits Only**: Permission values can only have bits set that are defined in the descriptor
//! 3. **Maximum Permission**: Permission values cannot exceed the maximum allowed by the descriptor

use crate::models::{CapabilityDescriptor, CapilityHexValue};

/// Validates a hexadecimal permission value against a capability descriptor.
///
/// This function performs comprehensive validation to ensure the permission value is valid:
/// 1. Validates descriptor integrity (OR mask ≤ sum of values)
/// 2. Ensures no invalid bits are set outside the descriptor's defined capabilities
/// 3. Ensures the value doesn't exceed the maximum permission allowed by the descriptor
///
/// # Arguments
///
/// * `value` - The hexadecimal permission value to validate
/// * `descriptor` - The capability descriptor defining valid permissions
///
/// # Returns
///
/// * `true` if the permission value is valid according to all validation rules
/// * `false` if any validation rule fails
///
/// # Examples
///
/// ```rust
/// use permission_translation::{models::CapabilityDescriptor, checks::is_valid_hex};
///
/// let mut descriptor = CapabilityDescriptor::new();
/// descriptor.insert("Admin".to_string(), 0x1);
/// descriptor.insert("User".to_string(), 0x2);
///
/// // Valid permission values
/// assert!(is_valid_hex(0x1, &descriptor)); // Admin only
/// assert!(is_valid_hex(0x2, &descriptor)); // User only
/// assert!(is_valid_hex(0x3, &descriptor)); // Admin + User
///
/// // Invalid permission values
/// assert!(!is_valid_hex(0x4, &descriptor)); // Undefined bit
/// assert!(!is_valid_hex(0x8, &descriptor)); // Exceeds maximum
/// ```
///
/// # Validation Details
///
/// ## Descriptor Integrity Check
/// Validates that the OR combination of all descriptor values doesn't exceed their arithmetic sum.
/// This mathematical property should always hold for valid descriptors.
///
/// ## Invalid Bits Check
/// Ensures the permission value only uses bits that are defined in the descriptor.
/// Any bits set outside the valid mask will cause validation to fail.
///
/// ## Maximum Permission Check
/// Ensures the permission value doesn't exceed the theoretical maximum (all permissions combined).
/// This prevents values that might be mathematically valid but exceed intended limits.
pub fn is_valid_hex(value: CapilityHexValue, descriptor: &CapabilityDescriptor) -> bool {
    // Combine all unit values from the descriptor
    // to form a mask of valid bits.
    let mut combined_value: CapilityHexValue = 0;
    let mut sum_value: CapilityHexValue = 0;
    for &unit_value in descriptor.values() {
        combined_value |= unit_value;
        sum_value += unit_value;
    }

    // Check that the mask doesn't exceed the sum of descriptor values
    // This validates the integrity of the descriptor data
    if combined_value > sum_value {
        return false;
    }

    // Check if the provided value has any bits
    // set outside of this mask.
    if (value & !combined_value) != 0 {
        return false;
    }

    // Check if the value exceeds the maximum permission
    // allowed by the descriptor (which is the combination of all permissions)
    if value > combined_value {
        return false;
    }

    true
}

/// Calculates the maximum possible hexadecimal permission value for a given descriptor.
///
/// This function computes the theoretical maximum permission value by combining all
/// individual capability values in the descriptor using bitwise OR operations.
/// The result represents a permission set with all possible capabilities enabled.
///
/// # Arguments
///
/// * `descriptor` - The capability descriptor to calculate the maximum value for
///
/// # Returns
///
/// The maximum possible permission value (bitwise OR of all descriptor values)
///
/// # Examples
///
/// ```rust
/// use permission_translation::{models::CapabilityDescriptor, checks::get_max_hex_value_descriptor};
///
/// let mut descriptor = CapabilityDescriptor::new();
/// descriptor.insert("Read".to_string(), 0x1);    // Binary: 0001
/// descriptor.insert("Write".to_string(), 0x2);   // Binary: 0010
/// descriptor.insert("Execute".to_string(), 0x4); // Binary: 0100
///
/// let max_value = get_max_hex_value_descriptor(&descriptor);
/// assert_eq!(max_value, 0x7); // Binary: 0111 (all permissions combined)
/// ```
///
/// # Use Cases
///
/// - **Validation**: Use with [`is_valid_hex`] to validate permission values
/// - **Permission Management**: Determine the full permission set for administrative roles
/// - **Capability Discovery**: Understand the complete range of available permissions
/// - **Testing**: Generate test cases with maximum permission scenarios
///
/// # Performance
///
/// This function iterates through all values in the descriptor once, making it O(n)
/// where n is the number of capabilities in the descriptor.
pub fn get_max_hex_value_descriptor(descriptor: &CapabilityDescriptor) -> CapilityHexValue {
    let mut max_value: CapilityHexValue = 0;
    for &unit_value in descriptor.values() {
        max_value |= unit_value;
    }
    max_value
}

pub fn get_sum_hex_value_descriptor(descriptor: &CapabilityDescriptor) -> CapilityHexValue {
    let mut sum_value: CapilityHexValue = 0;
    for &unit_value in descriptor.values() {
        sum_value += unit_value;
    }
    sum_value
}
