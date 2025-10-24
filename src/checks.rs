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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::CapabilityDescriptor;

    fn create_test_descriptor() -> CapabilityDescriptor {
        let mut descriptor = CapabilityDescriptor::new();
        descriptor.insert("Read".to_string(), 0x1);
        descriptor.insert("Write".to_string(), 0x2);
        descriptor.insert("Execute".to_string(), 0x4);
        descriptor.insert("Admin".to_string(), 0x8);
        descriptor
    }

    #[test]
    fn test_is_valid_hex_valid_permissions() {
        let descriptor = create_test_descriptor();

        assert!(is_valid_hex(0x0, &descriptor)); // No permissions
        assert!(is_valid_hex(0x1, &descriptor)); // Read only
        assert!(is_valid_hex(0x3, &descriptor)); // Read + Write
        assert!(is_valid_hex(0x7, &descriptor)); // Read + Write + Execute
        assert!(is_valid_hex(0xF, &descriptor)); // All permissions
    }

    #[test]
    fn test_is_valid_hex_invalid_permissions() {
        let descriptor = create_test_descriptor();

        assert!(!is_valid_hex(0x10, &descriptor)); // Invalid bit (16)
        assert!(!is_valid_hex(0x20, &descriptor)); // Invalid bit (32)
        assert!(!is_valid_hex(0xFF, &descriptor)); // Way too high (255)
        assert!(!is_valid_hex(0x100, &descriptor)); // Even higher (256)
    }

    #[test]
    fn test_is_valid_hex_empty_descriptor() {
        let descriptor = CapabilityDescriptor::new();

        assert!(is_valid_hex(0x0, &descriptor)); // Empty is valid
        assert!(!is_valid_hex(0x1, &descriptor)); // Any bit is invalid
        assert!(!is_valid_hex(0x2, &descriptor)); // Any bit is invalid
    }

    #[test]
    fn test_is_valid_hex_single_permission() {
        let mut descriptor = CapabilityDescriptor::new();
        descriptor.insert("OnlyPermission".to_string(), 0x4);

        assert!(is_valid_hex(0x0, &descriptor)); // No permissions
        assert!(is_valid_hex(0x4, &descriptor)); // The one permission
        assert!(!is_valid_hex(0x1, &descriptor)); // Different bit
        assert!(!is_valid_hex(0x2, &descriptor)); // Different bit
        assert!(!is_valid_hex(0x8, &descriptor)); // Higher bit
    }

    #[test]
    fn test_get_max_hex_value_descriptor() {
        let descriptor = create_test_descriptor();
        assert_eq!(get_max_hex_value_descriptor(&descriptor), 0xF);

        let empty_descriptor = CapabilityDescriptor::new();
        assert_eq!(get_max_hex_value_descriptor(&empty_descriptor), 0x0);

        let mut single_descriptor = CapabilityDescriptor::new();
        single_descriptor.insert("Single".to_string(), 0x8);
        assert_eq!(get_max_hex_value_descriptor(&single_descriptor), 0x8);
    }

    #[test]
    fn test_get_sum_hex_value_descriptor() {
        let descriptor = create_test_descriptor();
        // Sum: 0x1 + 0x2 + 0x4 + 0x8 = 0xF
        assert_eq!(get_sum_hex_value_descriptor(&descriptor), 0xF);

        let empty_descriptor = CapabilityDescriptor::new();
        assert_eq!(get_sum_hex_value_descriptor(&empty_descriptor), 0x0);

        // Test with overlapping bits to show difference between OR and sum
        let mut overlapping_descriptor = CapabilityDescriptor::new();
        overlapping_descriptor.insert("Permission1".to_string(), 0x3); // Binary: 11
        overlapping_descriptor.insert("Permission2".to_string(), 0x1); // Binary: 01 (overlaps)

        // OR: 0x3 | 0x1 = 0x3, Sum: 0x3 + 0x1 = 0x4
        assert_eq!(get_max_hex_value_descriptor(&overlapping_descriptor), 0x3);
        assert_eq!(get_sum_hex_value_descriptor(&overlapping_descriptor), 0x4);
    }

    #[test]
    fn test_descriptor_integrity_validation() {
        // Test normal case where OR equals sum (no overlapping bits)
        let descriptor = create_test_descriptor();
        let max_value = get_max_hex_value_descriptor(&descriptor);
        let sum_value = get_sum_hex_value_descriptor(&descriptor);
        assert_eq!(max_value, sum_value); // Should be equal for power-of-2 values
        assert!(is_valid_hex(max_value, &descriptor));
    }

    #[test]
    fn test_large_permission_system() {
        let mut large_descriptor = CapabilityDescriptor::new();
        for i in 0..10 {
            large_descriptor.insert(format!("Permission{}", i), 1 << i);
        }

        let max_value = get_max_hex_value_descriptor(&large_descriptor);
        assert_eq!(max_value, 0x3FF); // 10 bits: 1111111111 = 1023

        // Test valid values
        assert!(is_valid_hex(0x0, &large_descriptor));
        assert!(is_valid_hex(0x1, &large_descriptor));
        assert!(is_valid_hex(0x3FF, &large_descriptor)); // All permissions
        assert!(is_valid_hex(0x155, &large_descriptor)); // Alternating bits: 101010101

        // Test invalid values
        assert!(!is_valid_hex(0x400, &large_descriptor)); // Bit 11 (1024)
        assert!(!is_valid_hex(0x800, &large_descriptor)); // Bit 12 (2048)
    }

    #[test]
    fn test_boundary_conditions() {
        // Test with maximum i32 values
        let mut max_descriptor = CapabilityDescriptor::new();
        max_descriptor.insert("MaxPermission".to_string(), 0x40000000); // Bit 30

        assert!(is_valid_hex(0x0, &max_descriptor));
        assert!(is_valid_hex(0x40000000, &max_descriptor));
        assert!(!is_valid_hex(0x80000000u32 as i32, &max_descriptor)); // This would be negative

        // Test edge case with negative numbers (though shouldn't happen in practice)
        let mut negative_descriptor = CapabilityDescriptor::new();
        negative_descriptor.insert("NegativeTest".to_string(), -1);

        // This tests the robustness of our validation with unexpected inputs
        assert!(!is_valid_hex(1, &negative_descriptor)); // Should handle gracefully
    }

    #[test]
    fn test_zero_permission_value() {
        let descriptor = create_test_descriptor();

        // Zero should always be valid (represents "no permissions")
        assert!(is_valid_hex(0x0, &descriptor));

        // Even with empty descriptor
        let empty_descriptor = CapabilityDescriptor::new();
        assert!(is_valid_hex(0x0, &empty_descriptor));
    }

    #[test]
    fn test_specific_bit_patterns() {
        let descriptor = create_test_descriptor();

        // Test specific combinations
        assert!(is_valid_hex(0x5, &descriptor)); // Read + Execute (101)
        assert!(is_valid_hex(0xA, &descriptor)); // Write + Admin (1010)
        assert!(is_valid_hex(0xC, &descriptor)); // Execute + Admin (1100)

        // Test invalid patterns
        assert!(!is_valid_hex(0x11, &descriptor)); // Has invalid bit 5
        assert!(!is_valid_hex(0x33, &descriptor)); // Has invalid bits 5 and 6
    }
}
