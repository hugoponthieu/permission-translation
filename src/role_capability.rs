//! # Role Capability Module
//!
//! This module provides the main struct for working with role permissions and capabilities.
//! The [`RoleCapability`] struct combines a capability descriptor with a permission value
//! to provide methods for extracting and checking individual capabilities.

use crate::models::{
    CapabilityDescriptor, CapabilityHexUnitSet, CapabilityName, CapabilityNameSet, CapilityHexValue,
};

/// Represents a role with its associated capabilities and permission value.
///
/// This struct combines a capability descriptor (which defines available permissions)
/// with a specific hexadecimal permission value. It provides methods to extract
/// individual capabilities, check for specific permissions, and convert between
/// different representation formats.
///
/// # Examples
///
/// ```rust
/// use permission_translation::{
///     models::{CapabilityDescriptor, CapilityHexValue},
///     role_capability::RoleCapability,
/// };
///
/// // Create a capability descriptor
/// let mut descriptor = CapabilityDescriptor::new();
/// descriptor.insert("Administrator".to_string(), 0x1);
/// descriptor.insert("ManageServer".to_string(), 0x2);
/// descriptor.insert("ManageRoles".to_string(), 0x4);
///
/// // Create a role with combined permissions (Administrator + ManageServer)
/// let permission_value: CapilityHexValue = 0x3;
/// let role = RoleCapability::new(descriptor, permission_value);
///
/// // Check if role has specific capability
/// assert!(role.has_capability(&"Administrator".to_string()));
/// assert!(role.has_capability(&"ManageServer".to_string()));
/// assert!(!role.has_capability(&"ManageRoles".to_string()));
/// ```
///
/// # Fields
///
/// * `descriptor` - The capability descriptor defining available permissions
/// * `hex_value` - The combined hexadecimal permission value for this role
pub struct RoleCapability {
    descriptor: CapabilityDescriptor,
    pub hex_value: CapilityHexValue,
}

impl RoleCapability {
    /// Creates a new `RoleCapability` instance.
    ///
    /// # Arguments
    ///
    /// * `descriptor` - A capability descriptor defining the available permissions
    /// * `hex_value` - The combined hexadecimal permission value for this role
    ///
    /// # Returns
    ///
    /// A new `RoleCapability` instance with the specified descriptor and permission value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use permission_translation::{
    ///     models::{CapabilityDescriptor, CapilityHexValue},
    ///     role_capability::RoleCapability,
    /// };
    ///
    /// let mut descriptor = CapabilityDescriptor::new();
    /// descriptor.insert("Read".to_string(), 0x1);
    /// descriptor.insert("Write".to_string(), 0x2);
    ///
    /// let role = RoleCapability::new(descriptor, 0x3); // Read + Write
    /// ```
    pub fn new(descriptor: CapabilityDescriptor, hex_value: CapilityHexValue) -> Self {
        RoleCapability {
            descriptor,
            hex_value,
        }
    }

    /// Extracts individual capability hex values from the combined permission value.
    ///
    /// This method analyzes the role's permission value and returns a set containing
    /// the individual hex values of all capabilities that are enabled for this role.
    ///
    /// # Returns
    ///
    /// A `CapabilityHexUnitSet` containing the hex values of all enabled capabilities.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use permission_translation::{
    ///     models::{CapabilityDescriptor, CapilityHexValue},
    ///     role_capability::RoleCapability,
    /// };
    ///
    /// let mut descriptor = CapabilityDescriptor::new();
    /// descriptor.insert("Read".to_string(), 0x1);
    /// descriptor.insert("Write".to_string(), 0x2);
    /// descriptor.insert("Execute".to_string(), 0x4);
    ///
    /// let role = RoleCapability::new(descriptor, 0x3); // Read + Write
    /// let hex_set = role.to_hex_set();
    ///
    /// assert!(hex_set.contains(&0x1)); // Read
    /// assert!(hex_set.contains(&0x2)); // Write
    /// assert!(!hex_set.contains(&0x4)); // Execute not included
    /// ```
    pub fn to_hex_set(&self) -> CapabilityHexUnitSet {
        let mut hex_set = CapabilityHexUnitSet::new();
        let mut tmp = self.descriptor.values();
        while let Some(&value) = tmp.next() {
            if self.hex_value & value != 0 {
                hex_set.insert(value);
            }
        }
        hex_set
    }

    /// Extracts human-readable capability names from the combined permission value.
    ///
    /// This method analyzes the role's permission value and returns a set containing
    /// the names of all capabilities that are enabled for this role. This is the
    /// most user-friendly representation of a role's permissions.
    ///
    /// # Returns
    ///
    /// A `CapabilityNameSet` containing the names of all enabled capabilities.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use permission_translation::{
    ///     models::{CapabilityDescriptor, CapilityHexValue},
    ///     role_capability::RoleCapability,
    /// };
    ///
    /// let mut descriptor = CapabilityDescriptor::new();
    /// descriptor.insert("Administrator".to_string(), 0x1);
    /// descriptor.insert("ManageServer".to_string(), 0x2);
    /// descriptor.insert("ManageRoles".to_string(), 0x4);
    ///
    /// let role = RoleCapability::new(descriptor, 0x3); // Administrator + ManageServer
    /// let name_set = role.to_name_set();
    ///
    /// assert!(name_set.contains("Administrator"));
    /// assert!(name_set.contains("ManageServer"));
    /// assert!(!name_set.contains("ManageRoles"));
    /// ```
    pub fn to_name_set(&self) -> CapabilityNameSet {
        let mut name_set = CapabilityNameSet::new();
        for (name, &value) in &self.descriptor {
            if self.hex_value & value != 0 {
                name_set.insert(name.clone());
            }
        }
        name_set
    }

    /// Checks if the role has a specific capability.
    ///
    /// This method determines whether the role's permission value includes
    /// the specified capability by checking if the corresponding bit is set.
    ///
    /// # Arguments
    ///
    /// * `permission_name` - The name of the capability to check for
    ///
    /// # Returns
    ///
    /// * `true` if the role has the specified capability
    /// * `false` if the role doesn't have the capability or if the capability name is not found in the descriptor
    ///
    /// # Examples
    ///
    /// ```rust
    /// use permission_translation::{
    ///     models::{CapabilityDescriptor, CapilityHexValue},
    ///     role_capability::RoleCapability,
    /// };
    ///
    /// let mut descriptor = CapabilityDescriptor::new();
    /// descriptor.insert("Read".to_string(), 0x1);
    /// descriptor.insert("Write".to_string(), 0x2);
    ///
    /// let role = RoleCapability::new(descriptor, 0x1); // Read only
    ///
    /// assert!(role.has_capability(&"Read".to_string()));
    /// assert!(!role.has_capability(&"Write".to_string()));
    /// assert!(!role.has_capability(&"NonExistent".to_string()));
    /// ```
    ///
    /// # Performance
    ///
    /// This method performs a HashMap lookup followed by a bitwise AND operation,
    /// making it O(1) average case complexity.
    pub fn has_capability(&self, permission_name: &CapabilityName) -> bool {
        if let Some(&value) = self.descriptor.get(permission_name) {
            return self.hex_value & value != 0;
        }
        false
    }
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
    fn test_role_capability_new() {
        let descriptor = create_test_descriptor();
        let role = RoleCapability::new(descriptor.clone(), 0x5); // Read + Execute

        assert_eq!(role.hex_value, 0x5);
    }

    #[test]
    fn test_to_hex_set() {
        let descriptor = create_test_descriptor();
        let role = RoleCapability::new(descriptor, 0x5); // Read(0x1) + Execute(0x4)

        let hex_set = role.to_hex_set();
        assert!(hex_set.contains(&0x1)); // Read
        assert!(!hex_set.contains(&0x2)); // Write
        assert!(hex_set.contains(&0x4)); // Execute
        assert!(!hex_set.contains(&0x8)); // Admin
        assert_eq!(hex_set.len(), 2);
    }

    #[test]
    fn test_to_hex_set_empty_permissions() {
        let descriptor = create_test_descriptor();
        let role = RoleCapability::new(descriptor, 0x0); // No permissions

        let hex_set = role.to_hex_set();
        assert!(hex_set.is_empty());
    }

    #[test]
    fn test_to_hex_set_all_permissions() {
        let descriptor = create_test_descriptor();
        let role = RoleCapability::new(descriptor.clone(), 0xF); // All permissions

        let hex_set = role.to_hex_set();
        assert_eq!(hex_set.len(), 4);
        assert!(hex_set.contains(&0x1)); // Read
        assert!(hex_set.contains(&0x2)); // Write
        assert!(hex_set.contains(&0x4)); // Execute
        assert!(hex_set.contains(&0x8)); // Admin
    }

    #[test]
    fn test_to_name_set() {
        let descriptor = create_test_descriptor();
        let role = RoleCapability::new(descriptor, 0x3); // Read + Write

        let name_set = role.to_name_set();
        assert!(name_set.contains("Read"));
        assert!(name_set.contains("Write"));
        assert!(!name_set.contains("Execute"));
        assert!(!name_set.contains("Admin"));
        assert_eq!(name_set.len(), 2);
    }

    #[test]
    fn test_to_name_set_empty_permissions() {
        let descriptor = create_test_descriptor();
        let role = RoleCapability::new(descriptor, 0x0); // No permissions

        let name_set = role.to_name_set();
        assert!(name_set.is_empty());
    }

    #[test]
    fn test_to_name_set_all_permissions() {
        let descriptor = create_test_descriptor();
        let role = RoleCapability::new(descriptor.clone(), 0xF); // All permissions

        let name_set = role.to_name_set();
        assert_eq!(name_set.len(), 4);
        assert!(name_set.contains("Read"));
        assert!(name_set.contains("Write"));
        assert!(name_set.contains("Execute"));
        assert!(name_set.contains("Admin"));

        // Verify all capabilities from descriptor are present
        for (capability_name, _) in &descriptor {
            assert!(name_set.contains(capability_name));
        }
    }

    #[test]
    fn test_has_capability() {
        let descriptor = create_test_descriptor();
        let role = RoleCapability::new(descriptor, 0x9); // Read + Admin

        assert!(role.has_capability(&"Read".to_string()));
        assert!(!role.has_capability(&"Write".to_string()));
        assert!(!role.has_capability(&"Execute".to_string()));
        assert!(role.has_capability(&"Admin".to_string()));
        assert!(!role.has_capability(&"NonExistent".to_string()));
    }

    #[test]
    fn test_has_capability_empty_permissions() {
        let descriptor = create_test_descriptor();
        let role = RoleCapability::new(descriptor, 0x0); // No permissions

        assert!(!role.has_capability(&"Read".to_string()));
        assert!(!role.has_capability(&"Write".to_string()));
        assert!(!role.has_capability(&"Execute".to_string()));
        assert!(!role.has_capability(&"Admin".to_string()));
        assert!(!role.has_capability(&"NonExistent".to_string()));
    }

    #[test]
    fn test_has_capability_all_permissions() {
        let descriptor = create_test_descriptor();
        let role = RoleCapability::new(descriptor.clone(), 0xF); // All permissions

        for (capability_name, _) in &descriptor {
            assert!(role.has_capability(capability_name));
        }

        // Non-existent capability should still return false
        assert!(!role.has_capability(&"NonExistent".to_string()));
    }

    #[test]
    fn test_has_capability_case_sensitivity() {
        let descriptor = create_test_descriptor();
        let role = RoleCapability::new(descriptor, 0x1); // Read only

        assert!(role.has_capability(&"Read".to_string()));
        assert!(!role.has_capability(&"read".to_string())); // Different case
        assert!(!role.has_capability(&"READ".to_string())); // Different case
    }

    #[test]
    fn test_complex_permission_combinations() {
        let descriptor = create_test_descriptor();

        // Test various combinations
        let test_cases = vec![
            (0x1, vec!["Read"], vec!["Write", "Execute", "Admin"]),
            (0x2, vec!["Write"], vec!["Read", "Execute", "Admin"]),
            (0x4, vec!["Execute"], vec!["Read", "Write", "Admin"]),
            (0x8, vec!["Admin"], vec!["Read", "Write", "Execute"]),
            (0x5, vec!["Read", "Execute"], vec!["Write", "Admin"]),
            (0xA, vec!["Write", "Admin"], vec!["Read", "Execute"]),
            (0xC, vec!["Execute", "Admin"], vec!["Read", "Write"]),
        ];

        for (permission_value, should_have, should_not_have) in test_cases {
            let role = RoleCapability::new(descriptor.clone(), permission_value);

            for capability in should_have {
                assert!(
                    role.has_capability(&capability.to_string()),
                    "Role with 0x{:X} should have {} capability",
                    permission_value,
                    capability
                );
            }

            for capability in should_not_have {
                assert!(
                    !role.has_capability(&capability.to_string()),
                    "Role with 0x{:X} should NOT have {} capability",
                    permission_value,
                    capability
                );
            }
        }
    }

    #[test]
    fn test_large_permission_system() {
        let mut large_descriptor = CapabilityDescriptor::new();
        for i in 0..10 {
            large_descriptor.insert(format!("Permission{}", i), 1 << i);
        }

        // Test alternating permissions: 0x155 = 101010101 binary
        let role = RoleCapability::new(large_descriptor.clone(), 0x155);

        let name_set = role.to_name_set();
        let hex_set = role.to_hex_set();

        // Should have Permission0, Permission2, Permission4, Permission6, Permission8
        assert_eq!(name_set.len(), 5);
        assert_eq!(hex_set.len(), 5);

        assert!(role.has_capability(&"Permission0".to_string()));
        assert!(!role.has_capability(&"Permission1".to_string()));
        assert!(role.has_capability(&"Permission2".to_string()));
        assert!(!role.has_capability(&"Permission3".to_string()));
        assert!(role.has_capability(&"Permission4".to_string()));
        assert!(!role.has_capability(&"Permission5".to_string()));
        assert!(role.has_capability(&"Permission6".to_string()));
        assert!(!role.has_capability(&"Permission7".to_string()));
        assert!(role.has_capability(&"Permission8".to_string()));
        assert!(!role.has_capability(&"Permission9".to_string()));

        // Test hex set contains correct values
        assert!(hex_set.contains(&0x1)); // Permission0
        assert!(hex_set.contains(&0x4)); // Permission2
        assert!(hex_set.contains(&0x10)); // Permission4
        assert!(hex_set.contains(&0x40)); // Permission6
        assert!(hex_set.contains(&0x100)); // Permission8
    }

    #[test]
    fn test_descriptor_with_custom_hex_values() {
        let mut custom_descriptor = CapabilityDescriptor::new();
        custom_descriptor.insert("CustomA".to_string(), 0x10);
        custom_descriptor.insert("CustomB".to_string(), 0x20);
        custom_descriptor.insert("CustomC".to_string(), 0x40);

        let role = RoleCapability::new(custom_descriptor, 0x30); // CustomA + CustomB

        assert!(role.has_capability(&"CustomA".to_string()));
        assert!(role.has_capability(&"CustomB".to_string()));
        assert!(!role.has_capability(&"CustomC".to_string()));

        let hex_set = role.to_hex_set();
        assert!(hex_set.contains(&0x10));
        assert!(hex_set.contains(&0x20));
        assert!(!hex_set.contains(&0x40));
    }

    #[test]
    fn test_empty_descriptor() {
        let empty_descriptor = CapabilityDescriptor::new();
        let role = RoleCapability::new(empty_descriptor, 0x0);

        assert!(role.to_hex_set().is_empty());
        assert!(role.to_name_set().is_empty());
        assert!(!role.has_capability(&"AnyCapability".to_string()));
    }
}
