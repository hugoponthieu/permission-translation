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
