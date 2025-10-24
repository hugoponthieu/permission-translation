//! Library-level API tests
//!
//! These tests verify the public API of the permission translation library
//! and ensure that the examples in the documentation work correctly.

use permission_translation::{
    checks::{get_max_hex_value_descriptor, is_valid_hex},
    models::{CapabilityDescriptor, CapabilityHexUnitSet, CapabilityNameSet, CapilityHexValue},
    role_capability::RoleCapability,
};

#[test]
fn test_library_public_api_availability() {
    // Test that all public types are accessible
    let _descriptor: CapabilityDescriptor = CapabilityDescriptor::new();
    let _hex_value: CapilityHexValue = 0x0;
    let _hex_set: CapabilityHexUnitSet = CapabilityHexUnitSet::new();
    let _name_set: CapabilityNameSet = CapabilityNameSet::new();

    // Test that all public functions are accessible
    let descriptor = CapabilityDescriptor::new();
    let _is_valid = is_valid_hex(0x0, &descriptor);
    let _max_value = get_max_hex_value_descriptor(&descriptor);
    let _role = RoleCapability::new(descriptor, 0x0);
}

#[test]
fn test_documentation_example_from_lib_rs() {
    // This test verifies the main example from lib.rs documentation
    let mut descriptor = CapabilityDescriptor::new();
    descriptor.insert("Administrator".to_string(), 0x1);
    descriptor.insert("ManageServer".to_string(), 0x2);
    descriptor.insert("ManageRoles".to_string(), 0x4);

    // Create a role with combined permissions
    let permission_value: CapilityHexValue = 0x3; // Administrator + ManageServer
    let role = RoleCapability::new(descriptor.clone(), permission_value);

    // Validate the permission value
    assert!(is_valid_hex(permission_value, &descriptor));

    // Get human-readable capabilities
    let capabilities = role.to_name_set();
    assert!(capabilities.contains("Administrator"));
    assert!(capabilities.contains("ManageServer"));
    assert!(!capabilities.contains("ManageRoles"));
}

#[test]
fn test_readme_quick_start_example() {
    // This test verifies the quick start example from README.md
    let mut descriptor = CapabilityDescriptor::new();
    descriptor.insert("Read".to_string(), 0x1);
    descriptor.insert("Write".to_string(), 0x2);
    descriptor.insert("Delete".to_string(), 0x4);
    descriptor.insert("Admin".to_string(), 0x8);

    // Create a role with combined permissions (Read + Write)
    let permission_value: CapilityHexValue = 0x3;
    let role = RoleCapability::new(descriptor.clone(), permission_value);

    // Validate the permission value
    assert!(is_valid_hex(permission_value, &descriptor));

    // Get human-readable capabilities
    let capabilities = role.to_name_set();
    assert!(capabilities.contains("Read"));
    assert!(capabilities.contains("Write"));
    assert!(!capabilities.contains("Delete"));
    assert!(!capabilities.contains("Admin"));

    // Check specific capabilities
    assert!(role.has_capability(&"Read".to_string()));
    assert!(!role.has_capability(&"Admin".to_string()));
}

#[test]
fn test_complete_workflow_chain() {
    // Test a complete workflow that chains all major operations

    // Step 1: Create descriptor
    let mut descriptor = CapabilityDescriptor::new();
    descriptor.insert("Feature1".to_string(), 0x1);
    descriptor.insert("Feature2".to_string(), 0x2);
    descriptor.insert("Feature3".to_string(), 0x4);
    descriptor.insert("Feature4".to_string(), 0x8);

    // Step 2: Calculate maximum possible value
    let max_value = get_max_hex_value_descriptor(&descriptor);
    assert_eq!(max_value, 0xF);

    // Step 3: Validate various permission values
    let valid_values = vec![0x0, 0x1, 0x3, 0x7, 0xF];
    let invalid_values = vec![0x10, 0x20, 0xFF];

    for value in valid_values {
        assert!(
            is_valid_hex(value, &descriptor),
            "Value 0x{:X} should be valid",
            value
        );
    }

    for value in invalid_values {
        assert!(
            !is_valid_hex(value, &descriptor),
            "Value 0x{:X} should be invalid",
            value
        );
    }

    // Step 4: Create roles and test capability extraction
    let test_cases = vec![
        (0x1, vec!["Feature1"], 1),
        (0x3, vec!["Feature1", "Feature2"], 2),
        (0x5, vec!["Feature1", "Feature3"], 2),
        (0xF, vec!["Feature1", "Feature2", "Feature3", "Feature4"], 4),
    ];

    for (permission_value, expected_features, expected_count) in test_cases {
        let role = RoleCapability::new(descriptor.clone(), permission_value);

        // Test name set
        let name_set = role.to_name_set();
        assert_eq!(name_set.len(), expected_count);

        for feature in expected_features {
            assert!(name_set.contains(feature));
            assert!(role.has_capability(&feature.to_string()));
        }

        // Test hex set
        let hex_set = role.to_hex_set();
        assert_eq!(hex_set.len(), expected_count);
    }
}

#[test]
fn test_error_handling_and_edge_cases() {
    // Test with empty strings
    let mut descriptor = CapabilityDescriptor::new();
    descriptor.insert("".to_string(), 0x1); // Empty capability name

    let role = RoleCapability::new(descriptor.clone(), 0x1);
    assert!(role.has_capability(&"".to_string()));
    assert!(!role.has_capability(&"non-empty".to_string()));

    // Test with zero values
    let mut zero_descriptor = CapabilityDescriptor::new();
    zero_descriptor.insert("ZeroPermission".to_string(), 0x0);

    // Zero permission should be handled gracefully
    assert!(is_valid_hex(0x0, &zero_descriptor));

    let zero_role = RoleCapability::new(zero_descriptor.clone(), 0x0);
    // This is tricky - a permission with value 0x0 means "always off" in bitwise logic
    // So even with permission value 0x0, it won't match capability value 0x0
    assert!(!zero_role.has_capability(&"ZeroPermission".to_string()));

    // Test with duplicate capability names (HashMap will overwrite)
    let mut duplicate_descriptor = CapabilityDescriptor::new();
    duplicate_descriptor.insert("Duplicate".to_string(), 0x1);
    duplicate_descriptor.insert("Duplicate".to_string(), 0x2); // Overwrites previous

    assert_eq!(duplicate_descriptor.get("Duplicate"), Some(&0x2));
    assert_eq!(duplicate_descriptor.len(), 1);
}

#[test]
fn test_type_safety_and_consistency() {
    // Test that our type aliases maintain type safety
    let mut descriptor = CapabilityDescriptor::new();
    descriptor.insert("TestCapability".to_string(), 0x1);

    let role = RoleCapability::new(descriptor.clone(), 0x1);

    // Test that returned sets have correct types
    let name_set = role.to_name_set();
    let hex_set = role.to_hex_set();

    // Should be able to iterate and use standard HashSet methods
    assert_eq!(name_set.len(), 1);
    assert_eq!(hex_set.len(), 1);

    for name in &name_set {
        assert_eq!(name, "TestCapability");
    }

    for &hex_value in &hex_set {
        assert_eq!(hex_value, 0x1);
    }

    // Test max value calculation type consistency
    let max_value: CapilityHexValue = get_max_hex_value_descriptor(&descriptor);
    assert_eq!(max_value, 0x1);

    // Test validation function type consistency
    let is_valid: bool = is_valid_hex(max_value, &descriptor);
    assert!(is_valid);
}

#[test]
fn test_permission_combining_patterns() {
    // Test common patterns for combining permissions
    let mut descriptor = CapabilityDescriptor::new();
    descriptor.insert("Create".to_string(), 0x1);
    descriptor.insert("Read".to_string(), 0x2);
    descriptor.insert("Update".to_string(), 0x4);
    descriptor.insert("Delete".to_string(), 0x8);

    // Test CRUD combinations
    let create_only = 0x1;
    let read_only = 0x2;
    let create_read = 0x3; // 0x1 | 0x2
    let full_crud = 0xF; // 0x1 | 0x2 | 0x4 | 0x8

    let combinations = vec![
        (create_only, vec!["Create"]),
        (read_only, vec!["Read"]),
        (create_read, vec!["Create", "Read"]),
        (full_crud, vec!["Create", "Read", "Update", "Delete"]),
    ];

    for (permission_value, expected_capabilities) in combinations {
        assert!(is_valid_hex(permission_value, &descriptor));

        let role = RoleCapability::new(descriptor.clone(), permission_value);
        let capabilities = role.to_name_set();

        assert_eq!(capabilities.len(), expected_capabilities.len());

        for capability in expected_capabilities {
            assert!(capabilities.contains(capability));
            assert!(role.has_capability(&capability.to_string()));
        }
    }
}

#[test]
fn test_performance_characteristics() {
    // Test with a reasonably large permission system to ensure performance is acceptable
    let mut large_descriptor = CapabilityDescriptor::new();
    for i in 0..20 {
        large_descriptor.insert(format!("Permission{:02}", i), 1 << i);
    }

    // This should complete quickly even with 20 permissions
    let max_value = get_max_hex_value_descriptor(&large_descriptor);
    assert_eq!(max_value, 0xFFFFF); // 20 bits set

    // Validation should be fast
    assert!(is_valid_hex(max_value, &large_descriptor));
    assert!(!is_valid_hex(max_value + 1, &large_descriptor));

    // Role operations should be fast
    let role = RoleCapability::new(large_descriptor.clone(), max_value);
    let name_set = role.to_name_set();
    let hex_set = role.to_hex_set();

    assert_eq!(name_set.len(), 20);
    assert_eq!(hex_set.len(), 20);

    // Individual capability checks should be fast
    for i in 0..20 {
        assert!(role.has_capability(&format!("Permission{:02}", i)));
    }
    assert!(!role.has_capability(&"NonExistentPermission".to_string()));
}

#[test]
fn test_library_version_compatibility() {
    // Test that the library interface is stable and works as expected
    // This test serves as a regression test for API changes

    use permission_translation::*;

    // Test that all modules are accessible
    let descriptor = models::CapabilityDescriptor::new();
    let _validation = checks::is_valid_hex(0x0, &descriptor);
    let _role = role_capability::RoleCapability::new(descriptor, 0x0);

    // Test re-exports work correctly (if any are added in the future)
    // For now, ensure direct module access works
    assert!(true); // Placeholder - if this compiles, the API is accessible
}
