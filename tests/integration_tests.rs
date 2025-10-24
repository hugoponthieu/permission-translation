//! Integration tests for the permission translation library
//!
//! These tests verify that all components work together correctly
//! and test real-world usage scenarios.

use permission_translation::{
    checks::{get_max_hex_value_descriptor, is_valid_hex},
    models::CapabilityDescriptor,
    role_capability::RoleCapability,
};

#[test]
fn test_complete_permission_workflow() {
    // Setup: Create a realistic permission system for a chat server
    let mut descriptor = CapabilityDescriptor::new();
    descriptor.insert("SendMessage".to_string(), 0x1);
    descriptor.insert("ManageChannel".to_string(), 0x2);
    descriptor.insert("ManageServer".to_string(), 0x4);
    descriptor.insert("Administrator".to_string(), 0x8);
    descriptor.insert("BanMembers".to_string(), 0x10);
    descriptor.insert("CreateInvites".to_string(), 0x20);

    // Test 1: Validate different permission combinations
    let test_cases = vec![
        (0x0, true, "No permissions"),
        (0x1, true, "Send message only"),
        (0x3, true, "Send + Manage channel"),
        (0x7, true, "Send + Manage channel + Manage server"),
        (0x3F, true, "All permissions"),
        (0x40, false, "Invalid bit 7"),
        (0x80, false, "Invalid bit 8"),
        (0x100, false, "Invalid bit 9"),
    ];

    for (value, should_be_valid, description) in test_cases {
        assert_eq!(
            is_valid_hex(value, &descriptor),
            should_be_valid,
            "Failed for {}: 0x{:X}",
            description,
            value
        );
    }

    // Test 2: Create different user roles and verify capabilities

    // Regular user - can only send messages
    let user_permissions = 0x1;
    let user = RoleCapability::new(descriptor.clone(), user_permissions);

    assert!(user.has_capability(&"SendMessage".to_string()));
    assert!(!user.has_capability(&"ManageChannel".to_string()));
    assert!(!user.has_capability(&"Administrator".to_string()));

    let user_capabilities = user.to_name_set();
    assert_eq!(user_capabilities.len(), 1);
    assert!(user_capabilities.contains("SendMessage"));

    // Moderator - can send messages, manage channels, and ban members
    let moderator_permissions = 0x13; // 0x1 + 0x2 + 0x10
    let moderator = RoleCapability::new(descriptor.clone(), moderator_permissions);

    assert!(moderator.has_capability(&"SendMessage".to_string()));
    assert!(moderator.has_capability(&"ManageChannel".to_string()));
    assert!(moderator.has_capability(&"BanMembers".to_string()));
    assert!(!moderator.has_capability(&"ManageServer".to_string()));
    assert!(!moderator.has_capability(&"Administrator".to_string()));

    let moderator_capabilities = moderator.to_name_set();
    assert_eq!(moderator_capabilities.len(), 3);

    // Admin - has all permissions
    let admin_permissions = get_max_hex_value_descriptor(&descriptor);
    let admin = RoleCapability::new(descriptor.clone(), admin_permissions);

    let admin_capabilities = admin.to_name_set();
    assert_eq!(admin_capabilities.len(), 6); // All 6 permissions

    for (capability_name, _) in &descriptor {
        assert!(admin.has_capability(capability_name));
    }

    // Test 3: Verify hex value extraction
    let moderator_hex_values = moderator.to_hex_set();
    assert!(moderator_hex_values.contains(&0x1)); // SendMessage
    assert!(moderator_hex_values.contains(&0x2)); // ManageChannel
    assert!(moderator_hex_values.contains(&0x10)); // BanMembers
    assert!(!moderator_hex_values.contains(&0x4)); // ManageServer
    assert_eq!(moderator_hex_values.len(), 3);
}

#[test]
fn test_edge_cases_and_boundary_conditions() {
    // Test 1: Empty descriptor
    let empty_descriptor = CapabilityDescriptor::new();
    assert!(is_valid_hex(0x0, &empty_descriptor));
    assert!(!is_valid_hex(0x1, &empty_descriptor));
    assert_eq!(get_max_hex_value_descriptor(&empty_descriptor), 0x0);

    let empty_role = RoleCapability::new(empty_descriptor.clone(), 0x0);
    assert!(empty_role.to_hex_set().is_empty());
    assert!(empty_role.to_name_set().is_empty());
    assert!(!empty_role.has_capability(&"AnyPermission".to_string()));

    // Test 2: Single permission
    let mut single_descriptor = CapabilityDescriptor::new();
    single_descriptor.insert("OnlyPermission".to_string(), 0x8);

    assert!(is_valid_hex(0x0, &single_descriptor));
    assert!(is_valid_hex(0x8, &single_descriptor));
    assert!(!is_valid_hex(0x1, &single_descriptor));
    assert!(!is_valid_hex(0x4, &single_descriptor));
    assert!(!is_valid_hex(0x10, &single_descriptor));
    assert_eq!(get_max_hex_value_descriptor(&single_descriptor), 0x8);

    let single_role = RoleCapability::new(single_descriptor.clone(), 0x8);
    assert!(single_role.has_capability(&"OnlyPermission".to_string()));
    assert!(!single_role.has_capability(&"NonExistent".to_string()));

    // Test 3: Maximum practical permission system (16 permissions)
    let mut max_descriptor = CapabilityDescriptor::new();
    for i in 0..16 {
        max_descriptor.insert(format!("Permission{}", i), 1 << i);
    }

    let max_value = get_max_hex_value_descriptor(&max_descriptor);
    assert_eq!(max_value, 0xFFFF); // 16 bits all set

    assert!(is_valid_hex(0x0, &max_descriptor));
    assert!(is_valid_hex(0xFFFF, &max_descriptor));
    assert!(!is_valid_hex(0x10000, &max_descriptor)); // Bit 17 should be invalid

    // Test a complex permission combination
    let complex_permissions = 0xAAAA; // Alternating bits: 1010101010101010
    assert!(is_valid_hex(complex_permissions, &max_descriptor));

    let complex_role = RoleCapability::new(max_descriptor.clone(), complex_permissions);
    let capabilities = complex_role.to_name_set();
    assert_eq!(capabilities.len(), 8); // Every other permission

    // Should have Permission1, Permission3, Permission5, etc.
    for i in (1..16).step_by(2) {
        assert!(complex_role.has_capability(&format!("Permission{}", i)));
    }
    // Should NOT have Permission0, Permission2, Permission4, etc.
    for i in (0..16).step_by(2) {
        assert!(!complex_role.has_capability(&format!("Permission{}", i)));
    }
}

#[test]
fn test_real_world_file_permissions() {
    // Simulate Unix-like file permissions
    let mut file_descriptor = CapabilityDescriptor::new();
    file_descriptor.insert("OwnerRead".to_string(), 0x100); // 256
    file_descriptor.insert("OwnerWrite".to_string(), 0x80); // 128
    file_descriptor.insert("OwnerExecute".to_string(), 0x40); // 64
    file_descriptor.insert("GroupRead".to_string(), 0x20); // 32
    file_descriptor.insert("GroupWrite".to_string(), 0x10); // 16
    file_descriptor.insert("GroupExecute".to_string(), 0x8); // 8
    file_descriptor.insert("OtherRead".to_string(), 0x4); // 4
    file_descriptor.insert("OtherWrite".to_string(), 0x2); // 2
    file_descriptor.insert("OtherExecute".to_string(), 0x1); // 1

    // Test common permission combinations
    let read_only_all = 0x124; // Owner, Group, Other read (256 + 32 + 4)
    assert!(is_valid_hex(read_only_all, &file_descriptor));

    let readonly_role = RoleCapability::new(file_descriptor.clone(), read_only_all);
    assert!(readonly_role.has_capability(&"OwnerRead".to_string()));
    assert!(readonly_role.has_capability(&"GroupRead".to_string()));
    assert!(readonly_role.has_capability(&"OtherRead".to_string()));
    assert!(!readonly_role.has_capability(&"OwnerWrite".to_string()));

    // Test executable file permissions (755 equivalent)
    let executable_perms = 0x1ED; // 256+128+64+32+8+4+1 = 493 (0x1ED)
    assert!(is_valid_hex(executable_perms, &file_descriptor));

    let executable_role = RoleCapability::new(file_descriptor.clone(), executable_perms);
    let capabilities = executable_role.to_name_set();
    assert_eq!(capabilities.len(), 7); // All except GroupWrite and OtherWrite
}

#[test]
fn test_api_access_control_system() {
    // Simulate API endpoint permissions
    let mut api_descriptor = CapabilityDescriptor::new();
    api_descriptor.insert("ReadUsers".to_string(), 0x1);
    api_descriptor.insert("CreateUser".to_string(), 0x2);
    api_descriptor.insert("UpdateUser".to_string(), 0x4);
    api_descriptor.insert("DeleteUser".to_string(), 0x8);
    api_descriptor.insert("ReadPosts".to_string(), 0x10);
    api_descriptor.insert("CreatePost".to_string(), 0x20);
    api_descriptor.insert("UpdatePost".to_string(), 0x40);
    api_descriptor.insert("DeletePost".to_string(), 0x80);
    api_descriptor.insert("AdminAccess".to_string(), 0x100);

    // Test different API user types

    // Anonymous user - can only read
    let anonymous_permissions = 0x11; // ReadUsers + ReadPosts
    let anonymous = RoleCapability::new(api_descriptor.clone(), anonymous_permissions);
    assert!(anonymous.has_capability(&"ReadUsers".to_string()));
    assert!(anonymous.has_capability(&"ReadPosts".to_string()));
    assert!(!anonymous.has_capability(&"CreateUser".to_string()));
    assert!(!anonymous.has_capability(&"AdminAccess".to_string()));

    // Regular user - can read and create posts, read users
    let user_permissions = 0x31; // ReadUsers + ReadPosts + CreatePost
    let user = RoleCapability::new(api_descriptor.clone(), user_permissions);
    assert!(user.has_capability(&"ReadUsers".to_string()));
    assert!(user.has_capability(&"ReadPosts".to_string()));
    assert!(user.has_capability(&"CreatePost".to_string()));
    assert!(!user.has_capability(&"DeletePost".to_string()));
    assert!(!user.has_capability(&"AdminAccess".to_string()));

    // Content moderator - can manage posts but not users
    let moderator_permissions = 0xF0; // All post permissions
    let moderator = RoleCapability::new(api_descriptor.clone(), moderator_permissions);
    assert!(!moderator.has_capability(&"ReadUsers".to_string()));
    assert!(moderator.has_capability(&"ReadPosts".to_string()));
    assert!(moderator.has_capability(&"CreatePost".to_string()));
    assert!(moderator.has_capability(&"UpdatePost".to_string()));
    assert!(moderator.has_capability(&"DeletePost".to_string()));
    assert!(!moderator.has_capability(&"AdminAccess".to_string()));

    // Full admin - has all permissions
    let admin_permissions = get_max_hex_value_descriptor(&api_descriptor);
    let admin = RoleCapability::new(api_descriptor.clone(), admin_permissions);

    for (capability_name, _) in &api_descriptor {
        assert!(admin.has_capability(capability_name));
    }

    let admin_capabilities = admin.to_name_set();
    assert_eq!(admin_capabilities.len(), 9); // All capabilities
}

#[test]
fn test_validation_consistency() {
    // Test that validation is consistent across different descriptor sizes
    for num_permissions in 1..=20 {
        let mut descriptor = CapabilityDescriptor::new();
        for i in 0..num_permissions {
            descriptor.insert(format!("Perm{}", i), 1 << i);
        }

        let max_value = get_max_hex_value_descriptor(&descriptor);

        // Maximum value should always be valid
        assert!(is_valid_hex(max_value, &descriptor));

        // Zero should always be valid
        assert!(is_valid_hex(0x0, &descriptor));

        // One bit beyond max should always be invalid
        if max_value < i32::MAX / 2 {
            assert!(!is_valid_hex(max_value * 2, &descriptor));
        }

        // Test that all individual permissions are valid
        for i in 0..num_permissions {
            let individual_perm = 1 << i;
            assert!(is_valid_hex(individual_perm, &descriptor));
        }
    }
}

#[test]
fn test_error_recovery_and_robustness() {
    let mut descriptor = CapabilityDescriptor::new();
    descriptor.insert("Valid".to_string(), 0x1);

    // Test with very large invalid values
    assert!(!is_valid_hex(i32::MAX, &descriptor));
    assert!(!is_valid_hex(0x7FFFFFFF, &descriptor));

    // Test role creation with invalid permissions (should work but has_capability should handle gracefully)
    let invalid_role = RoleCapability::new(descriptor.clone(), 0xFF);

    // Since 0xFF (binary: 11111111) includes 0x1 (binary: 00000001),
    // has_capability should return true for "Valid" because 0xFF & 0x1 != 0
    assert!(invalid_role.has_capability(&"Valid".to_string()));

    // But it should return false for non-existent capabilities
    assert!(!invalid_role.has_capability(&"Invalid".to_string()));

    // The role should still function for methods that don't validate
    let hex_set = invalid_role.to_hex_set();
    let name_set = invalid_role.to_name_set();

    // The hex_set should contain 0x1 since 0xFF & 0x1 != 0
    assert!(!hex_set.is_empty());
    assert!(hex_set.contains(&0x1));

    // The name_set should contain "Valid" for the same reason
    assert!(!name_set.is_empty());
    assert!(name_set.contains("Valid"));
}
