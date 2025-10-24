//! # Permission Translation Example
//!
//! This example demonstrates how to use the permission translation library
//! to translate hexadecimal permission values into human-readable strings.
//!
//! ## Overview
//!
//! The library provides functionality to:
//! 1. Define capability descriptors with named permissions and hex values
//! 2. Create roles with combined permission values
//! 3. Extract individual capabilities from combined values
//! 4. Check for specific capabilities
//! 5. Validate permission values against descriptors
//!
//! ## Example Usage
//!
//! This example creates a permission system for a server management application
//! with capabilities like Administrator, ManageServer, ManageRoles, etc.

use permission_translation::{
    checks::{get_max_hex_value_descriptor, is_valid_hex},
    models::{CapabilityDescriptor, CapabilityHexUnitValue, CapilityHexValue},
    role_capability::RoleCapability,
};

/// Demonstrates the usage of the permission translation library.
///
/// This function showcases:
/// - Creating capability descriptors
/// - Combining permissions using bitwise operations
/// - Validating permission values
/// - Extracting human-readable capabilities
/// - Checking for specific capabilities
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Permission Translation Library Demo ===\n");

    // Step 1: Create a capability descriptor with server management permissions
    println!("1. Creating capability descriptor...");
    let mut permission_descriptor: CapabilityDescriptor = CapabilityDescriptor::new();
    permission_descriptor.insert("Administrator".to_string(), 0x1); // Binary: 00001
    permission_descriptor.insert("ManageServer".to_string(), 0x2); // Binary: 00010
    permission_descriptor.insert("ManageRoles".to_string(), 0x4); // Binary: 00100
    permission_descriptor.insert("CreateInvitation".to_string(), 0x8); // Binary: 01000
    permission_descriptor.insert("ManageChannels".to_string(), 0x10); // Binary: 10000

    println!("   Capabilities defined:");
    for (name, &hex_value) in &permission_descriptor {
        println!(
            "   - {}: 0x{:X} (binary: {:05b})",
            name, hex_value, hex_value
        );
    }
    println!();

    // Step 2: Calculate maximum possible permission value
    let max_permission = get_max_hex_value_descriptor(&permission_descriptor);
    println!(
        "2. Maximum possible permission value: 0x{:X} (binary: {:05b})\n",
        max_permission, max_permission
    );

    // Step 3: Create different permission combinations
    println!("3. Creating different role examples...");

    // Example 1: Administrator only
    let admin_value: CapabilityHexUnitValue = permission_descriptor
        .get("Administrator")
        .ok_or("Administrator capability not found")?
        .to_owned();

    println!("   Admin Role (0x{:X}):", admin_value);
    let admin_role = RoleCapability::new(permission_descriptor.clone(), admin_value);
    println!("   Capabilities: {:?}", admin_role.to_name_set());
    println!(
        "   Has Administrator: {}",
        admin_role.has_capability(&"Administrator".to_string())
    );
    println!(
        "   Has ManageServer: {}",
        admin_role.has_capability(&"ManageServer".to_string())
    );
    println!();

    // Example 2: Combined permissions (Administrator + ManageServer)
    let manage_server_value: CapabilityHexUnitValue = permission_descriptor
        .get("ManageServer")
        .ok_or("ManageServer capability not found")?
        .clone();

    let combined_permission: CapilityHexValue = admin_value | manage_server_value;
    println!("   Combined Role (0x{:X}):", combined_permission);
    let combined_role = RoleCapability::new(permission_descriptor.clone(), combined_permission);
    println!("   Capabilities: {:?}", combined_role.to_name_set());
    println!("   Hex values: {:?}", combined_role.to_hex_set());
    println!();

    // Example 3: Full permissions role
    let full_permission = max_permission;
    println!("   Full Permissions Role (0x{:X}):", full_permission);
    let full_role = RoleCapability::new(permission_descriptor.clone(), full_permission);
    println!("   Capabilities: {:?}", full_role.to_name_set());
    println!();

    // Step 4: Demonstrate validation
    println!("4. Permission validation examples...");

    // Valid permissions
    let valid_permissions = vec![0x1, 0x3, 0x7, 0x1F]; // Various valid combinations
    println!("   Valid permissions:");
    for &perm in &valid_permissions {
        let is_valid = is_valid_hex(perm, &permission_descriptor);
        println!(
            "   - 0x{:X}: {} (binary: {:05b})",
            perm,
            if is_valid { "✓" } else { "✗" },
            perm
        );
    }

    // Invalid permissions
    let invalid_permissions = vec![0x20, 0x40, 0x100]; // Values outside descriptor
    println!("   Invalid permissions:");
    for &perm in &invalid_permissions {
        let is_valid = is_valid_hex(perm, &permission_descriptor);
        println!(
            "   - 0x{:X}: {} (binary: {:08b})",
            perm,
            if is_valid { "✓" } else { "✗" },
            perm
        );
    }
    println!();

    // Step 5: Demonstrate capability checking
    println!("5. Capability checking examples...");
    let test_role = RoleCapability::new(permission_descriptor.clone(), 0x7); // Admin + ManageServer + ManageRoles

    let capabilities_to_check = vec![
        "Administrator",
        "ManageServer",
        "ManageRoles",
        "CreateInvitation",
        "NonExistentCapability",
    ];

    println!("   Role permissions (0x7): {:?}", test_role.to_name_set());
    for capability in capabilities_to_check {
        let has_capability = test_role.has_capability(&capability.to_string());
        println!(
            "   - Has '{}': {}",
            capability,
            if has_capability { "✓" } else { "✗" }
        );
    }

    println!("\n=== Demo completed successfully! ===");
    Ok(())
}
