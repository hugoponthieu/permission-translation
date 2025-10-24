//! # Quick Start Example
//!
//! A minimal example showing the most common usage patterns of the permission translation library.
//!
//! Run this example with:
//! ```bash
//! cargo run --example quick_start
//! ```

use permission_translation::{
    checks::is_valid_hex,
    models::{CapabilityDescriptor, CapilityHexValue},
    role_capability::RoleCapability,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Quick Start - Permission Translation Library\n");

    // 1. Define your permission system
    let mut permissions = CapabilityDescriptor::new();
    permissions.insert("Read".to_string(), 0x1);
    permissions.insert("Write".to_string(), 0x2);
    permissions.insert("Delete".to_string(), 0x4);
    permissions.insert("Admin".to_string(), 0x8);

    println!("📋 Available permissions:");
    for (name, &value) in &permissions {
        println!("   {} = 0x{:X}", name, value);
    }
    println!();

    // 2. Create a role with multiple permissions
    let user_permissions: CapilityHexValue = 0x3; // Read (0x1) + Write (0x2)
    let user_role = RoleCapability::new(permissions.clone(), user_permissions);

    println!("👤 User Role (0x{:X}):", user_permissions);
    println!("   Capabilities: {:?}", user_role.to_name_set());
    println!(
        "   Can read: {}",
        user_role.has_capability(&"Read".to_string())
    );
    println!(
        "   Can delete: {}",
        user_role.has_capability(&"Delete".to_string())
    );
    println!();

    // 3. Validate permission values
    let test_values = vec![0x1, 0x3, 0xF, 0x20]; // Valid and invalid examples
    println!("✅ Permission validation:");
    for &value in &test_values {
        let is_valid = is_valid_hex(value, &permissions);
        println!(
            "   0x{:X}: {}",
            value,
            if is_valid { "Valid ✓" } else { "Invalid ✗" }
        );
    }

    println!("\n🎉 Quick start completed!");
    Ok(())
}
