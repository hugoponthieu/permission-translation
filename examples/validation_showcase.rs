//! # Validation Showcase Example
//!
//! This example demonstrates the advanced validation features of the permission translation library.
//! It shows how to detect invalid permission values, corrupted descriptors, and edge cases.
//!
//! Run this example with:
//! ```bash
//! cargo run --example validation_showcase
//! ```

use permission_translation::{
    checks::{get_max_hex_value_descriptor, is_valid_hex},
    models::CapabilityDescriptor,
    role_capability::RoleCapability,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Validation Showcase - Permission Translation Library\n");

    // Example 1: Well-formed descriptor
    println!("1️⃣ Testing well-formed descriptor:");
    let mut good_descriptor = CapabilityDescriptor::new();
    good_descriptor.insert("Read".to_string(), 0x1);
    good_descriptor.insert("Write".to_string(), 0x2);
    good_descriptor.insert("Execute".to_string(), 0x4);
    good_descriptor.insert("Admin".to_string(), 0x8);

    test_descriptor("Good Descriptor", &good_descriptor);

    // Example 2: Test various permission values
    println!("\n2️⃣ Testing permission values against good descriptor:");
    let test_cases = vec![
        (0x0, "No permissions"),
        (0x1, "Read only"),
        (0x3, "Read + Write"),
        (0x7, "Read + Write + Execute"),
        (0xF, "All permissions"),
        (0x10, "Invalid bit (0x10)"),
        (0x20, "Invalid bit (0x20)"),
        (0xFF, "Way too high"),
    ];

    for (value, description) in test_cases {
        let is_valid = is_valid_hex(value, &good_descriptor);
        println!(
            "   0x{:02X} ({}): {}",
            value,
            description,
            if is_valid { "✅ Valid" } else { "❌ Invalid" }
        );

        if is_valid {
            let role = RoleCapability::new(good_descriptor.clone(), value);
            let capabilities = role.to_name_set();
            if !capabilities.is_empty() {
                println!("        Capabilities: {:?}", capabilities);
            }
        }
    }

    // Example 3: Edge cases and boundary conditions
    println!("\n3️⃣ Testing edge cases:");

    // Empty descriptor
    let empty_descriptor = CapabilityDescriptor::new();
    println!("   Empty descriptor validation:");
    println!(
        "     - Value 0x0: {}",
        if is_valid_hex(0x0, &empty_descriptor) {
            "✅ Valid"
        } else {
            "❌ Invalid"
        }
    );
    println!(
        "     - Value 0x1: {}",
        if is_valid_hex(0x1, &empty_descriptor) {
            "✅ Valid"
        } else {
            "❌ Invalid"
        }
    );

    // Single capability descriptor
    let mut single_descriptor = CapabilityDescriptor::new();
    single_descriptor.insert("OnlyCapability".to_string(), 0x1);
    println!("\n   Single capability descriptor:");
    println!(
        "     - Value 0x0: {}",
        if is_valid_hex(0x0, &single_descriptor) {
            "✅ Valid"
        } else {
            "❌ Invalid"
        }
    );
    println!(
        "     - Value 0x1: {}",
        if is_valid_hex(0x1, &single_descriptor) {
            "✅ Valid"
        } else {
            "❌ Invalid"
        }
    );
    println!(
        "     - Value 0x2: {}",
        if is_valid_hex(0x2, &single_descriptor) {
            "✅ Valid"
        } else {
            "❌ Invalid"
        }
    );

    // Example 4: Large permission values
    println!("\n4️⃣ Testing with larger permission systems:");
    let mut large_descriptor = CapabilityDescriptor::new();
    for i in 0..10 {
        let permission_name = format!("Permission{}", i);
        let permission_value = 1 << i; // Powers of 2: 1, 2, 4, 8, 16, 32, 64, 128, 256, 512
        large_descriptor.insert(permission_name, permission_value);
    }

    test_descriptor("Large Descriptor (10 permissions)", &large_descriptor);

    let large_test_cases = vec![
        (0x3FF, "All 10 permissions"),
        (0x400, "Invalid bit 11"),
        (0x555, "Alternating permissions (0101010101)"),
        (0x2AA, "Other alternating (1010101010)"),
    ];

    for (value, description) in large_test_cases {
        let is_valid = is_valid_hex(value, &large_descriptor);
        println!(
            "   0x{:03X} ({}): {}",
            value,
            description,
            if is_valid { "✅ Valid" } else { "❌ Invalid" }
        );
    }

    // Example 5: Demonstrate capability extraction
    println!("\n5️⃣ Capability extraction examples:");
    let demo_value = 0x15; // Binary: 10101 (permissions 0, 2, 4)
    if is_valid_hex(demo_value, &large_descriptor) {
        let role = RoleCapability::new(large_descriptor.clone(), demo_value);
        println!(
            "   Permission value 0x{:02X} (binary: {:010b}):",
            demo_value, demo_value
        );
        println!("   Hex values: {:?}", role.to_hex_set());
        println!("   Capability names: {:?}", role.to_name_set());

        // Test specific capabilities
        for i in 0..5 {
            let cap_name = format!("Permission{}", i);
            let has_cap = role.has_capability(&cap_name);
            println!(
                "     Has {}: {}",
                cap_name,
                if has_cap { "✅" } else { "❌" }
            );
        }
    }

    println!("\n🎉 Validation showcase completed!");
    Ok(())
}

/// Helper function to test and display information about a descriptor
fn test_descriptor(name: &str, descriptor: &CapabilityDescriptor) {
    println!("   {} ({} capabilities):", name, descriptor.len());

    if descriptor.is_empty() {
        println!("     (Empty descriptor)");
        return;
    }

    let max_value = get_max_hex_value_descriptor(descriptor);
    println!(
        "     Max possible value: 0x{:X} (binary: {:b})",
        max_value, max_value
    );

    // Calculate sum for comparison
    let sum: i32 = descriptor.values().sum();
    println!("     Sum of all values: 0x{:X}", sum);
    println!(
        "     OR vs Sum: {} (OR should ≤ Sum)",
        if max_value <= sum {
            "✅ Valid"
        } else {
            "❌ Invalid"
        }
    );

    // Show individual capabilities
    let mut sorted_caps: Vec<_> = descriptor.iter().collect();
    sorted_caps.sort_by_key(|(_, &value)| value);

    for (name, &value) in sorted_caps {
        println!("       {}: 0x{:X}", name, value);
    }
}
