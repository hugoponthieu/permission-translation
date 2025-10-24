//! # WASM Usage Example
//!
//! This example demonstrates how to use the permission translation library
//! with WebAssembly (WASM) bindings.
//!
//! To build for WASM:
//! ```bash
//! wasm-pack build --target web --features wasm
//! ```
//!
//! Or for Node.js:
//! ```bash
//! wasm-pack build --target nodejs --features wasm
//! ```

#[cfg(feature = "wasm")]
use permission_translation::{js_get_max_hex_value_descriptor, js_is_valid_hex};
#[cfg(feature = "wasm")]
use permission_translation::{JsCapabilityDescriptor, JsRoleCapability};

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm")]
#[wasm_bindgen(start)]
pub fn main() {
    // Set panic hook for better error messages in development
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();

    web_sys::console::log_1(&"Permission Translation WASM Example initialized".into());
}

/// Example function that demonstrates the WASM API
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn demo_permission_system() -> Result<JsValue, JsValue> {
    // Create a capability descriptor
    let mut descriptor = JsCapabilityDescriptor::new();
    descriptor.insert("Read".to_string(), 0x1);
    descriptor.insert("Write".to_string(), 0x2);
    descriptor.insert("Execute".to_string(), 0x4);
    descriptor.insert("Admin".to_string(), 0x8);

    // Calculate max permission value
    let max_value = js_get_max_hex_value_descriptor(&descriptor);

    // Create a role with Read + Write permissions
    let role = JsRoleCapability::new(&descriptor, 0x3);

    // Create result object
    let result = js_sys::Object::new();

    // Add descriptor information
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("descriptorSize"),
        &JsValue::from_f64(descriptor.len() as f64),
    )?;

    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("maxPermissionValue"),
        &JsValue::from_f64(max_value as f64),
    )?;

    // Add role information
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("roleHexValue"),
        &JsValue::from_f64(role.hex_value() as f64),
    )?;

    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("capabilities"),
        &role.get_capability_names(),
    )?;

    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("hexValues"),
        &role.get_capability_hex_values(),
    )?;

    // Test capability checks
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("canRead"),
        &JsValue::from_bool(role.has_capability("Read")),
    )?;

    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("canWrite"),
        &JsValue::from_bool(role.has_capability("Write")),
    )?;

    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("canExecute"),
        &JsValue::from_bool(role.has_capability("Execute")),
    )?;

    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("isAdmin"),
        &JsValue::from_bool(role.has_capability("Admin")),
    )?;

    // Test validation
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("isValidPermission"),
        &JsValue::from_bool(js_is_valid_hex(0x3, &descriptor)),
    )?;

    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("isInvalidPermission"),
        &JsValue::from_bool(!js_is_valid_hex(0x20, &descriptor)),
    )?;

    Ok(result.into())
}

/// Validate a permission value from JavaScript
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn validate_permission(
    permission_value: i32,
    descriptor_obj: &JsValue,
) -> Result<bool, JsValue> {
    let descriptor = JsCapabilityDescriptor::from_js_object(descriptor_obj)?;
    Ok(js_is_valid_hex(permission_value, &descriptor))
}

/// Create a role from JavaScript and get its capabilities
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn create_role_and_get_capabilities(
    descriptor_obj: &JsValue,
    permission_value: i32,
) -> Result<JsValue, JsValue> {
    let descriptor = JsCapabilityDescriptor::from_js_object(descriptor_obj)?;
    let role = JsRoleCapability::new(&descriptor, permission_value);

    let result = js_sys::Object::new();

    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("hexValue"),
        &JsValue::from_f64(role.hex_value() as f64),
    )?;

    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("capabilities"),
        &role.get_capability_names(),
    )?;

    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("hexValues"),
        &role.get_capability_hex_values(),
    )?;

    Ok(result.into())
}

// For non-WASM builds, provide a simple native example
#[cfg(not(feature = "wasm"))]
fn main() {
    use permission_translation::{
        checks::{get_max_hex_value_descriptor, is_valid_hex},
        models::CapabilityDescriptor,
        role_capability::RoleCapability,
    };

    println!("🚀 Permission Translation Library - Native Example");
    println!("💡 This example shows the same functionality that's available in WASM");
    println!();

    // Create a capability descriptor
    let mut descriptor = CapabilityDescriptor::new();
    descriptor.insert("Read".to_string(), 0x1);
    descriptor.insert("Write".to_string(), 0x2);
    descriptor.insert("Execute".to_string(), 0x4);
    descriptor.insert("Admin".to_string(), 0x8);

    println!(
        "📋 Created descriptor with {} capabilities:",
        descriptor.len()
    );
    for (name, &value) in &descriptor {
        println!("   {} = 0x{:X}", name, value);
    }
    println!();

    // Calculate max permission value
    let max_value = get_max_hex_value_descriptor(&descriptor);
    println!("🔢 Maximum permission value: 0x{:X}", max_value);
    println!();

    // Create a role with Read + Write permissions
    let role = RoleCapability::new(descriptor.clone(), 0x3);
    println!(
        "👤 Created role with permission value: 0x{:X}",
        role.hex_value
    );

    let capabilities = role.to_name_set();
    println!("   Capabilities: {:?}", capabilities);

    let hex_values = role.to_hex_set();
    println!("   Hex values: {:?}", hex_values);
    println!();

    // Test capability checks
    println!("🔍 Capability checks:");
    println!("   Can read: {}", role.has_capability(&"Read".to_string()));
    println!(
        "   Can write: {}",
        role.has_capability(&"Write".to_string())
    );
    println!(
        "   Can execute: {}",
        role.has_capability(&"Execute".to_string())
    );
    println!("   Is admin: {}", role.has_capability(&"Admin".to_string()));
    println!();

    // Test validation
    println!("✅ Validation tests:");
    println!("   0x3 is valid: {}", is_valid_hex(0x3, &descriptor));
    println!("   0x20 is valid: {}", is_valid_hex(0x20, &descriptor));
    println!();

    println!("🌐 To use this with WASM:");
    println!("   cargo run --example wasm_example --features wasm");
    println!("   wasm-pack build --target web --features wasm");
}
