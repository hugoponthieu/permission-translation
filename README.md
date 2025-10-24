# Permission Translation Library

A Rust library for translating hexadecimal permission values into human-readable capability sets. This library provides functionality to define permission descriptors, validate permission values, and extract individual capabilities from combined permission hex values.

## Features

- **Permission Validation**: Validate hex permission values against capability descriptors
- **Capability Extraction**: Extract individual capabilities from combined permission values
- **Human-Readable Translation**: Convert hex values to readable capability names
- **Flexible Descriptors**: Define custom capability descriptors for different permission systems
- **Comprehensive Validation**: Detect invalid bits, corrupted descriptors, and permission overflows

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
permission-translation = "0.3.0"
```

## Quick Start

```rust
use permission_translation::{
    models::{CapabilityDescriptor, CapilityHexValue},
    role_capability::RoleCapability,
    checks::is_valid_hex,
};

// Create a capability descriptor
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

// Check specific capabilities
assert!(role.has_capability(&"Read".to_string()));
assert!(!role.has_capability(&"Admin".to_string()));
```

## Examples

The library comes with comprehensive examples demonstrating different use cases:

### Quick Start Example
```bash
cargo run --example quick_start
```
A minimal example showing the most common usage patterns with a simple file permission system.

### Basic Usage Example
```bash
cargo run --example basic_usage
```
Comprehensive demonstration of all library features including:
- Creating capability descriptors
- Combining permissions using bitwise operations
- Validating permission values
- Extracting human-readable capabilities
- Checking for specific capabilities

### Validation Showcase Example
```bash
cargo run --example validation_showcase
```
Advanced validation features and edge cases including:
- Well-formed vs malformed descriptors
- Boundary condition testing
- Large permission systems
- Capability extraction from complex permission values

## Core Concepts

### Permission Values
Permission values are 32-bit integers where each bit represents a specific capability. Individual capabilities should use power-of-2 values (0x1, 0x2, 0x4, 0x8, etc.) to enable proper bitwise operations.

```rust
let read_permission = 0x1;    // Binary: 0001
let write_permission = 0x2;   // Binary: 0010
let combined = 0x3;           // Binary: 0011 (Read + Write)
```

### Capability Descriptors
Descriptors map human-readable capability names to their hex values, defining the available permissions in your system.

```rust
let mut descriptor = CapabilityDescriptor::new();
descriptor.insert("SendMessage".to_string(), 0x1);
descriptor.insert("ManageChannel".to_string(), 0x2);
descriptor.insert("Administrator".to_string(), 0x4);
```

### Role Capabilities
The `RoleCapability` struct combines a descriptor with a permission value to provide methods for extracting and checking capabilities.

```rust
let role = RoleCapability::new(descriptor, permission_value);
let capabilities = role.to_name_set();  // Get capability names
let hex_values = role.to_hex_set();     // Get hex values
let has_admin = role.has_capability(&"Administrator".to_string());
```

## Validation Rules

The library enforces several validation rules:

1. **Descriptor Integrity**: The OR mask of descriptor values must not exceed their sum
2. **Valid Bits Only**: Permission values can only have bits set that are defined in the descriptor
3. **Maximum Permission**: Permission values cannot exceed the maximum allowed by the descriptor

## API Documentation

Generate and view the full API documentation:

```bash
cargo doc --no-deps --open
```

## Testing

Run the test suite:

```bash
cargo test
```

This will run both unit tests and documentation tests to ensure all examples compile and work correctly.

## Use Cases

- **User Role Management**: Define and validate user permissions in web applications
- **File System Permissions**: Translate Unix-style permission bits to readable formats
- **API Access Control**: Manage and validate API endpoint access permissions
- **Game Development**: Handle player abilities and access levels
- **System Administration**: Manage service and resource access permissions

## License

This project is licensed under the MIT OR Apache-2.0 license.

## WebAssembly (WASM) Support

The library includes optional WebAssembly support for use in web browsers and Node.js environments. The WASM bindings expose the same functionality without duplicating code.

### Building for WASM

```bash
# Install wasm-pack if you haven't already
cargo install wasm-pack

# Build for web browsers
wasm-pack build --target web --features wasm

# Build for Node.js
wasm-pack build --target nodejs --features wasm

# Build for bundlers (webpack, etc.)
wasm-pack build --target bundler --features wasm
```

### WASM API

When the `wasm` feature is enabled, the library exposes WASM-compatible types:

- `JsCapabilityDescriptor` - WASM wrapper for capability descriptors
- `JsRoleCapability` - WASM wrapper for role capabilities
- `js_is_valid_hex()` - WASM function for permission validation
- `js_get_max_hex_value_descriptor()` - WASM function for max value calculation

### JavaScript Usage Example

```javascript
import init, { 
    JsCapabilityDescriptor, 
    JsRoleCapability, 
    js_is_valid_hex 
} from './pkg/permission_translation.js';

async function main() {
    // Initialize the WASM module
    await init();

    // Create a capability descriptor
    const descriptor = new JsCapabilityDescriptor();
    descriptor.insert("Read", 0x1);
    descriptor.insert("Write", 0x2);
    descriptor.insert("Execute", 0x4);
    descriptor.insert("Admin", 0x8);

    // Create a role with Read + Write permissions
    const role = new JsRoleCapability(descriptor, 0x3);

    // Check capabilities
    console.log("Can read:", role.has_capability("Read"));        // true
    console.log("Can write:", role.has_capability("Write"));      // true
    console.log("Can execute:", role.has_capability("Execute"));  // false
    console.log("Is admin:", role.has_capability("Admin"));       // false

    // Get all capabilities
    const capabilities = role.get_capability_names();
    console.log("All capabilities:", Array.from(capabilities));

    // Validate permission values
    console.log("0x3 is valid:", js_is_valid_hex(0x3, descriptor));  // true
    console.log("0x20 is valid:", js_is_valid_hex(0x20, descriptor)); // false
}

main();
```

### Node.js Usage

```javascript
const { 
    JsCapabilityDescriptor, 
    JsRoleCapability, 
    js_is_valid_hex 
} = require('./pkg/permission_translation');

// Create descriptor from JavaScript object
const descriptorData = {
    "SendMessage": 0x1,
    "ManageChannel": 0x2,
    "ManageServer": 0x4,
    "Administrator": 0x8
};

const descriptor = JsCapabilityDescriptor.from_js_object(descriptorData);
const role = new JsRoleCapability(descriptor, 0x3);

console.log("Role capabilities:", Array.from(role.get_capability_names()));
```

### WASM Example

Run the WASM example to see all features in action:

```bash
# Native version (shows the same functionality)
cargo run --example wasm_example

# WASM version (requires wasm-pack)
cargo run --example wasm_example --features wasm
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.