#![allow(dead_code)]

pub const COMPONENT_TYPE_NAME: &[u8] =
    b"component-type:wit-bindgen:0.57.1:elastos:bus@1.0.0:product-capsule-v1:encoded world";

pub fn leb_u32(mut value: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            bytes.push(byte);
            return bytes;
        }
        bytes.push(byte | 0x80);
    }
}

// A core module whose last section is a custom section with a multi-byte size.
pub fn with_custom_section(name: &[u8], data: &[u8]) -> Vec<u8> {
    let mut wasm = wat::parse_str("(module)").unwrap();
    append_custom_section(&mut wasm, name, data);
    wasm
}

pub fn append_custom_section(wasm: &mut Vec<u8>, name: &[u8], data: &[u8]) {
    let mut payload = leb_u32(name.len());
    payload.extend_from_slice(name);
    payload.extend_from_slice(data);
    wasm.push(0);
    wasm.extend_from_slice(&leb_u32(payload.len()));
    wasm.extend_from_slice(&payload);
}
