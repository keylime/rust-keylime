// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Parsers for UEFI event data structures.
//!
//! These parsers extract structured information from raw `event_data`
//! bytes returned by [`keylime::uefi::UefiLogHandler`].

/// Parsed UEFI_VARIABLE_DATA structure.
///
/// Represents the content of `EV_EFI_VARIABLE_DRIVER_CONFIG`,
/// `EV_EFI_VARIABLE_BOOT`, and `EV_EFI_VARIABLE_AUTHORITY` events.
#[derive(Debug, Clone)]
pub struct EfiVariableData {
    /// The variable name (e.g., "PK", "KEK", "db", "vendor_db", "MokList").
    pub variable_name: String,
    /// The raw variable data bytes.
    #[allow(dead_code)] // Available for future signature extraction
    pub variable_data: Vec<u8>,
}

/// Parse a UEFI_VARIABLE_DATA structure from raw event data.
///
/// Layout:
/// - VariableName GUID (16 bytes)
/// - UnicodeNameLength (u64, 8 bytes) — number of UTF-16 code units
/// - VariableDataLength (u64, 8 bytes)
/// - UnicodeName (UnicodeNameLength * 2 bytes, UTF-16LE)
/// - VariableData (VariableDataLength bytes)
pub fn parse_efi_variable_data(event_data: &[u8]) -> Option<EfiVariableData> {
    // Minimum: GUID(16) + name_len(8) + data_len(8) = 32 bytes
    if event_data.len() < 32 {
        return None;
    }

    // Read UnicodeNameLength at offset 16
    let name_len_bytes: [u8; 8] = event_data[16..24].try_into().ok()?;
    let name_len = u64::from_le_bytes(name_len_bytes) as usize;

    // Read VariableDataLength at offset 24
    let data_len_bytes: [u8; 8] = event_data[24..32].try_into().ok()?;
    let data_len = u64::from_le_bytes(data_len_bytes) as usize;

    if name_len == 0 {
        return None;
    }

    let name_byte_len = name_len * 2;
    let name_start = 32;
    let name_end = name_start + name_byte_len;

    if event_data.len() < name_end {
        return None;
    }

    // Decode UTF-16LE variable name
    let name_bytes = &event_data[name_start..name_end];
    let u16_chars: Vec<u16> = name_bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();

    let variable_name = String::from_utf16(&u16_chars)
        .ok()?
        .trim_end_matches('\0')
        .to_string();

    // Extract variable data
    let data_start = name_end;
    let data_end = data_start + data_len;
    let variable_data = if event_data.len() >= data_end {
        event_data[data_start..data_end].to_vec()
    } else {
        // Partial data — take what's available
        event_data[data_start..].to_vec()
    };

    Some(EfiVariableData {
        variable_name,
        variable_data,
    })
}

/// Parse EV_IPL event data as a string.
///
/// Tries UTF-8 first, then UTF-16LE. Returns `None` if the data
/// cannot be decoded as either encoding.
pub fn parse_ipl_string(event_data: &[u8]) -> Option<String> {
    if event_data.is_empty() {
        return None;
    }

    // Try UTF-8 first (most common for GRUB/shim)
    if let Ok(s) = std::str::from_utf8(event_data) {
        let trimmed = s.trim_end_matches('\0').to_string();
        if !trimmed.is_empty() {
            return Some(trimmed);
        }
    }

    // Try UTF-16LE (less common, but some implementations use it)
    if event_data.len() >= 2 && event_data.len().is_multiple_of(2) {
        let u16_chars: Vec<u16> = event_data
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        if let Ok(s) = String::from_utf16(&u16_chars) {
            let trimmed = s.trim_end_matches('\0').to_string();
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a UEFI_VARIABLE_DATA byte buffer.
    fn build_variable_data(name: &str, data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        // GUID (16 bytes) — use zeros
        buf.extend_from_slice(&[0u8; 16]);
        // UnicodeNameLength
        let name_len = name.len() as u64;
        buf.extend_from_slice(&name_len.to_le_bytes());
        // VariableDataLength
        let data_len = data.len() as u64;
        buf.extend_from_slice(&data_len.to_le_bytes());
        // UnicodeName in UTF-16LE
        for c in name.chars() {
            buf.push(c as u8);
            buf.push(0);
        }
        // VariableData
        buf.extend_from_slice(data);
        buf
    }

    #[test]
    fn test_parse_efi_variable_data_pk() {
        let data = build_variable_data("PK", &[0xAA, 0xBB]);
        let parsed = parse_efi_variable_data(&data).unwrap(); //#[allow_ci]
        assert_eq!(parsed.variable_name, "PK");
        assert_eq!(parsed.variable_data, vec![0xAA, 0xBB]);
    }

    #[test]
    fn test_parse_efi_variable_data_kek() {
        let data = build_variable_data("KEK", &[0x01, 0x02, 0x03]);
        let parsed = parse_efi_variable_data(&data).unwrap(); //#[allow_ci]
        assert_eq!(parsed.variable_name, "KEK");
        assert_eq!(parsed.variable_data.len(), 3);
    }

    #[test]
    fn test_parse_efi_variable_data_vendor_db() {
        let data = build_variable_data("vendor_db", &[0xFF; 32]);
        let parsed = parse_efi_variable_data(&data).unwrap(); //#[allow_ci]
        assert_eq!(parsed.variable_name, "vendor_db");
        assert_eq!(parsed.variable_data.len(), 32);
    }

    #[test]
    fn test_parse_efi_variable_data_moklist() {
        let data = build_variable_data("MokList", &[0xDE, 0xAD]);
        let parsed = parse_efi_variable_data(&data).unwrap(); //#[allow_ci]
        assert_eq!(parsed.variable_name, "MokList");
    }

    #[test]
    fn test_parse_efi_variable_data_too_short() {
        let data = vec![0u8; 16]; // Too short
        assert!(parse_efi_variable_data(&data).is_none());
    }

    #[test]
    fn test_parse_efi_variable_data_empty_name() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0u8; 16]); // GUID
        data.extend_from_slice(&0u64.to_le_bytes()); // name_len = 0
        data.extend_from_slice(&0u64.to_le_bytes()); // data_len = 0
        assert!(parse_efi_variable_data(&data).is_none());
    }

    #[test]
    fn test_parse_ipl_string_utf8() {
        let data = b"kernel_cmdline: root=/dev/sda1 ro";
        let result = parse_ipl_string(data);
        assert_eq!(
            result,
            Some("kernel_cmdline: root=/dev/sda1 ro".to_string())
        );
    }

    #[test]
    fn test_parse_ipl_string_utf8_with_null() {
        let mut data = b"MokList".to_vec();
        data.push(0);
        let result = parse_ipl_string(&data);
        assert_eq!(result, Some("MokList".to_string()));
    }

    #[test]
    fn test_parse_ipl_string_utf16le() {
        // Non-ASCII character that's invalid UTF-8 but valid UTF-16LE:
        // U+00E9 (é) = 0xE9, 0x00 in UTF-16LE
        let data = vec![0xE9, 0x00, 0x00, 0x00];
        let result = parse_ipl_string(&data);
        assert_eq!(result, Some("\u{00E9}".to_string()));
    }

    #[test]
    fn test_parse_ipl_string_empty() {
        let data: &[u8] = &[];
        assert!(parse_ipl_string(data).is_none());
    }
}
