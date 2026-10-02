// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Parsers for UEFI event data structures.
//!
//! These parsers extract structured information from raw `event_data`
//! bytes returned by [`keylime::uefi::UefiLogHandler`].

use uuid::Uuid;

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
    let name_len_raw = u64::from_le_bytes(name_len_bytes);
    let name_len = usize::try_from(name_len_raw).ok()?;

    // Read VariableDataLength at offset 24
    let data_len_bytes: [u8; 8] = event_data[24..32].try_into().ok()?;
    let data_len_raw = u64::from_le_bytes(data_len_bytes);
    let data_len = usize::try_from(data_len_raw).ok()?;

    if name_len == 0 {
        return None;
    }

    let name_byte_len = name_len.checked_mul(2)?;
    let name_start: usize = 32;
    let name_end = name_start.checked_add(name_byte_len)?;

    if event_data.len() < name_end {
        return None;
    }

    // Decode UTF-16LE variable name
    let name_bytes = &event_data[name_start..name_end];
    let u16_chars: Vec<u16> = name_bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| u16::from_le_bytes(*chunk))
        .collect();

    let variable_name = String::from_utf16(&u16_chars)
        .ok()?
        .trim_end_matches('\0')
        .to_string();

    // Extract variable data
    let data_start = name_end;
    let data_end =
        data_start.checked_add(data_len).unwrap_or(event_data.len());
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
            .as_chunks::<2>()
            .0
            .iter()
            .map(|chunk| u16::from_le_bytes(*chunk))
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

/// Escape a string for use as a literal in a Python-compatible regex pattern.
///
/// Matches Python 3.7+ `re.escape()` behavior: prefixes each special
/// character with a backslash.
pub fn regex_escape(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        if matches!(
            c,
            '\\' | '.'
                | '^'
                | '$'
                | '*'
                | '+'
                | '?'
                | '{'
                | '}'
                | '['
                | ']'
                | '|'
                | '('
                | ')'
                | '#'
                | '&'
                | '~'
                | '-'
                | '\t'
                | '\n'
                | '\r'
                | '\x0b'
                | '\x0c'
                | ' '
        ) {
            result.push('\\');
        }
        result.push(c);
    }
    result
}

/// Format a 16-byte EFI GUID (mixed-endian) as a lowercase hyphenated string.
fn format_efi_guid(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 16 {
        return None;
    }
    let guid_bytes: [u8; 16] = bytes[..16].try_into().ok()?;
    Some(Uuid::from_bytes_le(guid_bytes).hyphenated().to_string())
}

/// A parsed signature entry from an EFI_SIGNATURE_LIST.
#[derive(Debug, Clone)]
pub struct EfiSignatureEntry {
    pub signature_owner: String,
    pub signature_data: String,
}

const EFI_SIGNATURE_LIST_HEADER_SIZE: usize = 28;
const EFI_SIGNATURE_OWNER_SIZE: usize = 16;

/// Parse EFI_SIGNATURE_LIST structures from raw variable data.
///
/// The variable data for Secure Boot variables (PK, KEK, db, dbx) contains
/// one or more EFI_SIGNATURE_LIST structures, each containing one or more
/// EFI_SIGNATURE_DATA entries.
pub fn parse_efi_signature_list(
    variable_data: &[u8],
) -> Vec<EfiSignatureEntry> {
    let mut entries = Vec::new();
    let mut offset = 0;

    while offset + EFI_SIGNATURE_LIST_HEADER_SIZE <= variable_data.len() {
        // Skip SignatureType GUID (16 bytes)
        let list_size = u32::from_le_bytes(
            variable_data[offset + 16..offset + 20]
                .try_into()
                .unwrap_or([0; 4]),
        ) as usize;

        let header_size = u32::from_le_bytes(
            variable_data[offset + 20..offset + 24]
                .try_into()
                .unwrap_or([0; 4]),
        ) as usize;

        let sig_size = u32::from_le_bytes(
            variable_data[offset + 24..offset + 28]
                .try_into()
                .unwrap_or([0; 4]),
        ) as usize;

        if list_size == 0
            || sig_size <= EFI_SIGNATURE_OWNER_SIZE
            || list_size > variable_data.len() - offset
        {
            break;
        }

        let data_start =
            offset + EFI_SIGNATURE_LIST_HEADER_SIZE + header_size;
        let list_end = offset + list_size;

        let mut sig_offset = data_start;
        while sig_offset + sig_size <= list_end
            && sig_offset + sig_size <= variable_data.len()
        {
            if let Some(owner) = format_efi_guid(&variable_data[sig_offset..])
            {
                let sig_data_start = sig_offset + EFI_SIGNATURE_OWNER_SIZE;
                let sig_data_end = sig_offset + sig_size;
                let sig_data = &variable_data[sig_data_start..sig_data_end];

                entries.push(EfiSignatureEntry {
                    signature_owner: owner,
                    signature_data: format!("0x{}", hex::encode(sig_data)),
                });
            }
            sig_offset += sig_size;
        }

        offset = list_end;
    }

    entries
}

const DER_SEQUENCE_TAG: u8 = 0x30;
const DER_LONG_LENGTH_FORM: u8 = 0x82;
const DER_HEADER_SIZE: usize = 4;
const MAX_HEADER_SEARCH_BYTES: usize = 100;

/// Parse signatures from EV_EFI_VARIABLE_AUTHORITY event variable data.
///
/// The format differs from EFI_SIGNATURE_LIST: it contains a SignatureOwner
/// GUID followed by DER-encoded certificate data. Multiple signatures may
/// be concatenated.
pub fn parse_authority_signatures(
    variable_data: &[u8],
) -> Vec<EfiSignatureEntry> {
    let mut entries = Vec::new();
    let mut offset = 0;

    while offset + EFI_SIGNATURE_OWNER_SIZE < variable_data.len() {
        let guid = match format_efi_guid(&variable_data[offset..]) {
            Some(g) => g,
            None => break,
        };

        // Search for DER certificate start (0x30 0x82) after the GUID
        let search_start = offset + EFI_SIGNATURE_OWNER_SIZE;
        let search_end = (search_start + MAX_HEADER_SEARCH_BYTES)
            .min(variable_data.len().saturating_sub(2));

        let cert_start = (search_start..search_end).find(|&i| {
            variable_data[i] == DER_SEQUENCE_TAG
                && variable_data[i + 1] == DER_LONG_LENGTH_FORM
        });

        let cert_start = match cert_start {
            Some(pos) => pos,
            None => break,
        };

        if cert_start + DER_HEADER_SIZE > variable_data.len() {
            break;
        }

        let cert_length = ((variable_data[cert_start + 2] as usize) << 8)
            | (variable_data[cert_start + 3] as usize);
        let cert_end = cert_start + DER_HEADER_SIZE + cert_length;

        if cert_end > variable_data.len() {
            break;
        }

        // SignatureData spans from after the GUID to end of certificate
        let sig_data = &variable_data[search_start..cert_end];

        entries.push(EfiSignatureEntry {
            signature_owner: guid,
            signature_data: format!("0x{}", hex::encode(sig_data)),
        });

        offset = cert_end;
    }

    entries
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

    #[test]
    fn test_regex_escape_simple() {
        assert_eq!(regex_escape("hello"), "hello");
    }

    #[test]
    fn test_regex_escape_kernel_cmdline() {
        let input = "root=/dev/sda1 ro quiet splash vt.handoff=7 BOOT_IMAGE=(hd0,gpt2)/vmlinuz-5.15.0";
        let expected = r"root=/dev/sda1\ ro\ quiet\ splash\ vt\.handoff=7\ BOOT_IMAGE=\(hd0,gpt2\)/vmlinuz\-5\.15\.0";
        assert_eq!(regex_escape(input), expected);
    }

    #[test]
    fn test_regex_escape_all_special_chars() {
        let input = r"\\.^$*+?{}[]|()#&~-";
        let escaped = regex_escape(input);
        for c in [
            '\\', '.', '^', '$', '*', '+', '?', '{', '}', '[', ']', '|', '(',
            ')', '#', '&', '~', '-',
        ] {
            assert!(
                escaped.contains(&format!("\\{c}")),
                "missing escape for '{c}'"
            );
        }
    }

    #[test]
    fn test_format_efi_guid() {
        // EFI_GLOBAL_VARIABLE GUID: 8be4df61-93ca-11d2-aa0d-00e098032b8c
        // Stored in mixed-endian: first 3 fields LE, last 2 fields BE
        let bytes: [u8; 16] = [
            0x61, 0xdf, 0xe4, 0x8b, // Data1 LE
            0xca, 0x93, // Data2 LE
            0xd2, 0x11, // Data3 LE
            0xaa, 0x0d, // Data4[0..2] BE
            0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c, // Data4[2..8] BE
        ];
        assert_eq!(
            format_efi_guid(&bytes).unwrap(), //#[allow_ci]
            "8be4df61-93ca-11d2-aa0d-00e098032b8c"
        );
    }

    /// Helper: build an EFI_SIGNATURE_LIST with one EFI_SIGNATURE_DATA entry.
    fn build_signature_list(
        sig_type_guid: &[u8; 16],
        owner_guid: &[u8; 16],
        sig_data: &[u8],
    ) -> Vec<u8> {
        let sig_size = (EFI_SIGNATURE_OWNER_SIZE + sig_data.len()) as u32;
        let list_size =
            (EFI_SIGNATURE_LIST_HEADER_SIZE + sig_size as usize) as u32;
        let mut buf = Vec::new();
        buf.extend_from_slice(sig_type_guid); // SignatureType
        buf.extend_from_slice(&list_size.to_le_bytes()); // SignatureListSize
        buf.extend_from_slice(&0u32.to_le_bytes()); // SignatureHeaderSize
        buf.extend_from_slice(&sig_size.to_le_bytes()); // SignatureSize
        buf.extend_from_slice(owner_guid); // SignatureOwner
        buf.extend_from_slice(sig_data); // SignatureData
        buf
    }

    #[test]
    fn test_parse_efi_signature_list_single_entry() {
        let sig_type = [0u8; 16];
        // Microsoft GUID: 77fa9abd-0359-4d32-bd60-28f4e78f784b (in LE)
        let owner: [u8; 16] = [
            0xbd, 0x9a, 0xfa, 0x77, 0x59, 0x03, 0x32, 0x4d, 0xbd, 0x60, 0x28,
            0xf4, 0xe7, 0x8f, 0x78, 0x4b,
        ];
        let cert_data = vec![0xAA; 32];
        let data = build_signature_list(&sig_type, &owner, &cert_data);

        let entries = parse_efi_signature_list(&data);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].signature_owner,
            "77fa9abd-0359-4d32-bd60-28f4e78f784b"
        );
        assert_eq!(
            entries[0].signature_data,
            format!("0x{}", hex::encode(&cert_data))
        );
    }

    #[test]
    fn test_parse_efi_signature_list_empty() {
        let entries = parse_efi_signature_list(&[]);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_authority_signatures_with_der_cert() {
        let owner: [u8; 16] = [
            0xbd, 0x9a, 0xfa, 0x77, 0x59, 0x03, 0x32, 0x4d, 0xbd, 0x60, 0x28,
            0xf4, 0xe7, 0x8f, 0x78, 0x4b,
        ];
        let mut data = Vec::new();
        data.extend_from_slice(&owner);
        // DER certificate: SEQUENCE tag + long form length + 4 bytes of data
        data.push(DER_SEQUENCE_TAG); // 0x30
        data.push(DER_LONG_LENGTH_FORM); // 0x82
        data.push(0x00); // length high byte
        data.push(0x04); // length low byte = 4
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // cert data

        let entries = parse_authority_signatures(&data);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].signature_owner,
            "77fa9abd-0359-4d32-bd60-28f4e78f784b"
        );
        // SignatureData should include everything from after GUID to end of cert
        let expected_sig_data = &data[16..]; // DER header + cert data
        assert_eq!(
            entries[0].signature_data,
            format!("0x{}", hex::encode(expected_sig_data))
        );
    }
}
