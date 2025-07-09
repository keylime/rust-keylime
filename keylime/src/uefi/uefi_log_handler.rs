// This file allows extracting information such as:
// - Amount of uefi log events
// - PCR index for each event
// - Version of the log
// - Active hash algorithms
// - Event types
// - Digests (hashes) for each event
// - Event data (if applicable, e.g., EFI variable events)
// - Event data size
// - Event data GUIDs (for EFI variables)
// - Event data names (for EFI variables, if UTF-16 encoded)
// - PCR index for each event
use crate::error::{Error as KeylimeError, Result};
use base64::{
    engine::general_purpose::STANDARD as base64_standard, Engine as _,
};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use std::collections::HashMap;
use std::fs;
use std::io::{Cursor, Read, Write};

// Event Types (a partial list for common events)
const EV_NO_ACTION: u32 = 0x00000003;

// TPM Algorithm Identifiers (TPM_ALG_ID)
const TPM_ALG_SHA1: u16 = 0x0004;
const TPM_ALG_SHA256: u16 = 0x000B;
const TPM_ALG_SHA384: u16 = 0x000C;
const TPM_ALG_SHA512: u16 = 0x000D;

/// A user-friendly representation of a single parsed event from the log.
#[derive(Debug, Clone)]
pub struct ParsedUefiEvent {
    /// The PCR index this event extends.
    pub pcr_index: u32,
    /// A string representation of the event type.
    pub event_type: String,
    /// A map of hash algorithm names to their calculated digest for this event.
    pub digests: HashMap<String, Vec<u8>>,
    /// The raw data associated with the event, describing what was measured.
    pub event_data: Vec<u8>,
}

/// The main handler struct that holds the parsed log data.
#[derive(Debug)]
pub struct UefiLogHandler {
    /// A vector of all events parsed from the log.
    pub events: Vec<ParsedUefiEvent>,
    /// A list of hash algorithms that are active for this log.
    pub active_algorithms: Vec<String>,
    /// The raw bytes of the initial TCG_EfiSpecIdEvent.
    spec_id_event_raw: Vec<u8>,
}

impl UefiLogHandler {
    /// Creates a new UefiLogHandler by reading and parsing the binary log file
    /// from the given path.
    ///
    /// # Arguments
    /// * `log_path` - A string slice that holds the path to the UEFI event log file
    ///   (e.g., "/sys/kernel/security/tpm0/binary_bios_measurements").
    ///
    pub fn new(log_path: &str) -> Result<Self> {
        let log_bytes = fs::read(log_path)?;
        Self::from_bytes(&log_bytes)
    }

    pub fn from_bytes(log_bytes: &[u8]) -> Result<Self> {
        if log_bytes.is_empty() {
            return Err(KeylimeError::UEFILog(
                "Empty UEFI Log file".to_string(),
            ));
        }

        let mut cursor = Cursor::new(&log_bytes);
        let mut parsed_events = Vec::new();
        let mut active_algs_map = HashMap::new();
        let mut active_algs_list = Vec::new();

        //
        // Step 1: Parse the first event (TCG_EfiSpecIdEvent).
        // It uses a legacy TCG_PCR_EVENT header format.
        //
        // This event MUST be `EV_NO_ACTION` for PCR 0.
        let pcr_index_0 = cursor.read_u32::<LittleEndian>()?;
        let event_type_0 = cursor.read_u32::<LittleEndian>()?;

        if pcr_index_0 != 0 || event_type_0 != EV_NO_ACTION {
            return Err(KeylimeError::UEFILog(
                "First event in the log is not a valid TCG_EfiSpecIdEvent."
                    .to_string(),
            ));
        }

        // The legacy event header has a fixed 20-byte digest field for SHA1.
        // We read it into a buffer to advance the cursor.
        let mut legacy_digest_buf = [0u8; 20];
        cursor.read_exact(&mut legacy_digest_buf)?;

        let event_size_0 = cursor.read_u32::<LittleEndian>()?;
        let mut spec_id_event_data = vec![0u8; event_size_0 as usize];
        cursor.read_exact(&mut spec_id_event_data)?;

        let spec_id_event_end_pos = cursor.position() as usize;
        let spec_id_event_raw = log_bytes[0..spec_id_event_end_pos].to_vec();

        // Now, parse the TCG_EfiSpecIdEventStruct from the event data to find active algorithms.
        let mut spec_id_cursor = Cursor::new(&spec_id_event_data);

        // TCG_EfiSpecIdEventStruct fields:
        let mut signature_buf = [0u8; 16];
        spec_id_cursor.read_exact(&mut signature_buf)?;
        let _platform_class = spec_id_cursor.read_u32::<LittleEndian>()?;
        let _spec_version_minor = spec_id_cursor.read_u8()?;
        let _spec_version_major = spec_id_cursor.read_u8()?;
        let _spec_errata = spec_id_cursor.read_u8()?;
        let _uintn_size = spec_id_cursor.read_u8()?;

        let number_of_algs = spec_id_cursor.read_u32::<LittleEndian>()?;

        for _ in 0..number_of_algs {
            let alg_id = spec_id_cursor.read_u16::<LittleEndian>()?;
            let digest_size = spec_id_cursor.read_u16::<LittleEndian>()?;
            let alg_name = Self::map_alg_id_to_str(alg_id).to_string();
            if alg_name != "unknown" {
                active_algs_map.insert(alg_id, digest_size as usize);
                active_algs_list.push(alg_name);
            }
        }

        // The Spec ID event itself is not added to the list of "measurement" events.
        // The cursor is now positioned at the start of the first real measurement event.

        //
        // Step 2: Parse all subsequent measurement events (TCG_PCR_EVENT2 format).
        //
        while cursor.position() < log_bytes.len() as u64 {
            let pcr_index = cursor.read_u32::<LittleEndian>()?;
            let event_type_val = cursor.read_u32::<LittleEndian>()?;
            let event_type_str =
                Self::map_event_type_to_str(event_type_val).to_string();

            let digest_count = cursor.read_u32::<LittleEndian>()?;
            let mut digests_map = HashMap::new();
            for _ in 0..digest_count {
                let alg_id = cursor.read_u16::<LittleEndian>()?;
                if let Some(digest_size) = active_algs_map.get(&alg_id) {
                    let mut digest_buffer = vec![0u8; *digest_size];
                    cursor.read_exact(&mut digest_buffer)?;
                    digests_map.insert(
                        Self::map_alg_id_to_str(alg_id).to_string(),
                        digest_buffer,
                    );
                } else {
                    let known_size = Self::get_known_digest_size(alg_id);
                    let mut digest_buffer = vec![0u8; known_size];
                    cursor.read_exact(&mut digest_buffer)?;
                }
            }

            let event_data_size = cursor.read_u32::<LittleEndian>()?;
            let mut event_data_buffer = vec![0u8; event_data_size as usize];
            cursor.read_exact(&mut event_data_buffer)?;

            parsed_events.push(ParsedUefiEvent {
                pcr_index,
                event_type: event_type_str,
                digests: digests_map,
                event_data: event_data_buffer,
            });
        }

        Ok(UefiLogHandler {
            events: parsed_events,
            active_algorithms: active_algs_list,
            spec_id_event_raw,
        })
    }

    /// Reconstructs the binary UEFI event log from the parsed data.
    pub fn to_bytes(&self) -> std::io::Result<Vec<u8>> {
        let mut buffer = Vec::new();
        buffer.write_all(&self.spec_id_event_raw)?;

        for event in &self.events {
            buffer.write_u32::<LittleEndian>(event.pcr_index)?;
            let event_type_val =
                Self::map_str_to_event_type(&event.event_type);
            buffer.write_u32::<LittleEndian>(event_type_val)?;

            buffer.write_u32::<LittleEndian>(event.digests.len() as u32)?;

            let mut digests_sorted: Vec<_> = event.digests.iter().collect();
            digests_sorted.sort_by_key(|(alg_name, _)| {
                Self::map_str_to_alg_id(alg_name)
            });

            // Iterate over the sorted vector, not the HashMap directly.
            for (alg_name, digest_value) in digests_sorted {
                let alg_id = Self::map_str_to_alg_id(alg_name);
                buffer.write_u16::<LittleEndian>(alg_id)?;
                buffer.write_all(digest_value)?;
            }

            buffer.write_u32::<LittleEndian>(event.event_data.len() as u32)?;
            buffer.write_all(&event.event_data)?;
        }

        Ok(buffer)
    }

    pub fn base_64(&self) -> std::io::Result<String> {
        let bytes = self.to_bytes()?;
        Ok(base64_standard.encode(&bytes))
    }

    /// Returns the known digest size for a given algorithm ID.
    fn get_known_digest_size(alg_id: u16) -> usize {
        match alg_id {
            TPM_ALG_SHA1 => 20,
            TPM_ALG_SHA256 => 32,
            TPM_ALG_SHA384 => 48,
            TPM_ALG_SHA512 => 64,
            _ => 0,
        }
    }

    /// Returns the total number of events in the log.
    pub fn get_entry_count(&self) -> usize {
        self.events.len()
    }

    /// Returns the hash algorithms that are active in this log (e.g., "sha1", "sha256").
    pub fn get_active_algorithms(&self) -> &Vec<String> {
        &self.active_algorithms
    }

    /// Returns a list of all events that affect a specific PCR index.
    pub fn get_events_for_pcr_index(
        &self,
        pcr_index: u32,
    ) -> Vec<&ParsedUefiEvent> {
        self.events
            .iter()
            .filter(|event| event.pcr_index == pcr_index)
            .collect()
    }

    /// Returns a list of all events of a specific type.
    /// `event_type_str` should be one of the TCG-defined strings like "EV_POST_CODE".
    pub fn get_events_by_type(
        &self,
        event_type_str: &str,
    ) -> Vec<&ParsedUefiEvent> {
        self.events
            .iter()
            .filter(|event| event.event_type == event_type_str)
            .collect()
    }

    fn map_str_to_alg_id(alg_name: &str) -> u16 {
        match alg_name {
            "sha1" => TPM_ALG_SHA1,
            "sha256" => TPM_ALG_SHA256,
            "sha384" => TPM_ALG_SHA384,
            "sha512" => TPM_ALG_SHA512,
            _ => 0, // Should not happen with parsed data
        }
    }

    fn map_alg_id_to_str(alg_id: u16) -> &'static str {
        match alg_id {
            TPM_ALG_SHA1 => "sha1",
            TPM_ALG_SHA256 => "sha256",
            TPM_ALG_SHA384 => "sha384",
            TPM_ALG_SHA512 => "sha512",
            _ => "unknown",
        }
    }

    fn map_str_to_event_type(event_type_str: &str) -> u32 {
        match event_type_str {
            "EV_PREBOOT_CERT" => 0x00000000,
            "EV_POST_CODE" => 0x00000001,
            "EV_UNUSED" => 0x00000002,
            "EV_NO_ACTION" => 0x00000003,
            "EV_SEPARATOR" => 0x00000004,
            "EV_ACTION" => 0x00000005,
            "EV_EVENT_TAG" => 0x00000006,
            "EV_S_CRTM_CONTENTS" => 0x00000007,
            "EV_S_CRTM_VERSION" => 0x00000008,
            "EV_CPU_MICROCODE" => 0x00000009,
            "EV_PLATFORM_CONFIG_FLAGS" => 0x0000000A,
            "EV_TABLE_OF_DEVICES" => 0x0000000B,
            "EV_COMPACT_HASH" => 0x0000000C,
            "EV_IPL" => 0x0000000D,
            "EV_IPL_PARTITION_DATA" => 0x0000000E,
            "EV_NONHOST_CODE" => 0x0000000F,
            "EV_NONHOST_CONFIG" => 0x00000010,
            "EV_NONHOST_INFO" => 0x00000011,
            "EV_OMIT_BOOT_DEVICE_EVENTS" => 0x00000012,
            "EV_EFI_VARIABLE_DRIVER_CONFIG" => 0x80000001,
            "EV_EFI_VARIABLE_BOOT" => 0x80000002,
            "EV_EFI_BOOT_SERVICES_APPLICATION" => 0x80000003,
            "EV_EFI_BOOT_SERVICES_DRIVER" => 0x80000004,
            "EV_EFI_RUNTIME_SERVICES_DRIVER" => 0x80000005,
            "EV_EFI_GPT_EVENT" => 0x80000006,
            "EV_EFI_ACTION" => 0x80000007,
            "EV_EFI_PLATFORM_FIRMWARE_BLOB" => 0x80000008,
            "EV_EFI_HANDOFF_TABLES" => 0x80000009,
            "EV_EFI_HCRTM_EVENT" => 0x8000000A,
            _ => 0xFFFFFFFF, // Default for EV_UNKNOWN_TYPE
        }
    }

    fn map_event_type_to_str(event_type: u32) -> &'static str {
        match event_type {
            0x00000000 => "EV_PREBOOT_CERT",
            0x00000001 => "EV_POST_CODE",
            0x00000002 => "EV_UNUSED",
            0x00000003 => "EV_NO_ACTION",
            0x00000004 => "EV_SEPARATOR",
            0x00000005 => "EV_ACTION",
            0x00000006 => "EV_EVENT_TAG",
            0x00000007 => "EV_S_CRTM_CONTENTS",
            0x00000008 => "EV_S_CRTM_VERSION",
            0x00000009 => "EV_CPU_MICROCODE",
            0x0000000A => "EV_PLATFORM_CONFIG_FLAGS",
            0x0000000B => "EV_TABLE_OF_DEVICES",
            0x0000000C => "EV_COMPACT_HASH",
            0x0000000D => "EV_IPL",
            0x0000000E => "EV_IPL_PARTITION_DATA",
            0x0000000F => "EV_NONHOST_CODE",
            0x00000010 => "EV_NONHOST_CONFIG",
            0x00000011 => "EV_NONHOST_INFO",
            0x00000012 => "EV_OMIT_BOOT_DEVICE_EVENTS",
            0x80000001 => "EV_EFI_VARIABLE_DRIVER_CONFIG",
            0x80000002 => "EV_EFI_VARIABLE_BOOT",
            0x80000003 => "EV_EFI_BOOT_SERVICES_APPLICATION",
            0x80000004 => "EV_EFI_BOOT_SERVICES_DRIVER",
            0x80000005 => "EV_EFI_RUNTIME_SERVICES_DRIVER",
            0x80000006 => "EV_EFI_GPT_EVENT",
            0x80000007 => "EV_EFI_ACTION",
            0x80000008 => "EV_EFI_PLATFORM_FIRMWARE_BLOB",
            0x80000009 => "EV_EFI_HANDOFF_TABLES",
            0x8000000A => "EV_EFI_HCRTM_EVENT",
            _ => "EV_UNKNOWN_TYPE",
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_uefi_log_handler() {
        let log_path = "/sys/kernel/security/tpm0/binary_bios_measurements";
        if std::path::Path::new(log_path).exists() {
            let handler = UefiLogHandler::new(log_path)
                .expect("Failed to parse UEFI log");
            assert!(!handler.get_active_algorithms().is_empty());
            let pcr_indexes = vec![0, 1, 2, 3, 4, 5, 6, 7];
            let mut all_events: Vec<&ParsedUefiEvent> = Vec::new();
            for pcr_index in pcr_indexes {
                let events = handler.get_events_for_pcr_index(pcr_index);
                if !events.is_empty() {
                    all_events.extend(events);
                }
            }
            if handler.get_entry_count() > 0 {
                assert!(!all_events.is_empty());
            }
        }
    }

    #[test]
    fn test_parse_minimal_valid_log() {
        // --- A byte array that simulates a valid UEFI log ---
        let fake_log_bytes: &[u8] = &[
            // --- Event 1: TCG_EfiSpecIdEvent (legacy header format) ---
            // 1. TCG_PCR_EVENT Header
            0x00, 0x00, 0x00, 0x00, // pcr_index: 0
            0x03, 0x00, 0x00, 0x00, // event_type: EV_NO_ACTION
            // digest: 20 bytes of a SHA1 digest (zeros in this case)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // event_size: 37 bytes (size of the TCG_EfiSpecIdEventStruct that follows)
            37, 0x00, 0x00, 0x00,
            // 2. Event Content (TCG_EfiSpecIdEventStruct)
            // signature: "Spec ID Event\0" (16 bytes)
            0x53, 0x70, 0x65, 0x63, 0x20, 0x49, 0x44, 0x20, 0x45, 0x76, 0x65,
            0x6e, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // platform_class
            0x00, // spec_version_minor
            0x02, // spec_version_major
            0x00, // spec_errata
            0x02, // uintn_size
            0x02, 0x00, 0x00, 0x00, // numberOfAlgorithms: 2
            // alg_id: SHA1, digest_size: 20
            0x04, 0x00, 20, 0x00,
            // alg_id: SHA256, digest_size: 32
            0x0B, 0x00, 32, 0x00, // vendorInfoSize: 0
            0x00,
            // --- Event 2: A normal measurement event (TCG_PCR_EVENT2 format) ---
            // 1. TCG_PCR_EVENT2 Header
            0x04, 0x00, 0x00, 0x00, // pcr_index: 4
            0x01, 0x00, 0x00, 0x00, // event_type: EV_POST_CODE
            // 2. Digests List
            0x02, 0x00, 0x00,
            0x00, // count: 2 (one digest for SHA1 and another for SHA256)
            // SHA1 Digest (20 bytes)
            0x04, 0x00, // alg_id: SHA1
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            // SHA256 Digest (32 bytes)
            0x0B, 0x00, // alg_id: SHA256
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            // 3. Event Content
            0x04, 0x00, 0x00, 0x00, // eventSize: 4
            0xDE, 0xAD, 0xBE, 0xEF, // eventData (4 bytes)
        ];

        let handler = UefiLogHandler::from_bytes(fake_log_bytes).unwrap(); //#[allow_ci]

        assert_eq!(handler.get_entry_count(), 1);

        let mut active_algs = handler.get_active_algorithms().clone();
        active_algs.sort(); // We sort for a deterministic comparison.
        assert_eq!(
            active_algs,
            vec!["sha1".to_string(), "sha256".to_string()]
        );

        assert_eq!(handler.events.len(), 1);
        assert!(handler.get_events_for_pcr_index(1).is_empty());
        assert!(handler.get_events_by_type("EV_NO_ACTION").is_empty());
        assert!(!handler.get_events_by_type("EV_POST_CODE").is_empty());
        let event = &handler.events[0];
        assert_eq!(event.pcr_index, 4);
        assert_eq!(event.event_type, "EV_POST_CODE");
        assert_eq!(event.digests.len(), 2);
        assert_eq!(event.event_data, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn map_event_type_to_str() {
        let event_tuples = vec![
            (0x00000000, "EV_PREBOOT_CERT"),
            (0x00000001, "EV_POST_CODE"),
            (0x00000002, "EV_UNUSED"),
            (0x00000003, "EV_NO_ACTION"),
            (0x00000004, "EV_SEPARATOR"),
            (0x00000005, "EV_ACTION"),
            (0x00000006, "EV_EVENT_TAG"),
            (0x00000007, "EV_S_CRTM_CONTENTS"),
            (0x00000008, "EV_S_CRTM_VERSION"),
            (0x00000009, "EV_CPU_MICROCODE"),
            (0x0000000A, "EV_PLATFORM_CONFIG_FLAGS"),
            (0x0000000B, "EV_TABLE_OF_DEVICES"),
            (0x0000000C, "EV_COMPACT_HASH"),
            (0x0000000D, "EV_IPL"),
            (0x0000000E, "EV_IPL_PARTITION_DATA"),
            (0x0000000F, "EV_NONHOST_CODE"),
            (0x00000010, "EV_NONHOST_CONFIG"),
            (0x00000011, "EV_NONHOST_INFO"),
            (0x00000012, "EV_OMIT_BOOT_DEVICE_EVENTS"),
            (0x80000001, "EV_EFI_VARIABLE_DRIVER_CONFIG"),
            (0x80000002, "EV_EFI_VARIABLE_BOOT"),
            (0x80000003, "EV_EFI_BOOT_SERVICES_APPLICATION"),
            (0x80000004, "EV_EFI_BOOT_SERVICES_DRIVER"),
            (0x80000005, "EV_EFI_RUNTIME_SERVICES_DRIVER"),
            (0x80000006, "EV_EFI_GPT_EVENT"),
            (0x80000007, "EV_EFI_ACTION"),
            (0x80000008, "EV_EFI_PLATFORM_FIRMWARE_BLOB"),
            (0x80000009, "EV_EFI_HANDOFF_TABLES"),
            (0x8000000A, "EV_EFI_HCRTM_EVENT"),
            (0xFFFFFFFF, "EV_UNKNOWN_TYPE"),
        ];
        for (event_type, expected_str) in event_tuples {
            assert_eq!(
                UefiLogHandler::map_event_type_to_str(event_type),
                expected_str,
                "Failed to map event type 0x{event_type:08X} to string"
            );
        }
    }

    #[test]
    fn get_known_digest_size_test() {
        let alg_sizes = vec![
            (TPM_ALG_SHA1, 20),
            (TPM_ALG_SHA256, 32),
            (TPM_ALG_SHA384, 48),
            (TPM_ALG_SHA512, 64),
        ];
        for (alg_id, expected_size) in alg_sizes {
            assert_eq!(
                UefiLogHandler::get_known_digest_size(alg_id),
                expected_size,
                "Failed to get known size for algorithm ID: {alg_id:#04X}"
            );
        }
        // Test an unknown algorithm
        assert_eq!(
            UefiLogHandler::get_known_digest_size(0xFFFF),
            0,
            "Unknown algorithm should return size 0"
        );
    }

    #[test]
    fn map_alg_id_to_str_test() {
        let algs = vec![
            (TPM_ALG_SHA1, "sha1"),
            (TPM_ALG_SHA256, "sha256"),
            (TPM_ALG_SHA384, "sha384"),
            (TPM_ALG_SHA512, "sha512"),
            (0xFFFF, "unknown"), // Unknown algorithm
        ];
        for (alg_id, expected_str) in algs {
            assert_eq!(
                UefiLogHandler::map_alg_id_to_str(alg_id),
                expected_str,
                "Failed to map algorithm ID {alg_id:#04X} to string"
            );
        }
    }

    #[test]
    fn test_empty_bytes() {
        let empty_bytes: &[u8] = &[];
        let result = UefiLogHandler::from_bytes(empty_bytes);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "UEFI Log parser error: Empty UEFI Log file"
        );
    }

    #[test]
    fn test_wrong_pcr_header() {
        let fake_log_bytes: &[u8] = &[
            0x01, 0x00, 0x00, 0x00, // pcr_index: 1 to test wrong header
            0x03, 0x00, 0x00, 0x00, // event_type: EV_NO_ACTION
        ];
        let handler = UefiLogHandler::from_bytes(fake_log_bytes);
        assert!(handler.is_err());
    }

    #[test]
    fn test_inexisting_uefi_log() {
        let non_existent_path = "/path/to/nonexistent/uefi_log";
        let result = UefiLogHandler::new(non_existent_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_log_reconstruction_to_bytes_and_base64() {
        let fake_log_bytes: &[u8] = &[
            // 1. TCG_PCR_EVENT Header
            0x00, 0x00, 0x00, 0x00, // pcr_index: 0
            0x03, 0x00, 0x00, 0x00, // event_type: EV_NO_ACTION
            // digest: 20 bytes of a SHA1 digest (zeros in this case)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // event_size: 37 bytes (size of the TCG_EfiSpecIdEventStruct that follows)
            37, 0x00, 0x00, 0x00,
            // 2. Event Content (TCG_EfiSpecIdEventStruct)
            // signature: "Spec ID Event\0" (16 bytes)
            0x53, 0x70, 0x65, 0x63, 0x20, 0x49, 0x44, 0x20, 0x45, 0x76, 0x65,
            0x6e, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // platform_class
            0x00, // spec_version_minor
            0x02, // spec_version_major
            0x00, // spec_errata
            0x02, // uintn_size
            0x02, 0x00, 0x00, 0x00, // numberOfAlgorithms: 2
            // alg_id: SHA1, digest_size: 20
            0x04, 0x00, 20, 0x00,
            // alg_id: SHA256, digest_size: 32
            0x0B, 0x00, 32, 0x00, // vendorInfoSize: 0
            0x00,
            // --- Event 2: A normal measurement event (TCG_PCR_EVENT2 format) ---
            // 1. TCG_PCR_EVENT2 Header
            0x04, 0x00, 0x00, 0x00, // pcr_index: 4
            0x01, 0x00, 0x00, 0x00, // event_type: EV_POST_CODE
            // 2. Digests List
            0x02, 0x00, 0x00,
            0x00, // count: 2 (one digest for SHA1 and another for SHA256)
            // SHA1 Digest (20 bytes)
            0x04, 0x00, // alg_id: SHA1
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            // SHA256 Digest (32 bytes)
            0x0B, 0x00, // alg_id: SHA256
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            // 3. Event Content
            0x04, 0x00, 0x00, 0x00, // eventSize: 4
            0xDE, 0xAD, 0xBE, 0xEF, // eventData (4 bytes)
        ];

        let handler = UefiLogHandler::from_bytes(fake_log_bytes).unwrap(); //#[allow_ci]
        let reconstructed_bytes = handler.to_bytes().unwrap(); //#[allow_ci]
        assert_eq!(reconstructed_bytes, fake_log_bytes.to_vec());
        let base64_str = handler.base_64().unwrap(); //#[allow_ci]
        let decoded_bytes = base64_standard.decode(&base64_str).unwrap(); //#[allow_ci]
        assert_eq!(decoded_bytes, fake_log_bytes);
    }

    #[test]
    fn test_map_str_to_alg_id() {
        let algs = vec![
            ("sha1", TPM_ALG_SHA1),
            ("sha256", TPM_ALG_SHA256),
            ("sha384", TPM_ALG_SHA384),
            ("sha512", TPM_ALG_SHA512),
            ("unknown", 0),
        ];
        for (alg_str, expected_id) in algs {
            assert_eq!(
                UefiLogHandler::map_str_to_alg_id(alg_str),
                expected_id
            );
        }
    }

    #[test]
    fn test_map_str_to_event_type() {
        let event_tuples = vec![
            ("EV_PREBOOT_CERT", 0x00000000),
            ("EV_POST_CODE", 0x00000001),
            ("EV_UNUSED", 0x00000002),
            ("EV_SEPARATOR", 0x00000004),
            ("EV_ACTION", 0x00000005),
            ("EV_EVENT_TAG", 0x00000006),
            ("EV_S_CRTM_CONTENTS", 0x00000007),
            ("EV_S_CRTM_VERSION", 0x00000008),
            ("EV_CPU_MICROCODE", 0x00000009),
            ("EV_PLATFORM_CONFIG_FLAGS", 0x0000000A),
            ("EV_TABLE_OF_DEVICES", 0x0000000B),
            ("EV_COMPACT_HASH", 0x0000000C),
            ("EV_IPL", 0x0000000D),
            ("EV_IPL_PARTITION_DATA", 0x0000000E),
            ("EV_NONHOST_CODE", 0x0000000F),
            ("EV_NONHOST_CONFIG", 0x00000010),
            ("EV_NONHOST_INFO", 0x00000011),
            ("EV_OMIT_BOOT_DEVICE_EVENTS", 0x00000012),
            ("EV_NO_ACTION", 0x00000003),
            ("EV_EFI_VARIABLE_DRIVER_CONFIG", 0x80000001),
            ("EV_EFI_VARIABLE_BOOT", 0x80000002),
            ("EV_EFI_BOOT_SERVICES_APPLICATION", 0x80000003),
            ("EV_EFI_BOOT_SERVICES_DRIVER", 0x80000004),
            ("EV_EFI_RUNTIME_SERVICES_DRIVER", 0x80000005),
            ("EV_EFI_GPT_EVENT", 0x80000006),
            ("EV_EFI_ACTION", 0x80000007),
            ("EV_EFI_PLATFORM_FIRMWARE_BLOB", 0x80000008),
            ("EV_EFI_HANDOFF_TABLES", 0x80000009),
            ("EV_EFI_HCRTM_EVENT", 0x8000000A),
            ("EV_UNKNOWN_TYPE", 0xFFFFFFFF),
        ];
        for (event_str, expected_type) in event_tuples {
            assert_eq!(
                UefiLogHandler::map_str_to_event_type(event_str),
                expected_type,
            );
        }
    }
}
