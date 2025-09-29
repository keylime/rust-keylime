use serde::Serialize;
use base64::engine::general_purpose;
use base64::Engine;
use std::io::Read;
use serde_json::{json, Value};
use byteorder::{BigEndian, WriteBytesExt, ReadBytesExt};
use std::io::Cursor;
use std::collections::HashMap;

const TYPE_RECNUM: u8 = 0;
const TYPE_INDEX_TYPE: u8 = 1;
const TYPE_DIGESTS: u8 = 3;
const TYPE_CONTENT: u8 = 5;
const TYPE_CONTENT_IMA: u8 = 6;
const TYPE_TEMPLATE_NAME: u8 = 7;
const TYPE_TEMPLATE_DATA: u8 = 8;
const TYPE_FILE_HASH: u8 = 0x0A;

#[derive(Serialize)]
pub struct CMW {
    #[serde(rename = "__cmwc_t")]
    pub cmwc_type: String,
    pub evidence: Evidence,
}

#[derive(Serialize)]
pub struct Evidence {
    pub tpms_attest: EvidenceEntry,
    pub tpmt_signature: EvidenceEntry,
    pub pcr_values: EvidenceEntry,
    pub event_log: EvidenceEntry,
    pub keylime_metadata: EvidenceEntry,
}

#[derive(Serialize)]
pub struct EvidenceEntry(
    pub String, // content_type, e.g. "application/vnd.keylime.tpm2.tpms_attest"
    pub String, // base64-encoded data
);

// CMW functions

pub fn build_cmw(
    tpms_attest: &[u8],
    tpmt_signature: &[u8],
    pcr_values: &[u8],
    event_log: &[u8],
    keylime_metadata: &Value,
) -> CMW {
    CMW {
        cmwc_type: "tag:keylime.org,2025:tpm2-agent".to_string(),
        evidence: Evidence {
            tpms_attest: EvidenceEntry(
                "application/vnd.keylime.tpm2.tpms_attest".to_string(),
                general_purpose::URL_SAFE_NO_PAD.encode(tpms_attest),
            ),
            tpmt_signature: EvidenceEntry(
                "application/vnd.keylime.tpm2.tpmt_signature".to_string(),
                general_purpose::URL_SAFE_NO_PAD.encode(tpmt_signature),
            ),
            pcr_values: EvidenceEntry(
                "application/vnd.keylime.tpm2.pcr_values".to_string(),
                general_purpose::URL_SAFE_NO_PAD.encode(pcr_values),
            ),
            event_log: EvidenceEntry(
                "application/vnd.keylime.cel".to_string(),
                general_purpose::URL_SAFE_NO_PAD.encode(event_log),
            ),
            keylime_metadata: EvidenceEntry(
                "application/vnd.keylime.tpm2.metadata".to_string(),
                general_purpose::URL_SAFE_NO_PAD.encode(
                    serde_json::to_string(keylime_metadata).unwrap().as_bytes(),
                ),
            ),
        },
    }
}

/// TLV encoder
fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    result.push(tag);
    result.write_u32::<BigEndian>(value.len() as u32).unwrap();
    result.extend_from_slice(value);
    result
}


pub fn build_event_log(ima_list_str: &str, mb_list_b64: Option<&str>) -> Vec<u8> {
    let mut log: Vec<u8> = Vec::new();
    let mut recnum = 0u64;

    for line in ima_list_str.lines() {
        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }

        let pcr_index_str = parts[0];
        let pcr_index_u8: u8 = pcr_index_str.parse().unwrap_or(10);

        if pcr_index_u8 > 23 {
            println!("Warning: PCR index {} is outside typical range (0-23). Clamping to 23.", pcr_index_u8);
        }

        let measurement_hash = parts[1];
        let template_type = parts[2];
        let template_hash = parts[3];

        if let Some((hash_alg, hash_val)) = template_hash.split_once(':') {
            if let Ok(digest_bytes) = hex::decode(hash_val) {
                // Recnum
                let recnum_tlv = encode_tlv(TYPE_RECNUM, &recnum.to_be_bytes());

                // IndexType
                let index_tlv = encode_tlv(TYPE_INDEX_TYPE, &[pcr_index_u8]);

                // Digest Type
                let digest_type = if hash_alg.to_lowercase() == "sha256" { 0x0b } else { 0x04 };
                let digest_entry = encode_tlv(digest_type, &digest_bytes);
                let digest_array = encode_tlv(TYPE_DIGESTS, &digest_entry);

                // Content (IMA)
                let name_tlv = encode_tlv(TYPE_TEMPLATE_NAME, template_type.as_bytes());
                let data_str = parts[3..].join(" ");
                let data_tlv = encode_tlv(TYPE_TEMPLATE_DATA, data_str.as_bytes());
                let file_hash_tlv = encode_tlv(TYPE_FILE_HASH, measurement_hash.as_bytes());

                let content_ima = encode_tlv(TYPE_CONTENT_IMA, &[name_tlv, data_tlv, file_hash_tlv].concat());
                let content = encode_tlv(TYPE_CONTENT, &content_ima);

                let cel_record = [
                    recnum_tlv,
                    index_tlv,
                    digest_array,
                    content
                ].concat();

                log.extend_from_slice(&cel_record);
                recnum += 1;
            }
        }
    }
    

    if let Some(mb64) = mb_list_b64 {
        if let Ok(decoded) = general_purpose::STANDARD.decode(mb64) {
            let recnum_tlv = encode_tlv(TYPE_RECNUM, &recnum.to_be_bytes());

            let index_tlv = encode_tlv(TYPE_INDEX_TYPE, &[0u8]); // PCR Index 0 as u8

            let sha1_digest = &decoded[..20]; // take first 20 bytes
            let digest_entry = encode_tlv(0x04, sha1_digest); // 0x04 = sha1
            let digest_array = encode_tlv(TYPE_DIGESTS, &digest_entry);

            let content = encode_tlv(TYPE_CONTENT, &encode_tlv(0x9, &decoded)); // type 0x9 = pcclient_std (arbitrary)

            let cel_record = [
                recnum_tlv,
                index_tlv,
                digest_array,
                content
            ].concat();

            log.extend_from_slice(&cel_record);
        }
    }

    log
}

pub fn get_keylime_metadata(
    pubkey: Option<String>,
    boottime: Option<String>,
    hash_alg: &str,
    sign_alg: &str,
) -> Value {
    json!({
        "boottime": boottime,
        "pubkey": pubkey,
        "hash_alg": hash_alg,
        "sign_alg": sign_alg
    })
}


pub fn decode_cmw(cmw: &CMW) -> Result<HashMap<String, Value>, String> {
    let mut result = HashMap::new();

    let tpms_attest = general_purpose::URL_SAFE_NO_PAD
        .decode(&cmw.evidence.tpms_attest.1)
        .map_err(|e| format!("Failed to decode TPMS_ATTEST: {}", e))?;
    result.insert("TPMS_ATTEST".to_string(), json!(tpms_attest));

    let tpmt_signature = general_purpose::URL_SAFE_NO_PAD
        .decode(&cmw.evidence.tpmt_signature.1)
        .map_err(|e| format!("Failed to decode TPMT_SIGNATURE: {}", e))?;
    result.insert("TPMT_SIGNATURE".to_string(), json!(tpmt_signature));

    let pcrs = general_purpose::URL_SAFE_NO_PAD
        .decode(&cmw.evidence.pcr_values.1)
        .map_err(|e| format!("Failed to decode PCRs: {}", e))?;
    result.insert("PCRs".to_string(), json!(pcrs));

    let event_log_bin = general_purpose::URL_SAFE_NO_PAD
        .decode(&cmw.evidence.event_log.1)
        .map_err(|e| format!("Failed to decode event_log: {}", e))?;
    result.insert("event_log".to_string(), json!(event_log_bin));

    let metadata_str = general_purpose::URL_SAFE_NO_PAD
        .decode(&cmw.evidence.keylime_metadata.1)
        .map_err(|e| format!("Failed to decode keylime_metadata: {}", e))?;
    let metadata_json: Value = serde_json::from_slice(&metadata_str)
        .map_err(|e| format!("Invalid metadata JSON: {}", e))?;
    result.insert("keylime_metadata".to_string(), metadata_json);

    Ok(result)
}

pub fn parse_cel_log(cel: &[u8]) -> Vec<Value> {
    let mut cursor = Cursor::new(cel);
    let mut result = Vec::new();

    while let Ok(tag) = cursor.read_u8() {
        let length = match cursor.read_u32::<BigEndian>() {
            Ok(len) => len as usize,
            Err(_) => break,
        };

        let mut record_data = vec![tag];
        record_data.extend_from_slice(&(length as u32).to_be_bytes());
        let mut buf = vec![0u8; length];
        if cursor.read_exact(&mut buf).is_err() {
            break;
        }
        record_data.extend_from_slice(&buf);

        let mut entry_map = HashMap::new();
        let mut inner_cursor = Cursor::new(&record_data);

        while let Ok(tag) = inner_cursor.read_u8() {
            let len = match inner_cursor.read_u32::<BigEndian>() {
                Ok(len) => len as usize,
                Err(_) => break,
            };
            let mut data = vec![0u8; len];
            if inner_cursor.read_exact(&mut data).is_err() {
                break;
            }

            match tag {
                0 => {
                    let mut val_cursor = Cursor::new(&data);
                    if let Ok(recnum) = val_cursor.read_u64::<BigEndian>() {
                        entry_map.insert("recnum", json!(recnum));
                    }
                }
                1 => {
                    let mut val_cursor = Cursor::new(&data);
                    if let Ok(pcr_index) = val_cursor.read_u32::<BigEndian>() {
                        entry_map.insert("pcr_index", json!(pcr_index));
                    }
                }
                3 => {
                    // Digest array
                    let mut digest_array = Vec::new();
                    let mut digest_cursor = Cursor::new(&data);
                    while let Ok(digest_tag) = digest_cursor.read_u8() {
                        let digest_len = match digest_cursor.read_u32::<BigEndian>() {
                            Ok(l) => l as usize,
                            Err(_) => break,
                        };
                        let mut digest_data = vec![0u8; digest_len];
                        if digest_cursor.read_exact(&mut digest_data).is_err() {
                            break;
                        }

                        let hash_alg = match digest_tag {
                            0x0b => "sha256",
                            0x04 => "sha1",
                            _ => "unknown",
                        };

                        digest_array.push(json!({
                            "hash_alg": hash_alg,
                            "digest": hex::encode(&digest_data),
                        }));
                    }
                    entry_map.insert("digests", json!(digest_array));
                }
                5 => {
                    // Content block
                    let mut content_cursor = Cursor::new(&data);
                    if let Ok(content_type_tag) = content_cursor.read_u8() {
                        let content_len = match content_cursor.read_u32::<BigEndian>() {
                            Ok(l) => l as usize,
                            Err(_) => break,
                        };

                        let mut content_data = vec![0u8; content_len];
                        if content_cursor.read_exact(&mut content_data).is_ok() {
                            if content_type_tag == 6 {
                                // IMA Template
                                let mut template_cursor = Cursor::new(&content_data);

                                let mut template_name = None;
                                let mut template_data = None;

                                while let Ok(inner_tag) = template_cursor.read_u8() {
                                    let inner_len = match template_cursor.read_u32::<BigEndian>() {
                                        Ok(l) => l as usize,
                                        Err(_) => break,
                                    };
                                    let mut inner_data = vec![0u8; inner_len];
                                    if template_cursor.read_exact(&mut inner_data).is_err() {
                                        break;
                                    }

                                    match inner_tag {
                                        7 => {
                                            template_name = Some(String::from_utf8_lossy(&inner_data).to_string());
                                        }
                                        8 => {
                                            template_data = Some(String::from_utf8_lossy(&inner_data).to_string());
                                        }
                                        _ => {}
                                    }
                                }

                                entry_map.insert("content_type", json!("ima_template"));
                                entry_map.insert("content", json!({
                                    "template_name": template_name,
                                    "template_data": template_data
                                }));
                            } else if content_type_tag == 9 {
                                // Measured Boot entry (pcclient_std)
                                entry_map.insert("content_type", json!("pcclient_std"));
                                entry_map.insert("content", json!(base64::engine::general_purpose::STANDARD.encode(&content_data)));
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        result.push(json!(entry_map));
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test_cmw_building_and_decoding() {
        let tpms_attest = b"sample_tpms_attest_data";
        let tpmt_signature = b"sample_signature_data";
        let pcr_values = b"sample_pcr_data";

        let ima_log = "10 0000000000000000 ima-ng sha256:94c0ac6d0ff747d8f1ca7fac89101a141f3e8f6a2c710717b477a026422766d6 /bin/bash\n";

        let binding = general_purpose::STANDARD.encode(&[0u8; 32]);
        let mb_log_b64 = Some(&binding);

        let event_log = build_event_log(ima_log, mb_log_b64.map(|x| x.as_str()));

        let metadata: Value = get_keylime_metadata(
            Some("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9...".to_string()),
            Some("1716827200".to_string()),
            "sha256",
            "rsassa",
        );

        let cmw = build_cmw(
            tpms_attest,
            tpmt_signature,
            pcr_values,
            &event_log,
            &metadata,
        );

        let decoded = decode_cmw(&cmw).expect("CMW decode failed");

        assert_eq!(cmw.cmwc_type, "tag:keylime.org,2025:tpm2-agent");
        assert_eq!(cmw.evidence.tpms_attest.0, "application/vnd.keylime.tpm2.tpms_attest");
        assert_eq!(cmw.evidence.event_log.0, "application/vnd.keylime.cel");

        assert_eq!(decoded.contains_key("TPMS_ATTEST"), true);
        assert_eq!(decoded.contains_key("TPMT_SIGNATURE"), true);
        assert_eq!(decoded.contains_key("PCRs"), true);
        assert_eq!(decoded.contains_key("event_log"), true);
        assert_eq!(decoded.contains_key("keylime_metadata"), true);

        let original_attest = tpms_attest.to_vec();
        let original_sig = tpmt_signature.to_vec();
        let original_pcr = pcr_values.to_vec();

        assert_eq!(decoded["TPMS_ATTEST"], json!(original_attest));
        assert_eq!(decoded["TPMT_SIGNATURE"], json!(original_sig));
        assert_eq!(decoded["PCRs"], json!(original_pcr));

        let meta = &decoded["keylime_metadata"];
        assert_eq!(meta["boottime"], "1716827200");
        assert_eq!(meta["hash_alg"], "sha256");
        assert_eq!(meta["sign_alg"], "rsassa");

        let cel_bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(&cmw.evidence.event_log.1)
            .expect("failed to decode CEL");

        let parsed_log = parse_cel_log(&cel_bytes);

        println!("Parsed CEL:\n{}", serde_json::to_string_pretty(&parsed_log).unwrap());

        println!("\nFull CMW:\n{}", serde_json::to_string_pretty(&cmw).unwrap());
        println!("\nDecoded Metadata:\n{}", serde_json::to_string_pretty(&meta).unwrap());
        println!("\nDecoded CMW:\n{}", serde_json::to_string_pretty(&decoded).unwrap());
    }
}
