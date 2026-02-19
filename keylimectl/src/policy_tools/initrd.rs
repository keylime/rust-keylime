// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! Initramfs extraction and hashing.
//!
//! Extracts files from initramfs/initrd images (CPIO archives with
//! optional compression) and computes digests for policy generation.
//! Supports gzip, zstd, xz, and bzip2 compression.

use crate::commands::error::PolicyGenerationError;
use crate::policy_tools::digest::algorithm_to_message_digest;
use openssl::hash::Hasher;
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Map of file paths to their digest strings (e.g., "sha256:abcd...").
pub type DigestMap = HashMap<String, Vec<String>>;

// --- CPIO new-ASCII constants ---
const CPIO_MAGIC: &[u8] = b"070701";
const CPIO_MAGIC_CRC: &[u8] = b"070702";
const CPIO_HEADER_LEN: usize = 110; // 6 + 13*8
const CPIO_FILESIZE_OFFSET: usize = 54; // 6 + 6*8
const CPIO_NAMESIZE_OFFSET: usize = 94; // 6 + 11*8
const CPIO_FIELD_LEN: usize = 8;
const CPIO_ALIGNMENT: usize = 4;
const CPIO_TRAILER: &[u8] = b"TRAILER!!!";

// --- Compression magic bytes ---
const MAGIC_GZIP: &[u8] = &[0x1f, 0x8b];
const MAGIC_ZSTD: &[u8] = &[0x28, 0xb5, 0x2f, 0xfd];
const MAGIC_XZ: &[u8] = &[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00];
const MAGIC_BZIP2: &[u8] = b"BZh";

/// Regular file mode bit in CPIO.
const S_IFREG: u32 = 0o100000;

/// Compression format detected from magic bytes.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Compression {
    Gzip,
    Zstd,
    Xz,
    Bzip2,
    Uncompressed,
}

/// Detect compression format from the first few bytes.
fn detect_compression(data: &[u8]) -> Compression {
    if data.len() >= 6
        && (data.starts_with(CPIO_MAGIC) || data.starts_with(CPIO_MAGIC_CRC))
    {
        return Compression::Uncompressed;
    }
    if data.len() >= 6 && data.starts_with(MAGIC_XZ) {
        return Compression::Xz;
    }
    if data.len() >= 4 && data.starts_with(MAGIC_ZSTD) {
        return Compression::Zstd;
    }
    if data.len() >= 3 && data.starts_with(MAGIC_BZIP2) {
        return Compression::Bzip2;
    }
    if data.len() >= 2 && data.starts_with(MAGIC_GZIP) {
        return Compression::Gzip;
    }
    Compression::Uncompressed
}

/// Align `pos` up to the nearest `alignment` boundary.
fn align_up(pos: usize, alignment: usize) -> usize {
    (pos + alignment - 1) & !(alignment - 1)
}

/// Parse a hex field of `CPIO_FIELD_LEN` bytes from the CPIO header.
fn parse_hex_field(data: &[u8], offset: usize) -> Option<u32> {
    if data.len() < offset + CPIO_FIELD_LEN {
        return None;
    }
    let field =
        std::str::from_utf8(&data[offset..offset + CPIO_FIELD_LEN]).ok()?;
    u32::from_str_radix(field, 16).ok()
}

/// Skip the early microcode CPIO archive (if present) and return the
/// offset where the main initramfs data begins.
fn skip_early_cpio(data: &[u8]) -> usize {
    // Check if data starts with CPIO magic
    if data.len() < CPIO_HEADER_LEN
        || (!data.starts_with(CPIO_MAGIC)
            && !data.starts_with(CPIO_MAGIC_CRC))
    {
        return 0;
    }

    let mut pos = 0;

    // Walk through the CPIO archive
    loop {
        if pos + CPIO_HEADER_LEN > data.len() {
            return 0;
        }

        // Verify magic
        if !data[pos..].starts_with(CPIO_MAGIC)
            && !data[pos..].starts_with(CPIO_MAGIC_CRC)
        {
            return 0;
        }

        let namesize = match parse_hex_field(data, pos + CPIO_NAMESIZE_OFFSET)
        {
            Some(n) => n as usize,
            None => return 0,
        };

        let filesize = match parse_hex_field(data, pos + CPIO_FILESIZE_OFFSET)
        {
            Some(n) => n as usize,
            None => return 0,
        };

        // Extract filename
        let name_start = pos + CPIO_HEADER_LEN;
        let name_end = name_start + namesize;
        if name_end > data.len() {
            return 0;
        }
        let name = &data[name_start..name_end];

        // Check for TRAILER!!! (end of archive)
        let name_trimmed = if name.last() == Some(&0) {
            &name[..name.len() - 1]
        } else {
            name
        };

        if name_trimmed == CPIO_TRAILER {
            // Found end of archive — skip padding zeros
            // to find the start of the next archive
            let trailer_end = align_up(name_end, CPIO_ALIGNMENT);
            let data_end = align_up(trailer_end + filesize, CPIO_ALIGNMENT);

            // Scan past zero padding
            let mut next_start = data_end;
            while next_start < data.len() && data[next_start] == 0 {
                next_start += 1;
            }

            // If we found more data, that's the main initrd
            if next_start < data.len() {
                return next_start;
            }

            // No more data — the entire file was one CPIO
            return 0;
        }

        // Advance past this entry
        let name_padded = align_up(name_end, CPIO_ALIGNMENT);
        let data_padded = align_up(name_padded + filesize, CPIO_ALIGNMENT);
        pos = data_padded;
    }
}

/// Decompress data using the detected format.
fn decompress(
    data: &[u8],
    format: Compression,
) -> Result<Vec<u8>, PolicyGenerationError> {
    match format {
        Compression::Gzip => {
            let mut decoder = flate2::read::GzDecoder::new(data);
            let mut decompressed = Vec::new();
            let _ = decoder.read_to_end(&mut decompressed).map_err(|e| {
                PolicyGenerationError::Output {
                    path: "<initrd>".into(),
                    reason: format!("Gzip decompression failed: {e}"),
                }
            })?;
            Ok(decompressed)
        }
        Compression::Zstd => {
            let decompressed = zstd::decode_all(data).map_err(|e| {
                PolicyGenerationError::Output {
                    path: "<initrd>".into(),
                    reason: format!("Zstd decompression failed: {e}"),
                }
            })?;
            Ok(decompressed)
        }
        Compression::Xz => {
            let mut decoder = xz2::read::XzDecoder::new(data);
            let mut decompressed = Vec::new();
            let _ = decoder.read_to_end(&mut decompressed).map_err(|e| {
                PolicyGenerationError::Output {
                    path: "<initrd>".into(),
                    reason: format!("XZ decompression failed: {e}"),
                }
            })?;
            Ok(decompressed)
        }
        Compression::Bzip2 => {
            let mut decoder = bzip2::read::BzDecoder::new(data);
            let mut decompressed = Vec::new();
            let _ = decoder.read_to_end(&mut decompressed).map_err(|e| {
                PolicyGenerationError::Output {
                    path: "<initrd>".into(),
                    reason: format!("Bzip2 decompression failed: {e}"),
                }
            })?;
            Ok(decompressed)
        }
        Compression::Uncompressed => Ok(data.to_vec()),
    }
}

/// Parse a CPIO new-ASCII archive in memory and compute SHA-256
/// digests for all regular files.
///
/// Returns a map of file paths to digest strings.
fn extract_cpio_digests(
    data: &[u8],
    algorithm: &str,
) -> Result<DigestMap, PolicyGenerationError> {
    let mut digests = DigestMap::new();
    let mut pos = 0;

    loop {
        if pos + CPIO_HEADER_LEN > data.len() {
            break;
        }

        // Verify magic
        if !data[pos..].starts_with(CPIO_MAGIC)
            && !data[pos..].starts_with(CPIO_MAGIC_CRC)
        {
            break;
        }

        let mode =
            parse_hex_field(data, pos + 6 + CPIO_FIELD_LEN).unwrap_or(0);
        let filesize = parse_hex_field(data, pos + CPIO_FILESIZE_OFFSET)
            .unwrap_or(0) as usize;
        let namesize = parse_hex_field(data, pos + CPIO_NAMESIZE_OFFSET)
            .unwrap_or(0) as usize;

        // Extract filename
        let name_start = pos + CPIO_HEADER_LEN;
        let name_end = name_start + namesize;
        if name_end > data.len() {
            break;
        }
        let name_raw = &data[name_start..name_end];
        let name = std::str::from_utf8(name_raw)
            .unwrap_or("")
            .trim_end_matches('\0');

        // Check for TRAILER
        if name.as_bytes() == CPIO_TRAILER {
            break;
        }

        // Advance to file data (aligned)
        let data_start = align_up(name_end, CPIO_ALIGNMENT);
        let data_end = data_start + filesize;

        // Process regular files only
        if (mode & S_IFREG) == S_IFREG
            && filesize > 0
            && data_end <= data.len()
        {
            let file_data = &data[data_start..data_end];

            // Compute digest
            let md = algorithm_to_message_digest(algorithm).map_err(|e| {
                PolicyGenerationError::Output {
                    path: "<initrd>".into(),
                    reason: format!("Unsupported algorithm: {e}"),
                }
            })?;
            let mut hasher = Hasher::new(md).map_err(|e| {
                PolicyGenerationError::Output {
                    path: "<initrd>".into(),
                    reason: format!("Failed to create hasher: {e}"),
                }
            })?;
            hasher.update(file_data).map_err(|e| {
                PolicyGenerationError::Output {
                    path: "<initrd>".into(),
                    reason: format!("Failed to hash data: {e}"),
                }
            })?;
            let digest_bytes = hasher.finish().map_err(|e| {
                PolicyGenerationError::Output {
                    path: "<initrd>".into(),
                    reason: format!("Failed to finalize hash: {e}"),
                }
            })?;
            let digest_hex = hex::encode(digest_bytes);

            // Normalize filename: strip leading "./" or "/"
            let normalized = name
                .strip_prefix("./")
                .or_else(|| name.strip_prefix('/'))
                .unwrap_or(name);

            let file_path = if normalized.starts_with('/') {
                normalized.to_string()
            } else {
                format!("/{normalized}")
            };

            digests.entry(file_path).or_default().push(digest_hex);
        }

        // Advance to next entry (aligned)
        pos = align_up(data_end, CPIO_ALIGNMENT);
    }

    Ok(digests)
}

/// Find initrd/initramfs files in a directory.
///
/// Matches files whose name starts with "initr" (e.g., `initrd.img-5.15.0`,
/// `initramfs-5.15.0.img`).
fn list_initrds(
    basedir: &Path,
) -> Result<Vec<PathBuf>, PolicyGenerationError> {
    let mut initrds = Vec::new();
    let entries = std::fs::read_dir(basedir).map_err(|e| {
        PolicyGenerationError::Output {
            path: basedir.to_path_buf(),
            reason: format!("Failed to list directory: {e}"),
        }
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| PolicyGenerationError::Output {
            path: basedir.to_path_buf(),
            reason: format!("Failed to read directory entry: {e}"),
        })?;

        let file_name = entry.file_name();
        let name = file_name.to_string_lossy().to_string();

        if name.starts_with("initr")
            && entry.file_type().map(|t| t.is_file()).unwrap_or(false)
        {
            initrds.push(entry.path());
        }
    }

    initrds.sort();
    Ok(initrds)
}

/// Process all initramfs files in a directory and return merged digests.
///
/// For each initrd/initramfs file found:
/// 1. Read the file into memory
/// 2. Skip early microcode CPIO archives
/// 3. Detect and decompress (gzip/zstd/xz/bzip2)
/// 4. Parse the CPIO archive and compute file digests
pub fn process_ramdisk_dir(
    dir: &Path,
    algorithm: &str,
) -> Result<DigestMap, PolicyGenerationError> {
    let initrd_files = list_initrds(dir)?;

    if initrd_files.is_empty() {
        log::debug!("No initrd/initramfs files found in {}", dir.display());
        return Ok(DigestMap::new());
    }

    let mut merged_digests = DigestMap::new();

    for initrd_path in &initrd_files {
        log::debug!("Processing initrd: {}", initrd_path.display());

        let raw_data = std::fs::read(initrd_path).map_err(|e| {
            PolicyGenerationError::Output {
                path: initrd_path.clone(),
                reason: format!("Failed to read initrd: {e}"),
            }
        })?;

        // Skip early microcode CPIO
        let offset = skip_early_cpio(&raw_data);
        let data = &raw_data[offset..];

        if data.is_empty() {
            log::debug!("Skipping empty initrd: {}", initrd_path.display());
            continue;
        }

        // Detect compression and decompress
        let compression = detect_compression(data);
        let cpio_data = decompress(data, compression)?;

        // Parse CPIO and extract digests
        let digests = extract_cpio_digests(&cpio_data, algorithm)?;

        // Merge into results
        for (path, file_digests) in digests {
            merged_digests.entry(path).or_default().extend(file_digests);
        }

        log::debug!(
            "Extracted {} file digests from {}",
            merged_digests.len(),
            initrd_path.display()
        );
    }

    Ok(merged_digests)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_compression_gzip() {
        let data = [0x1f, 0x8b, 0x08, 0x00];
        assert_eq!(detect_compression(&data), Compression::Gzip);
    }

    #[test]
    fn test_detect_compression_zstd() {
        let data = [0x28, 0xb5, 0x2f, 0xfd, 0x00];
        assert_eq!(detect_compression(&data), Compression::Zstd);
    }

    #[test]
    fn test_detect_compression_xz() {
        let data = [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00];
        assert_eq!(detect_compression(&data), Compression::Xz);
    }

    #[test]
    fn test_detect_compression_bzip2() {
        let data = [b'B', b'Z', b'h', b'9'];
        assert_eq!(detect_compression(&data), Compression::Bzip2);
    }

    #[test]
    fn test_detect_compression_cpio() {
        let data = *b"070701";
        assert_eq!(detect_compression(&data), Compression::Uncompressed);
    }

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0, 4), 0);
        assert_eq!(align_up(1, 4), 4);
        assert_eq!(align_up(3, 4), 4);
        assert_eq!(align_up(4, 4), 4);
        assert_eq!(align_up(5, 4), 8);
        assert_eq!(align_up(110, 4), 112);
    }

    #[test]
    fn test_parse_hex_field() {
        let data = b"00000042";
        assert_eq!(parse_hex_field(data, 0), Some(0x42));
    }

    /// Build a minimal CPIO new-ASCII archive containing
    /// one regular file with the given name and content.
    fn build_cpio_archive(name: &str, content: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();

        // File entry
        let namesize = name.len() + 1; // include null
        let filesize = content.len();
        let mode = S_IFREG | 0o644;

        // Header (110 bytes)
        let header = format!(
            "070701\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}",
            1,        // ino
            mode,     // mode
            0,        // uid
            0,        // gid
            1,        // nlink
            0,        // mtime
            filesize, // filesize
            0,        // devmajor
            0,        // devminor
            0,        // rdevmajor
            0,        // rdevminor
            namesize, // namesize
            0,        // check
        );
        buf.extend_from_slice(header.as_bytes());

        // Filename + null
        buf.extend_from_slice(name.as_bytes());
        buf.push(0);

        // Pad to 4-byte boundary
        while buf.len() % CPIO_ALIGNMENT != 0 {
            buf.push(0);
        }

        // File data
        buf.extend_from_slice(content);

        // Pad to 4-byte boundary
        while buf.len() % CPIO_ALIGNMENT != 0 {
            buf.push(0);
        }

        // TRAILER entry
        let trailer_name = "TRAILER!!!";
        let trailer_namesize = trailer_name.len() + 1;
        let trailer = format!(
            "070701\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}\
             {:08x}",
            0,                // ino
            0,                // mode
            0,                // uid
            0,                // gid
            1,                // nlink
            0,                // mtime
            0,                // filesize
            0,                // devmajor
            0,                // devminor
            0,                // rdevmajor
            0,                // rdevminor
            trailer_namesize, // namesize
            0,                // check
        );
        buf.extend_from_slice(trailer.as_bytes());
        buf.extend_from_slice(trailer_name.as_bytes());
        buf.push(0);

        // Final padding
        while buf.len() % CPIO_ALIGNMENT != 0 {
            buf.push(0);
        }

        buf
    }

    #[test]
    fn test_extract_cpio_digests_single_file() {
        let content = b"Hello, world!";
        let archive = build_cpio_archive("usr/bin/hello", content);

        let digests = extract_cpio_digests(&archive, "sha256").unwrap(); //#[allow_ci]

        assert_eq!(digests.len(), 1);
        assert!(digests.contains_key("/usr/bin/hello"));
        let digest_list = &digests["/usr/bin/hello"];
        assert_eq!(digest_list.len(), 1);
        // Bare hex sha256 digest = 64 chars
        assert_eq!(digest_list[0].len(), 64);
        assert!(digest_list[0].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_extract_cpio_digests_empty_archive() {
        // Just a TRAILER
        let archive = build_cpio_archive("TRAILER!!!", &[]);
        // This won't work since build_cpio_archive adds
        // the file first. Build a standalone trailer.
        let mut buf = Vec::new();
        let trailer_name = "TRAILER!!!";
        let trailer_namesize = trailer_name.len() + 1;
        let header = format!(
            "070701\
             {:08x}{:08x}{:08x}{:08x}\
             {:08x}{:08x}{:08x}{:08x}\
             {:08x}{:08x}{:08x}{:08x}\
             {:08x}",
            0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, trailer_namesize, 0,
        );
        buf.extend_from_slice(header.as_bytes());
        buf.extend_from_slice(trailer_name.as_bytes());
        buf.push(0);
        while buf.len() % CPIO_ALIGNMENT != 0 {
            buf.push(0);
        }
        // Ignore the archive from build_cpio_archive
        let _ = archive;

        let digests = extract_cpio_digests(&buf, "sha256").unwrap(); //#[allow_ci]
        assert!(digests.is_empty());
    }

    #[test]
    fn test_skip_early_cpio_no_cpio() {
        // Compressed data, no early CPIO
        let data = [0x1f, 0x8b, 0x08, 0x00];
        assert_eq!(skip_early_cpio(&data), 0);
    }

    #[test]
    fn test_skip_early_cpio_single_archive() {
        let archive =
            build_cpio_archive("kernel/x86/microcode.bin", b"microcode");
        // Single archive — skip_early_cpio returns 0
        // because there's no second archive after it
        assert_eq!(skip_early_cpio(&archive), 0);
    }

    #[test]
    fn test_skip_early_cpio_two_archives() {
        let early =
            build_cpio_archive("kernel/x86/microcode.bin", b"microcode");
        let mut data = early.clone();

        // Add padding zeros
        data.extend_from_slice(&[0u8; 12]);

        // Add a gzip-compressed main initrd
        let gzip_magic = [0x1f, 0x8b, 0x08, 0x00, 0xAA, 0xBB];
        data.extend_from_slice(&gzip_magic);

        let offset = skip_early_cpio(&data);
        // Should point to the gzip magic
        assert!(offset > 0);
        assert_eq!(data[offset], 0x1f);
        assert_eq!(data[offset + 1], 0x8b);
    }

    #[test]
    fn test_list_initrds_with_temp_dir() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap(); //#[allow_ci]

        // Create files matching and not matching
        std::fs::File::create(dir.path().join("initrd.img-5.15.0"))
            .unwrap() //#[allow_ci]
            .write_all(b"data")
            .unwrap(); //#[allow_ci]
        std::fs::File::create(dir.path().join("initramfs-5.15.0.img"))
            .unwrap() //#[allow_ci]
            .write_all(b"data")
            .unwrap(); //#[allow_ci]
        std::fs::File::create(dir.path().join("vmlinuz-5.15.0"))
            .unwrap() //#[allow_ci]
            .write_all(b"data")
            .unwrap(); //#[allow_ci]
        std::fs::File::create(dir.path().join("config-5.15.0"))
            .unwrap() //#[allow_ci]
            .write_all(b"data")
            .unwrap(); //#[allow_ci]

        let initrds = list_initrds(dir.path()).unwrap(); //#[allow_ci]

        assert_eq!(initrds.len(), 2);
        let names: Vec<String> = initrds
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string()) //#[allow_ci]
            .collect();
        assert!(names.contains(&"initrd.img-5.15.0".to_string()));
        assert!(names.contains(&"initramfs-5.15.0.img".to_string()));
    }

    #[test]
    fn test_process_ramdisk_dir_with_cpio() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap(); //#[allow_ci]

        // Create a small uncompressed CPIO initrd
        let archive = build_cpio_archive("etc/test.conf", b"key=val");
        let initrd_path = dir.path().join("initrd.img-test");
        std::fs::File::create(&initrd_path)
            .unwrap() //#[allow_ci]
            .write_all(&archive)
            .unwrap(); //#[allow_ci]

        let digests = process_ramdisk_dir(dir.path(), "sha256").unwrap(); //#[allow_ci]

        assert_eq!(digests.len(), 1);
        assert!(digests.contains_key("/etc/test.conf"));
    }

    #[test]
    fn test_process_ramdisk_dir_with_gzip_cpio() {
        use flate2::write::GzEncoder;
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap(); //#[allow_ci]

        // Create a CPIO archive
        let archive =
            build_cpio_archive("usr/lib/test.so", b"ELF binary data here");

        // Gzip compress it
        let mut encoder =
            GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&archive).unwrap(); //#[allow_ci]
        let compressed = encoder.finish().unwrap(); //#[allow_ci]

        let initrd_path = dir.path().join("initramfs-test.img");
        std::fs::write(&initrd_path, &compressed).unwrap(); //#[allow_ci]

        let digests = process_ramdisk_dir(dir.path(), "sha256").unwrap(); //#[allow_ci]

        assert_eq!(digests.len(), 1);
        assert!(digests.contains_key("/usr/lib/test.so"));
    }
}
