// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Keylime Authors

//! RPM repository analysis for policy generation.
//!
//! Supports both local and remote RPM repositories.
//! Local repos are scanned for RPM files and their headers are parsed
//! to extract file digests. Remote repos use `repomd.xml` metadata,
//! with `filelists-ext.xml` as a fast path when available.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::commands::error::PolicyGenerationError;

/// Map of file paths to their digests.
type DigestMap = HashMap<String, Vec<String>>;

/// Check if a hex digest string is all zeros (empty/unset digest).
fn is_empty_digest(hex: &str) -> bool {
    !hex.is_empty() && hex.chars().all(|c| c == '0')
}

/// Analyze a single RPM package file, extracting file digests
/// from the header.
///
/// Returns a map of file paths to their digests in
/// `"algorithm:hex"` format. Filters out entries with
/// empty/zero digests.
pub fn analyze_rpm_pkg(
    path: &Path,
) -> Result<DigestMap, PolicyGenerationError> {
    let metadata = rpm::PackageMetadata::open(path).map_err(|e| {
        PolicyGenerationError::RpmParse {
            path: path.to_path_buf(),
            reason: format!("Failed to parse RPM header: {e}"),
        }
    })?;

    extract_digests_from_metadata(&metadata, path)
}

/// Extract file digests from parsed RPM package metadata.
fn extract_digests_from_metadata(
    metadata: &rpm::PackageMetadata,
    source_path: &Path,
) -> Result<DigestMap, PolicyGenerationError> {
    let file_entries = metadata.get_file_entries().map_err(|e| {
        PolicyGenerationError::RpmParse {
            path: source_path.to_path_buf(),
            reason: format!("Failed to get file entries: {e}"),
        }
    })?;

    let mut digests = DigestMap::new();

    for entry in &file_entries {
        if let Some(ref file_digest) = entry.digest {
            let hex = file_digest.as_hex();
            if !hex.is_empty() && !is_empty_digest(hex) {
                digests
                    .entry(entry.path.to_string_lossy().to_string())
                    .or_default()
                    .push(hex.to_string());
            }
        }
    }

    Ok(digests)
}

/// Analyze all RPM packages in a local repository directory.
///
/// Scans for `*.rpm` files recursively and extracts file digests
/// from each package's header.
pub fn analyze_local_repo(
    repo_dir: &Path,
) -> Result<DigestMap, PolicyGenerationError> {
    if !repo_dir.is_dir() {
        return Err(PolicyGenerationError::RpmParse {
            path: repo_dir.to_path_buf(),
            reason: "Not a directory".to_string(),
        });
    }

    let repodata_dir = repo_dir.join("repodata");
    if !repodata_dir.is_dir() {
        log::warn!(
            "No repodata/ directory found in {}; scanning for RPM files anyway",
            repo_dir.display()
        );
    }

    // Find all RPM files
    let rpm_files = find_rpm_files(repo_dir)?;

    if rpm_files.is_empty() {
        log::warn!("No RPM files found in {}", repo_dir.display());
        return Ok(DigestMap::new());
    }

    log::info!(
        "Found {} RPM files in {}",
        rpm_files.len(),
        repo_dir.display()
    );

    // Analyze each RPM and merge results
    let mut merged = DigestMap::new();
    for rpm_path in &rpm_files {
        match analyze_rpm_pkg(rpm_path) {
            Ok(pkg_digests) => {
                merge_digest_maps(&mut merged, &pkg_digests);
            }
            Err(e) => {
                log::warn!("Failed to analyze {}: {e}", rpm_path.display());
            }
        }
    }

    Ok(merged)
}

/// Analyze a remote RPM repository via HTTP.
///
/// Attempts the fast path using `filelists-ext.xml` metadata
/// first. Falls back to parsing `primary.xml` and downloading
/// individual RPM files if extended file lists are not available.
pub async fn analyze_remote_repo(
    repo_url: &str,
) -> Result<DigestMap, PolicyGenerationError> {
    let base_url = if repo_url.ends_with('/') {
        repo_url.to_string()
    } else {
        format!("{repo_url}/")
    };

    // Download repomd.xml
    let repomd_url = format!("{base_url}repodata/repomd.xml");
    let repomd_xml = fetch_text(&repomd_url).await.map_err(|e| {
        PolicyGenerationError::RpmParse {
            path: PathBuf::from(&repomd_url),
            reason: format!("Failed to download repomd.xml: {e}"),
        }
    })?;

    // Try fast path: filelists-ext.xml
    if let Some(filelists_href) =
        parse_repomd_location(&repomd_xml, "filelists-ext")
    {
        let filelists_url = format!("{base_url}{filelists_href}");
        log::info!("Using filelists-ext.xml fast path: {filelists_url}");

        match fetch_and_decompress(&filelists_url).await {
            Ok(xml_data) => {
                let xml = String::from_utf8_lossy(&xml_data);
                return parse_filelists_ext(&xml);
            }
            Err(e) => {
                log::warn!(
                    "Failed to fetch filelists-ext.xml: {e}; \
                     falling back to RPM downloads"
                );
            }
        }
    }

    // Slow path: parse primary.xml for RPM URLs, download
    // each RPM file and parse its header.
    log::warn!(
        "filelists-ext.xml not available; \
         using slow path (downloading RPM files)"
    );

    let primary_href = parse_repomd_location(&repomd_xml, "primary")
        .ok_or_else(|| PolicyGenerationError::RpmParse {
            path: PathBuf::from(&base_url),
            reason: "No primary metadata found in repomd.xml".to_string(),
        })?;

    let primary_url = format!("{base_url}{primary_href}");
    let primary_data =
        fetch_and_decompress(&primary_url).await.map_err(|e| {
            PolicyGenerationError::RpmParse {
                path: PathBuf::from(&primary_url),
                reason: format!("Failed to download primary.xml: {e}"),
            }
        })?;

    let primary_xml = String::from_utf8_lossy(&primary_data);
    let rpm_urls = parse_primary_rpm_urls(&primary_xml, &base_url)?;

    log::info!("Found {} RPM packages to analyze", rpm_urls.len());

    let mut merged = DigestMap::new();
    for rpm_url in &rpm_urls {
        match fetch_and_parse_rpm(rpm_url).await {
            Ok(pkg_digests) => {
                merge_digest_maps(&mut merged, &pkg_digests);
            }
            Err(e) => {
                log::warn!("Failed to analyze {rpm_url}: {e}");
            }
        }
    }

    Ok(merged)
}

/// Find all `.rpm` files recursively in a directory.
fn find_rpm_files(dir: &Path) -> Result<Vec<PathBuf>, PolicyGenerationError> {
    let mut rpm_files = Vec::new();
    find_rpm_files_recursive(dir, &mut rpm_files)?;
    Ok(rpm_files)
}

fn find_rpm_files_recursive(
    dir: &Path,
    results: &mut Vec<PathBuf>,
) -> Result<(), PolicyGenerationError> {
    let entries = std::fs::read_dir(dir).map_err(|e| {
        PolicyGenerationError::RpmParse {
            path: dir.to_path_buf(),
            reason: format!("Failed to read directory: {e}"),
        }
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| PolicyGenerationError::RpmParse {
            path: dir.to_path_buf(),
            reason: format!("Failed to read directory entry: {e}"),
        })?;

        let path = entry.path();
        if path.is_dir() {
            find_rpm_files_recursive(&path, results)?;
        } else if let Some(ext) = path.extension() {
            if ext == "rpm" {
                results.push(path);
            }
        }
    }

    Ok(())
}

/// Merge src DigestMap into dst, deduplicating digest values.
fn merge_digest_maps(dst: &mut DigestMap, src: &DigestMap) {
    for (path, digests) in src {
        let entry = dst.entry(path.clone()).or_default();
        for digest in digests {
            if !entry.contains(digest) {
                entry.push(digest.clone());
            }
        }
    }
}

/// Parse repomd.xml to find the location of a specific data type.
///
/// Looks for `<data type="TYPE"><location href="..."/>` and
/// returns the href value.
fn parse_repomd_location(xml: &str, data_type: &str) -> Option<String> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);
    let mut buf = Vec::new();
    let mut in_target_data = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                if e.local_name().as_ref() == b"data" {
                    for attr in e.attributes().flatten() {
                        if attr.key.local_name().as_ref() == b"type"
                            && attr.value.as_ref() == data_type.as_bytes()
                        {
                            in_target_data = true;
                        }
                    }
                }
            }
            Ok(Event::Empty(e)) => {
                if in_target_data && e.local_name().as_ref() == b"location" {
                    for attr in e.attributes().flatten() {
                        if attr.key.local_name().as_ref() == b"href" {
                            return Some(
                                String::from_utf8_lossy(&attr.value)
                                    .to_string(),
                            );
                        }
                    }
                }
            }
            Ok(Event::End(e)) => {
                if e.local_name().as_ref() == b"data" {
                    in_target_data = false;
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    None
}

/// Parse filelists-ext.xml to extract file digests.
///
/// Looks for `<file hash="HEX">PATH</file>` elements.
fn parse_filelists_ext(
    xml: &str,
) -> Result<DigestMap, PolicyGenerationError> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);
    let mut buf = Vec::new();
    let mut digests = DigestMap::new();
    let mut current_hash: Option<String> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                if e.local_name().as_ref() == b"file" {
                    for attr in e.attributes().flatten() {
                        if attr.key.local_name().as_ref() == b"hash" {
                            current_hash = Some(
                                String::from_utf8_lossy(&attr.value)
                                    .to_string(),
                            );
                        }
                    }
                }
            }
            Ok(Event::Text(e)) => {
                if let Some(ref hash) = current_hash {
                    let text = e.unescape().unwrap_or_default().to_string();
                    if !text.is_empty() {
                        digests.entry(text).or_default().push(hash.clone());
                    }
                }
            }
            Ok(Event::End(e)) => {
                if e.local_name().as_ref() == b"file" {
                    current_hash = None;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(PolicyGenerationError::RpmParse {
                    path: PathBuf::from("<filelists-ext.xml>"),
                    reason: format!("XML parse error: {e}"),
                });
            }
            _ => {}
        }
        buf.clear();
    }

    Ok(digests)
}

/// Parse primary.xml to get RPM package location URLs.
fn parse_primary_rpm_urls(
    xml: &str,
    base_url: &str,
) -> Result<Vec<String>, PolicyGenerationError> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);
    let mut buf = Vec::new();
    let mut urls = Vec::new();
    let mut in_package = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                if e.local_name().as_ref() == b"package" {
                    for attr in e.attributes().flatten() {
                        if attr.key.local_name().as_ref() == b"type"
                            && attr.value.as_ref() == b"rpm"
                        {
                            in_package = true;
                        }
                    }
                }
            }
            Ok(Event::Empty(e)) => {
                if in_package && e.local_name().as_ref() == b"location" {
                    for attr in e.attributes().flatten() {
                        if attr.key.local_name().as_ref() == b"href" {
                            let href = String::from_utf8_lossy(&attr.value);
                            urls.push(format!("{base_url}{href}"));
                        }
                    }
                }
            }
            Ok(Event::End(e)) => {
                if e.local_name().as_ref() == b"package" {
                    in_package = false;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(PolicyGenerationError::RpmParse {
                    path: PathBuf::from("<primary.xml>"),
                    reason: format!("XML parse error: {e}"),
                });
            }
            _ => {}
        }
        buf.clear();
    }

    Ok(urls)
}

/// Fetch text content from a URL.
async fn fetch_text(url: &str) -> Result<String, PolicyGenerationError> {
    let response = reqwest::get(url).await.map_err(|e| {
        PolicyGenerationError::RpmParse {
            path: PathBuf::from(url),
            reason: format!("HTTP request failed: {e}"),
        }
    })?;
    let status = response.status();
    if !status.is_success() {
        return Err(PolicyGenerationError::RpmParse {
            path: PathBuf::from(url),
            reason: format!("HTTP {status}"),
        });
    }
    response
        .text()
        .await
        .map_err(|e| PolicyGenerationError::RpmParse {
            path: PathBuf::from(url),
            reason: format!("Failed to read response body: {e}"),
        })
}

/// Fetch data from a URL and decompress if needed (gzip, xz,
/// zstd, bzip2).
async fn fetch_and_decompress(
    url: &str,
) -> Result<Vec<u8>, PolicyGenerationError> {
    let response = reqwest::get(url).await.map_err(|e| {
        PolicyGenerationError::RpmParse {
            path: PathBuf::from(url),
            reason: format!("HTTP request failed: {e}"),
        }
    })?;
    let status = response.status();
    if !status.is_success() {
        return Err(PolicyGenerationError::RpmParse {
            path: PathBuf::from(url),
            reason: format!("HTTP {status}"),
        });
    }
    let data = response.bytes().await.map_err(|e| {
        PolicyGenerationError::RpmParse {
            path: PathBuf::from(url),
            reason: format!("Failed to read response body: {e}"),
        }
    })?;
    let data = data.to_vec();

    decompress_data(&data, url)
}

/// Detect compression format and decompress data.
fn decompress_data(
    data: &[u8],
    source: &str,
) -> Result<Vec<u8>, PolicyGenerationError> {
    if data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b {
        // Gzip
        let mut decoder = flate2::read::GzDecoder::new(data);
        let mut decompressed = Vec::new();
        let _ = decoder.read_to_end(&mut decompressed).map_err(|e| {
            PolicyGenerationError::RpmParse {
                path: PathBuf::from(source),
                reason: format!("Gzip decompression failed: {e}"),
            }
        })?;
        Ok(decompressed)
    } else if data.len() >= 6
        && data[0..6] == [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]
    {
        // XZ
        let mut decoder = xz2::read::XzDecoder::new(data);
        let mut decompressed = Vec::new();
        let _ = decoder.read_to_end(&mut decompressed).map_err(|e| {
            PolicyGenerationError::RpmParse {
                path: PathBuf::from(source),
                reason: format!("XZ decompression failed: {e}"),
            }
        })?;
        Ok(decompressed)
    } else if data.len() >= 4 && data[0..4] == [0x28, 0xb5, 0x2f, 0xfd] {
        // Zstd
        let mut decoder = zstd::stream::Decoder::new(data).map_err(|e| {
            PolicyGenerationError::RpmParse {
                path: PathBuf::from(source),
                reason: format!("Zstd init failed: {e}"),
            }
        })?;
        let mut decompressed = Vec::new();
        let _ = decoder.read_to_end(&mut decompressed).map_err(|e| {
            PolicyGenerationError::RpmParse {
                path: PathBuf::from(source),
                reason: format!("Zstd decompression failed: {e}"),
            }
        })?;
        Ok(decompressed)
    } else if data.len() >= 3
        && data[0] == b'B'
        && data[1] == b'Z'
        && data[2] == b'h'
    {
        // Bzip2
        let mut decoder = bzip2::read::BzDecoder::new(data);
        let mut decompressed = Vec::new();
        let _ = decoder.read_to_end(&mut decompressed).map_err(|e| {
            PolicyGenerationError::RpmParse {
                path: PathBuf::from(source),
                reason: format!("Bzip2 decompression failed: {e}"),
            }
        })?;
        Ok(decompressed)
    } else {
        // Assume uncompressed
        Ok(data.to_vec())
    }
}

/// Fetch and parse an RPM file from a remote URL.
///
/// Downloads the full RPM file and parses only the header
/// metadata to extract file digests.
async fn fetch_and_parse_rpm(
    url: &str,
) -> Result<DigestMap, PolicyGenerationError> {
    let response = reqwest::get(url).await.map_err(|e| {
        PolicyGenerationError::RpmParse {
            path: PathBuf::from(url),
            reason: format!("HTTP request failed: {e}"),
        }
    })?;
    let status = response.status();
    if !status.is_success() {
        return Err(PolicyGenerationError::RpmParse {
            path: PathBuf::from(url),
            reason: format!("HTTP {status}"),
        });
    }
    let data = response.bytes().await.map_err(|e| {
        PolicyGenerationError::RpmParse {
            path: PathBuf::from(url),
            reason: format!("Failed to read response body: {e}"),
        }
    })?;

    let metadata =
        rpm::PackageMetadata::parse(&mut std::io::Cursor::new(&data))
            .map_err(|e| PolicyGenerationError::RpmParse {
                path: PathBuf::from(url),
                reason: format!("Failed to parse RPM header: {e}"),
            })?;

    extract_digests_from_metadata(&metadata, Path::new(url))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_empty_digest() {
        assert!(is_empty_digest("00000000000000000000000000000000"));
        assert!(is_empty_digest(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ));
        assert!(!is_empty_digest("abcdef1234567890abcdef1234567890"));
        assert!(!is_empty_digest(""));
        assert!(is_empty_digest("0"));
    }

    #[test]
    fn test_merge_digest_maps() {
        let mut dst = DigestMap::new();
        let _ = dst.insert("/usr/bin/a".into(), vec!["aaaa".into()]);

        let mut src = DigestMap::new();
        let _ = src.insert("/usr/bin/a".into(), vec!["bbbb".into()]);
        let _ = src.insert("/usr/bin/b".into(), vec!["cccc".into()]);

        merge_digest_maps(&mut dst, &src);

        assert_eq!(dst["/usr/bin/a"].len(), 2);
        assert!(dst["/usr/bin/a"].contains(&"aaaa".to_string()));
        assert!(dst["/usr/bin/a"].contains(&"bbbb".to_string()));
        assert_eq!(dst["/usr/bin/b"], vec!["cccc".to_string()]);
    }

    #[test]
    fn test_merge_digest_maps_dedup() {
        let mut dst = DigestMap::new();
        let _ = dst.insert("/usr/bin/a".into(), vec!["aaaa".into()]);

        let mut src = DigestMap::new();
        let _ = src.insert("/usr/bin/a".into(), vec!["aaaa".into()]);

        merge_digest_maps(&mut dst, &src);

        assert_eq!(dst["/usr/bin/a"].len(), 1);
    }

    #[test]
    fn test_parse_repomd_location_filelists_ext() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <data type="primary">
    <location href="repodata/primary.xml.gz"/>
  </data>
  <data type="filelists-ext">
    <location href="repodata/filelists-ext.xml.gz"/>
  </data>
  <data type="filelists">
    <location href="repodata/filelists.xml.gz"/>
  </data>
</repomd>"#;

        let result = parse_repomd_location(xml, "filelists-ext");
        assert_eq!(result, Some("repodata/filelists-ext.xml.gz".to_string()));

        let result = parse_repomd_location(xml, "primary");
        assert_eq!(result, Some("repodata/primary.xml.gz".to_string()));

        let result = parse_repomd_location(xml, "nonexistent");
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_filelists_ext() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<filelists-ext xmlns="http://linux.duke.edu/metadata/filelists-ext">
  <package name="bash" arch="x86_64">
    <file hash="abcdef1234567890">/usr/bin/bash</file>
    <file hash="1234567890abcdef">/usr/bin/sh</file>
  </package>
  <package name="coreutils" arch="x86_64">
    <file hash="deadbeef12345678">/usr/bin/ls</file>
  </package>
</filelists-ext>"#;

        let result = parse_filelists_ext(xml).unwrap(); //#[allow_ci]
        assert_eq!(result.len(), 3);
        assert_eq!(result["/usr/bin/bash"], vec!["abcdef1234567890"]);
        assert_eq!(result["/usr/bin/sh"], vec!["1234567890abcdef"]);
        assert_eq!(result["/usr/bin/ls"], vec!["deadbeef12345678"]);
    }

    #[test]
    fn test_parse_primary_rpm_urls() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" packages="2">
  <package type="rpm">
    <name>bash</name>
    <location href="Packages/bash-5.2.26-1.fc40.x86_64.rpm"/>
  </package>
  <package type="rpm">
    <name>coreutils</name>
    <location href="Packages/coreutils-9.4-1.fc40.x86_64.rpm"/>
  </package>
</metadata>"#;

        let urls =
            parse_primary_rpm_urls(xml, "https://example.com/repo/").unwrap(); //#[allow_ci]
        assert_eq!(urls.len(), 2);
        assert_eq!(
            urls[0],
            "https://example.com/repo/Packages/bash-5.2.26-1.fc40.x86_64.rpm"
        );
        assert_eq!(
            urls[1],
            "https://example.com/repo/Packages/coreutils-9.4-1.fc40.x86_64.rpm"
        );
    }

    #[test]
    fn test_find_rpm_files() {
        let dir = tempfile::tempdir().unwrap(); //#[allow_ci]

        // Create test files
        std::fs::write(dir.path().join("test1.rpm"), b"fake").unwrap(); //#[allow_ci]
        std::fs::write(dir.path().join("test2.rpm"), b"fake").unwrap(); //#[allow_ci]
        std::fs::write(dir.path().join("readme.txt"), b"text").unwrap(); //#[allow_ci]

        let subdir = dir.path().join("subdir");
        std::fs::create_dir(&subdir).unwrap(); //#[allow_ci]
        std::fs::write(subdir.join("test3.rpm"), b"fake").unwrap(); //#[allow_ci]

        let rpm_files = find_rpm_files(dir.path()).unwrap(); //#[allow_ci]
        assert_eq!(rpm_files.len(), 3);
        assert!(rpm_files.iter().all(|p| p.extension().unwrap() == "rpm")); //#[allow_ci]
    }

    #[test]
    fn test_decompress_uncompressed() {
        let data = b"hello world";
        let result = decompress_data(data, "test").unwrap(); //#[allow_ci]
        assert_eq!(result, b"hello world");
    }

    #[test]
    fn test_decompress_gzip() {
        use flate2::write::GzEncoder;
        use std::io::Write;

        let mut encoder =
            GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"gzip test data").unwrap(); //#[allow_ci]
        let compressed = encoder.finish().unwrap(); //#[allow_ci]

        let result = decompress_data(&compressed, "test").unwrap(); //#[allow_ci]
        assert_eq!(result, b"gzip test data");
    }

    #[test]
    fn test_parse_repomd_empty() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
</repomd>"#;

        let result = parse_repomd_location(xml, "primary");
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_filelists_ext_empty() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<filelists-ext xmlns="http://linux.duke.edu/metadata/filelists-ext">
</filelists-ext>"#;

        let result = parse_filelists_ext(xml).unwrap(); //#[allow_ci]
        assert!(result.is_empty());
    }
}
