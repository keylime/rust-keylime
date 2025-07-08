use crate::ima::entry;
use std::fs;

use crate::error::{Error as KeylimeError, Result};

pub struct ImaLog {
    pub entries: Vec<entry::Entry>,
}

impl ImaLog {
    pub fn new(log_path: &str) -> Result<Self> {
        let contents = fs::read_to_string(log_path).map_err(|e| {
            KeylimeError::Other(format!(
                "Unable to parse IMA file {}: {}",
                log_path, e
            ))
        })?;
        let entries = contents
            .lines()
            .filter_map(|line| entry::Entry::try_from(line).ok())
            .collect::<Vec<entry::Entry>>();
        if entries.is_empty() {
            return Err(KeylimeError::Other(format!(
                "No valid entries found in IMA log file: {}",
                log_path
            )));
        }
        Ok(Self { entries })
    }
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
    pub fn get_entries(
        &self,
        offset: usize,
        entry_count: Option<usize>,
    ) -> Vec<String> {
        if offset >= self.entries.len() {
            return Vec::new();
        }
        let end = match entry_count {
            Some(count) => std::cmp::min(offset + count, self.entries.len()),
            None => self.entries.len(),
        };
        self.entries[offset..end]
            .iter()
            .map(|entry| entry.raw_line.clone())
            .collect()
    }
    pub fn get_entries_as_string(
        &self,
        offset: usize,
        entry_count: Option<usize>,
    ) -> String {
        let entries = self.get_entries(offset, entry_count);
        let mut result = entries.join("\n");
        if !result.is_empty() {
            result.push('\n');
        }
        result
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[tokio::test]
    #[cfg(feature = "testing")]
    async fn test_ima_log() {
        use super::*;
        let log_path = "/sys/kernel/security/ima/ascii_runtime_measurements";
        if std::path::Path::new(log_path).exists() {
            let ima_log = ImaLog::new(log_path);
            if let Ok(log) = ima_log {
                assert!(log.entry_count() > 0, "IMA log should have entries");
            }
        }
    }

    #[test]
    fn test_ima_log_parser() {
        let log_path = "test-data/ima_log.txt";
        let ima_log = ImaLog::new(log_path);
        if let Ok(log) = ima_log {
            assert!(log.entry_count() > 0, "IMA log should have entries");
        }
    }

    #[test]
    fn test_ima_log_empty() {
        let log_path = "test-data/empty_ima_log.txt";
        let ima_log = ImaLog::new(log_path);
        assert!(ima_log.is_err(), "Should return an error for empty log");
    }

    #[test]
    fn test_unexisting_log() {
        let log_path = "/non/existent/ima/log.txt";
        let ima_log = ImaLog::new(log_path);
        assert!(
            ima_log.is_err(),
            "Should return an error for non-existent log"
        );
    }

    #[test]
    fn test_invalid_log() {
        let log_path = "test-data/invalid_ima_log.txt";
        let ima_log = ImaLog::new(log_path);
        assert!(
            ima_log.is_err(),
            "Should return an error for invalid log format"
        );
    }

    #[test]
    fn test_get_all_entries_as_string() {
        let log_path = "test-data/ima_log.txt";
        let ima_log =
            ImaLog::new(log_path).expect("Failed to create ImaLog from file");
        let original_content = fs::read_to_string(log_path)
            .expect("Failed to read original log file");
        let result_string =
            ima_log.get_entries_as_string(0, Some(ima_log.entry_count()));
        assert_eq!(result_string, original_content);
    }
}
