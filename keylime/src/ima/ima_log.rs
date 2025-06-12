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
}
