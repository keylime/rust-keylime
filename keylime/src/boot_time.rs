use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use std::fs::File;
use std::io::{BufRead, BufReader};

/// Returns the system boot time as a `DateTime<Utc>` object by reading /proc/stat.
pub fn get_boot_time() -> Result<DateTime<Utc>> {
    let file = File::open("/proc/stat")?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        if line.starts_with("btime") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let timestamp = parts[1].parse::<i64>()?;
                let boot_datetime = DateTime::from_timestamp(timestamp, 0)
                    .ok_or_else(|| {
                        anyhow!(
                            "Invalid or out-of-range Unix timestamp: {}",
                            timestamp
                        )
                    })?;

                return Ok(boot_datetime);
            }
        }
    }

    Err(anyhow!("btime field not found in /proc/stat"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_boot_time() {
        let boot_time1 = get_boot_time().unwrap(); //#[allow_ci]
        let boot_time2 = get_boot_time().unwrap(); //#[allow_ci]
        assert_eq!(boot_time1, boot_time2);
    }
}
