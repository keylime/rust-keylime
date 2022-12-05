// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use std::{
    collections::HashSet,
    fs::File,
    io::{prelude::*, Error, SeekFrom},
};

/// MeasurementList models the IMA measurement lists's last two known
/// numbers of entries in the log and filesizes at that point
#[derive(Debug)]
pub struct MeasurementList {
    entries: HashSet<(u64, u64)>,
}

impl MeasurementList {
    pub fn new() -> Self {
        Self {
            entries: HashSet::new(),
        }
    }

    pub fn reset(&mut self) {
        self.entries = HashSet::new();
    }

    fn update(&mut self, num_entries: u64, filesize: u64) -> Option<bool> {
        if self.entries.len() > 32 {
            let e = *self.entries.iter().next()?;
            let _ = self.entries.remove(&e);
        }
        Some(self.entries.insert((num_entries, filesize)))
    }

    fn find(&self, nth_entry: u64) -> (u64, u64) {
        self.entries.iter().fold((0, 0), |best, entry| {
            if entry.0 > best.0 && entry.0 < nth_entry {
                *entry
            } else {
                best
            }
        })
    }

    /// Read the IMA measurement list starting from a given entry.
    /// The entry may be of any value 0 <= entry <= entries_in_log where
    /// entries_in_log + 1 indicates that the client wants to read the next entry
    /// once available. If the entry is outside this range, the function will
    /// automatically read from the 0-th entry.
    /// This function returns the measurement list and the entry from where it
    /// was read and the current number of entries in the file.
    pub fn read(
        &mut self,
        ima_file: &mut File,
        nth_entry: u64,
    ) -> Result<(String, u64, u64), Error> {
        // Try to find the closest entry to the nth_entry
        let (mut num_entries, filesize) = self.find(nth_entry);

        let mut ml = None;
        let mut filedata = String::new();
        let _ = ima_file.seek(SeekFrom::Start(filesize))?;
        let _ = ima_file.read_to_string(&mut filedata)?;
        let mut offset: usize = 0;

        loop {
            if nth_entry == num_entries {
                ml = Some(&filedata[offset..]);
            }
            let s = &filedata[offset..];
            let idx = match s.find('\n') {
                None => break,
                Some(i) => i,
            };
            offset = offset + idx + 1;
            num_entries += 1;
        }

        let _ = self.update(num_entries, filesize + offset as u64);

        match ml {
            None => self.read(ima_file, 0),
            Some(slice) => Ok((String::from(slice), nth_entry, num_entries)),
        }
    }
}

impl Default for MeasurementList {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn read_measurement_list_test() {
        let mut ima_ml = MeasurementList::new();

        let filedata = "0-entry\n1-entry\n2-entry\n";
        let mut tf = NamedTempFile::new().unwrap(); //#[allow_ci]
        tf.write_all(filedata.as_bytes()).unwrap(); //#[allow_ci]
        tf.flush().unwrap(); //#[allow_ci]

        let mut ima_file = File::open(tf.path()).unwrap(); //#[allow_ci]

        // Request the 2nd entry, which is available
        let (ml, nth_entry, num_entries) =
            ima_ml.read(&mut ima_file, 2).unwrap(); //#[allow_ci]
        assert_eq!(num_entries, 3);
        assert_eq!(nth_entry, 2);
        assert_eq!(ml.find("2-entry").unwrap(), 0); //#[allow_ci]

        // Request the 3rd entry, which is not available yet, thus we get an empty list
        let (ml, nth_entry, num_entries) =
            ima_ml.read(&mut ima_file, 3).unwrap(); //#[allow_ci]
        assert_eq!(num_entries, 3);
        assert_eq!(nth_entry, 3);
        assert_eq!(ml.len(), 0); //#[allow_ci]

        // Request the 4th entry, which is beyond the next entry; since this is wrong,
        // we expect the entire list now.
        let (ml, nth_entry, num_entries) =
            ima_ml.read(&mut ima_file, 4).unwrap(); //#[allow_ci]
        assert_eq!(num_entries, 3);
        assert_eq!(nth_entry, 0);
        assert_eq!(ml.find("0-entry").unwrap(), 0); //#[allow_ci]
    }
}
