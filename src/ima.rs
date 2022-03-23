// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use log::*;
use std::{
    collections::HashSet,
    fs::File,
    io::{prelude::*, Error, SeekFrom},
    path::Path,
};

/// IMAMeasurementList models the IMA measurement lists's last two known
/// numbers of entries in the log and filesizes at that point
#[derive(Debug)]
pub(crate) struct ImaMeasurementList {
    entries: HashSet<(u64, u64)>,
}

pub type IMAError = Result<(Option<String>, Option<u64>, Option<u64>), Error>;

impl ImaMeasurementList {
    pub(crate) fn new() -> ImaMeasurementList {
        ImaMeasurementList {
            entries: HashSet::new(),
        }
    }

    fn reset(&mut self) {
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
}

/// Read the IMA measurement list starting from a given entry.
/// The entry may be of any value 0 <= entry <= entries_in_log where
/// entries_in_log + 1 indicates that the client wants to read the next entry
/// once available. If the entry is outside this range, the function will
/// automatically read from the 0-th entry.
/// This function returns the measurement list and the entry from where it
/// was read and the current number of entries in the file.
pub(crate) fn read_measurement_list(
    ima_ml: &mut ImaMeasurementList,
    filename: &Path,
    nth_entry: u64,
) -> IMAError {
    if !Path::new(filename).exists() {
        let _ = ima_ml.reset();
        warn!("IMA measurement list not available: {}", filename.display());
        return Ok((None, None, None));
    }

    let mut nth_entry = nth_entry;

    // Try to find the closest entry to the nth_entry
    let (mut num_entries, filesize) = ima_ml.find(nth_entry);

    let mut ml = None;
    let mut filedata = String::new();
    let mut file = File::open(filename)?;
    let _ = file.seek(SeekFrom::Start(filesize))?;
    let _ = file.read_to_string(&mut filedata)?;
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

    let _ = ima_ml.update(num_entries, filesize + offset as u64);

    match ml {
        None => read_measurement_list(ima_ml, filename, 0),
        Some(slice) => Ok((
            Some(String::from(slice)),
            Some(nth_entry),
            Some(num_entries),
        )),
    }
}

mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn read_measurement_list_test() {
        let mut ima_ml = ImaMeasurementList::new();

        let filedata = "0-entry\n1-entry\n2-entry\n";
        let mut tf = NamedTempFile::new().unwrap(); //#[allow_ci]
        tf.write_all(filedata.as_bytes());
        tf.flush();

        // Request the 2nd entry, which is available
        let (ml, nth_entry, num_entries) =
            read_measurement_list(&mut ima_ml, tf.path(), 2).unwrap(); //#[allow_ci]
        assert_eq!(num_entries, Some(3));
        assert_eq!(nth_entry, Some(2));
        assert_eq!(ml.unwrap().find("2-entry").unwrap(), 0); //#[allow_ci]

        // Request the 3rd entry, which is not available yet, thus we get an empty list
        let (ml, nth_entry, num_entries) =
            read_measurement_list(&mut ima_ml, tf.path(), 3).unwrap(); //#[allow_ci]
        assert_eq!(num_entries, Some(3));
        assert_eq!(nth_entry, Some(3));
        assert_eq!(ml.unwrap().len(), 0); //#[allow_ci]

        // Request the 4th entry, which is beyond the next entry; since this is wrong,
        // we expect the entire list now.
        let (ml, nth_entry, num_entries) =
            read_measurement_list(&mut ima_ml, tf.path(), 4).unwrap(); //#[allow_ci]
        assert_eq!(num_entries, Some(3));
        assert_eq!(nth_entry, Some(0));
        assert_eq!(ml.unwrap().find("0-entry").unwrap(), 0); //#[allow_ci]
    }
}
