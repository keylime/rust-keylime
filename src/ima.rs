// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

#[macro_use]
use log::*;

use std::collections::HashSet;
use std::fs::File;
use std::io::prelude::*;
use std::io::Error;
use std::io::SeekFrom;
use std::path::Path;
use std::str;

use tempfile::NamedTempFile;

/// IMAMeasurementList models the IMA measurement lists's last two known
/// numbers of entries in the log and filesizes at that point
#[derive(Debug)]
pub(crate) struct ImaMeasurementList {
    entries: HashSet<(u64, u64)>,
}

pub type IMAError = Result<(String, u64, u64), Error>;

impl ImaMeasurementList {
    pub(crate) fn new() -> ImaMeasurementList {
        let mut iml = ImaMeasurementList {
            entries: HashSet::new(),
        };
        let _ = iml.reset();
        iml
    }

    fn reset(&mut self) {
        self.entries = HashSet::new();
    }

    fn update(&mut self, num_entries: u64, filesize: u64) {
        if self.entries.len() > 32 {
            let e = self.entries.iter().next().cloned().unwrap();
            let _ = self.entries.remove(&e);
        }
        let _ = self.entries.insert((num_entries, filesize));
    }

    fn find(&self, nth_entry: u64) -> (u64, u64) {
        let mut best = (0, 0);
        for entry in self.entries.iter() {
            if entry.0 > best.0 && entry.0 < nth_entry {
                best = *entry
            }
        }
        return best;
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
    let mut nth_entry = nth_entry;

    // Try to find the closest entry to the nth_entry
    let (mut num_entries, filesize) = ima_ml.find(nth_entry);

    let mut ml = None;
    let mut filedata = String::new();

    if !Path::new(filename).exists() {
        let _ = ima_ml.reset();
        nth_entry = 0;
        log::warn!(
            "IMA measurement list not available: {}",
            filename.to_str().unwrap()
        );
    } else {
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
        ima_ml.update(num_entries, filesize + offset as u64);

        match ml {
            None => return read_measurement_list(ima_ml, filename, 0),
            Some(_) => (),
        }
    }
    return Ok((String::from(ml.unwrap()), nth_entry, num_entries));
}

#[test]
fn read_measurement_list_test() {
    let mut ima_ml = ImaMeasurementList::new();

    let filedata = "0-entry\n1-entry\n2-entry\n";
    let mut tf = match NamedTempFile::new() {
        Ok(tf) => tf,
        Err(_) => panic!("Could not create temp file"),
    };
    tf.write_all(filedata.as_bytes());
    tf.flush();

    // Request the 2nd entry, which is available
    let (ml, nth_entry, num_entries) =
        match read_measurement_list(&mut ima_ml, tf.path(), 2) {
            Err(v) => panic!("Reading measurement list failed: {}", v),
            Ok((ml, nth_entry, num_entries)) => (ml, nth_entry, num_entries),
        };
    assert_eq!(num_entries, 3);
    assert_eq!(nth_entry, 2);
    assert_eq!(ml.find("2-entry").unwrap(), 0);

    // Request the 3rd entry, which is not available yet, thus we get an empty list
    let (ml, nth_entry, num_entries) =
        match read_measurement_list(&mut ima_ml, tf.path(), 3) {
            Err(v) => panic!("Reading measurement list failed: {}", v),
            Ok((ml, nth_entry, num_entries)) => (ml, nth_entry, num_entries),
        };
    assert_eq!(num_entries, 3);
    assert_eq!(nth_entry, 3);
    assert_eq!(ml.len(), 0);

    // Request the 4th entry, which is beyond the next entry; since this is wrong,
    // we expect the entire list now.
    let (ml, nth_entry, num_entries) =
        match read_measurement_list(&mut ima_ml, tf.path(), 4) {
            Err(v) => panic!("Reading measurement list failed: {}", v),
            Ok((ml, nth_entry, num_entries)) => (ml, nth_entry, num_entries),
        };
    assert_eq!(num_entries, 3);
    assert_eq!(nth_entry, 0);
    assert_eq!(ml.find("0-entry").unwrap(), 0);
}
