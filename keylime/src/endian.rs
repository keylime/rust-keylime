// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Keylime Authors

use cpu_endian;

// TODO: templatize
pub fn local_endianness_32(input: u32) -> [u8; 4] {
    match cpu_endian::working() {
        cpu_endian::Endian::Little => input.to_le_bytes(),
        cpu_endian::Endian::Big => input.to_be_bytes(),
        _ => panic!("Unexpected endianness"),
    }
}

pub fn local_endianness_16(input: u16) -> [u8; 2] {
    match cpu_endian::working() {
        cpu_endian::Endian::Little => input.to_le_bytes(),
        cpu_endian::Endian::Big => input.to_be_bytes(),
        _ => panic!("Unexpected endianness"),
    }
}

pub fn local_endianness_8(input: u8) -> [u8; 1] {
    match cpu_endian::working() {
        cpu_endian::Endian::Little => input.to_le_bytes(),
        cpu_endian::Endian::Big => input.to_be_bytes(),
        _ => panic!("Unexpected endianness"),
    }
}
