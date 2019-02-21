#![allow(missing_docs)]

use crate::vec::Vec;

use crate::leb128;
use crate::Format;
use test_assembler::{Label, Section};

pub trait GimliSectionMethods {
    fn sleb(self, val: i64) -> Self;
    fn uleb(self, val: u64) -> Self;
    fn initial_length(self, format: Format, length: &Label, start: &Label) -> Self;
    fn word(self, size: u8, val: u64) -> Self;
    fn word_label(self, size: u8, val: &Label) -> Self;
}

impl GimliSectionMethods for Section {
    fn sleb(self, val: i64) -> Self {
        let mut buf = Vec::new();
        let written = leb128::write::signed(&mut buf, val).unwrap();
        self.append_bytes(&buf[0..written])
    }

    fn uleb(self, val: u64) -> Self {
        let mut buf = Vec::new();
        let written = leb128::write::unsigned(&mut buf, val).unwrap();
        self.append_bytes(&buf[0..written])
    }

    fn initial_length(self, format: Format, length: &Label, start: &Label) -> Self {
        match format {
            Format::Dwarf32 => self.D32(length).mark(start),
            Format::Dwarf64 => self.D32(0xffff_ffff).D64(length).mark(start),
        }
    }

    fn word(self, size: u8, val: u64) -> Self {
        match size {
            4 => self.D32(val as u32),
            8 => self.D64(val),
            _ => panic!("unsupported word size"),
        }
    }

    fn word_label(self, size: u8, val: &Label) -> Self {
        match size {
            4 => self.D32(val),
            8 => self.D64(val),
            _ => panic!("unsupported word size"),
        }
    }
}
