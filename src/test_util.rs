#![allow(missing_docs)]

extern crate test_assembler;

use vec::Vec;

use self::test_assembler::Section;
use leb128;

pub trait GimliSectionMethods {
    fn sleb(self, val: i64) -> Self;
    fn uleb(self, val: u64) -> Self;
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
}
