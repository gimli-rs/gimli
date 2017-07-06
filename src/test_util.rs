#![allow(missing_docs)]

extern crate test_assembler;

use leb128;
use self::test_assembler::{Endian, Section, ToLabelOrNum};

pub trait GimliSectionMethods {
    fn e32<'a, T>(self, endian: Endian, val: T) -> Self where T: ToLabelOrNum<'a, u32>;
    fn e64<'a, T>(self, endian: Endian, val: T) -> Self where T: ToLabelOrNum<'a, u64>;
    fn sleb(self, val: i64) -> Self;
    fn uleb(self, val: u64) -> Self;
}

impl GimliSectionMethods for Section {
    fn e32<'a, T>(self, endian: Endian, val: T) -> Self
        where T: ToLabelOrNum<'a, u32>
    {
        match endian {
            Endian::Little => self.L32(val),
            Endian::Big => self.B32(val),
        }
    }

    fn e64<'a, T>(self, endian: Endian, val: T) -> Self
        where T: ToLabelOrNum<'a, u64>
    {
        match endian {
            Endian::Little => self.L64(val),
            Endian::Big => self.B64(val),
        }
    }

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
