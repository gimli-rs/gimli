#![no_main]

use gimli::{read::DebugAbbrev, DebugAbbrevOffset, LittleEndian};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|debug_abbrev: &[u8]| {
    let len = debug_abbrev.len();
    let debug_abbrev = DebugAbbrev::new(&debug_abbrev, LittleEndian);

    let offset = DebugAbbrevOffset(0);
    if let Ok(abbreviations) = debug_abbrev.abbreviations(offset) {
        for i in 1..len {
            let _ = abbreviations.get(i as u64);
        }
    }
});
