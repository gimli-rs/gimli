#![no_main]

use gimli::{
    read::{DebugAbbrev, DebugInfo},
    LittleEndian,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|sections: (Vec<u8>, Vec<u8>)| {
    let (debug_abbrev, debug_info) = sections;
    let debug_abbrev = DebugAbbrev::new(&debug_abbrev, LittleEndian);
    let debug_info = DebugInfo::new(&debug_info, LittleEndian);

    let mut units = debug_info.units();
    while let Ok(Some(unit)) = units.next() {
        if let Ok(abbrevs) = unit.abbreviations(&debug_abbrev) {
            let mut cursor = unit.entries(&abbrevs);
            while let Ok(Some(_)) = cursor.next_dfs() {
                continue;
            }
        }
    }
});
