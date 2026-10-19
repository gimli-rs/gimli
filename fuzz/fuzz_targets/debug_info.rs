#![no_main]

use gimli::{
    read::{AbbreviationsCache, AbbreviationsCacheStrategy, DebugAbbrev, DebugInfo},
    LittleEndian,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|sections: (Vec<u8>, Vec<u8>)| {
    let (debug_abbrev, debug_info) = sections;
    let debug_abbrev = DebugAbbrev::new(&debug_abbrev, LittleEndian);
    let debug_info = DebugInfo::new(&debug_info, LittleEndian);

    let mut abbreviations_cache = AbbreviationsCache::new();
    abbreviations_cache.populate(
        AbbreviationsCacheStrategy::Duplicates,
        &debug_abbrev,
        debug_info.units(),
    );

    let mut units = debug_info.units();
    while let Ok(Some(unit)) = units.next() {
        if let Ok(abbrevs) = abbreviations_cache.get(&debug_abbrev, unit.debug_abbrev_offset()) {
            let mut cursor = unit.entries(&abbrevs);
            while let Ok(Some(_)) = cursor.next_dfs() {
                continue;
            }
        }
    }
});
