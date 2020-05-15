#![no_main]

use gimli::{read::DebugAranges, LittleEndian};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|debug_aranges: &[u8]| {
    let debug_aranges = DebugAranges::new(&debug_aranges, LittleEndian);
    let mut items = debug_aranges.items();
    while let Ok(Some(_entry)) = items.next() {
        continue;
    }
});
