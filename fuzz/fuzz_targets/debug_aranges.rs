#![no_main]

use gimli::{read::DebugAranges, LittleEndian};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|debug_aranges: &[u8]| {
    let debug_aranges = DebugAranges::new(&debug_aranges, LittleEndian);
    let mut headers = debug_aranges.headers();
    while let Ok(Some(header)) = headers.next() {
        let mut entries = header.entries();
        while let Ok(Some(_entry)) = entries.next() {
            continue;
        }
    }
});
