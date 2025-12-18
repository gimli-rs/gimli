#![no_main]

use gimli::{DebugNames, LittleEndian};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|section: &[u8]| {
    let debug_names = DebugNames::new(section, LittleEndian);

    let mut headers = debug_names.headers();
    while let Ok(Some(header)) = headers.next() {
        let Ok(name_index) = header.index() else {
            continue;
        };
        for i in 0..name_index.bucket_count() {
            let Ok(Some(mut bucket)) = name_index.find_by_bucket(i) else {
                continue;
            };
            while let Ok(Some((index, _hash))) = bucket.next() {
                let Ok(mut entries) = name_index.name_entries(index) else {
                    continue;
                };
                while let Ok(Some(entry)) = entries.next() {
                    let _ = entry.compile_unit(&name_index);
                    let _ = entry.type_unit(&name_index);
                }
            }
        }
    }
});
