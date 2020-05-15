#![no_main]

use gimli::{read::DebugLine, DebugLineOffset, LittleEndian};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|debug_line: &[u8]| {
    let debug_line = DebugLine::new(&debug_line, LittleEndian);

    let offset = DebugLineOffset(0);
    let address_size = 8;
    if let Ok(program) = debug_line.program(offset, address_size, None, None) {
        let mut rows = program.rows();
        while let Ok(Some(row)) = rows.next_row() {
            let _ = row;
        }
    }
});
