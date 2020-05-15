#![no_main]

use gimli::{
    read::{BaseAddresses, CieOrFde, EhFrame, UninitializedUnwindContext, UnwindSection},
    LittleEndian,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|eh_frame: &[u8]| {
    let eh_frame = EhFrame::new(&eh_frame, LittleEndian);

    let mut ctx = UninitializedUnwindContext::new();
    let bases = BaseAddresses::default()
        .set_eh_frame(0)
        .set_eh_frame_hdr(0)
        .set_text(0)
        .set_got(0);

    let mut entries = eh_frame.entries(&bases);
    while let Ok(Some(entry)) = entries.next() {
        match entry {
            CieOrFde::Cie(_) => continue,
            CieOrFde::Fde(partial) => {
                if let Ok(fde) = partial.parse(EhFrame::cie_from_offset) {
                    if let Ok(mut table) = fde.rows(&eh_frame, &bases, &mut ctx) {
                        while let Ok(Some(_row)) = table.next_row() {
                            continue;
                        }
                    }
                }
            }
        };
    }
});
