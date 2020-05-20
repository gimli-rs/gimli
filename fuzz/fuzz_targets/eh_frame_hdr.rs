#![no_main]

use gimli::{read::EhFrameHdr, BaseAddresses, LittleEndian};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|eh_frame_hdr: &[u8]| {
    let eh_frame_hdr = EhFrameHdr::new(eh_frame_hdr, LittleEndian);
    let bases = BaseAddresses::default()
        .set_eh_frame(0)
        .set_eh_frame_hdr(0)
        .set_text(0)
        .set_got(0);
    let address_size = 8;
    let _ = eh_frame_hdr.parse(&bases, address_size);
});
