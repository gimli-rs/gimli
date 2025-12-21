use criterion::{Bencher, Criterion, criterion_main};
use std::hint::black_box;

use gimli::{
    Attribute, AttributeSpecification, AttributeValue, DebugAbbrev, DebugAddr, DebugAddrBase,
    DebugAranges, DebugInfo, DebugLine, DebugLineOffset, DebugLoc, DebugLocLists, DebugPubNames,
    DebugPubTypes, DebugRanges, DebugRngLists, Encoding, EndianSlice, EntriesRaw, EntriesTreeNode,
    Expression, LittleEndian, LocationLists, NativeEndian, Operation, RangeLists, RangeListsOffset,
    Reader, ReaderOffset, leb128,
};
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::rc::Rc;

criterion_main!(benches);
fn benches() {
    bench_leb128();
    bench_read();
    cfi::bench_cfi();
    write::bench_write();
}

fn bench_leb128() {
    let mut c = Criterion::default().configure_from_args();
    c.bench_function("leb128 unsigned small", bench_reading_leb128_unsigned_small);
    c.bench_function("leb128 unsigned large", bench_reading_leb128_unsigned_large);
    c.bench_function("leb128 u16 small", bench_reading_leb128_u16_small);
}

/// Benchmark reading of small (one or two byte in encoded form)
/// unsigned LEB128 values.
fn bench_reading_leb128_unsigned_small(b: &mut Bencher) {
    let data = (0..255)
        .map(|n| {
            let mut buf = Vec::new();
            leb128::write::unsigned(&mut buf, n).unwrap();

            let mut slice = EndianSlice::new(buf.as_slice(), NativeEndian);
            assert_eq!(leb128::read::unsigned(&mut slice).unwrap(), n);

            (buf.into_boxed_slice(), n)
        })
        .collect::<Vec<_>>();

    let () = b.iter(|| {
        for (data, _) in &data {
            let mut slice = black_box(EndianSlice::new(data, NativeEndian));
            let v = leb128::read::unsigned(&mut slice).unwrap();
            black_box(v);
        }
    });
}

/// Benchmark reading of large unsigned LEB128 values.
fn bench_reading_leb128_unsigned_large(b: &mut Bencher) {
    #[rustfmt::skip]
    let data = [
        (&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01][..], u64::MAX),
        (&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x00][..], u64::MAX / 2),
        (&[0xd5, 0xaa, 0xd5, 0xaa, 0xd5, 0xaa, 0xd5, 0xaa, 0x55, 0x00][..], u64::MAX / 3),
        (&[0xb3, 0xe6, 0xcc, 0x99, 0xb3, 0xe6, 0xcc, 0x99, 0x33, 0x00][..], u64::MAX / 5),
        (&[0xaa, 0xd5, 0xaa, 0xd5, 0xaa, 0xd5, 0xaa, 0xd5, 0x2a, 0x00][..], u64::MAX / 6),
        (&[0x92, 0xc9, 0xa4, 0x92, 0xc9, 0xa4, 0x92, 0xc9, 0x24, 0x00][..], u64::MAX / 7),
        (&[0xf1, 0xb8, 0x9c, 0x8e, 0xc7, 0xe3, 0xf1, 0xb8, 0x1c, 0x00][..], u64::MAX / 9),
        (&[0x99, 0xb3, 0xe6, 0xcc, 0x99, 0xb3, 0xe6, 0xcc, 0x19, 0x00][..], u64::MAX / 10),
        (&[0xd1, 0x8b, 0xdd, 0xe8, 0xc5, 0xae, 0xf4, 0xa2, 0x17, 0x00][..], u64::MAX / 11),
        (&[0xd5, 0xaa, 0xd5, 0xaa, 0xd5, 0xaa, 0xd5, 0xaa, 0x15, 0x00][..], u64::MAX / 12),
        (&[0xb1, 0xa7, 0xec, 0x89, 0xbb, 0xe2, 0xce, 0xd8, 0x13, 0x00][..], u64::MAX / 13),
        (&[0xc9, 0xa4, 0x92, 0xc9, 0xa4, 0x92, 0xc9, 0xa4, 0x12, 0x00][..], u64::MAX / 14),
        (&[0x91, 0xa2, 0xc4, 0x88, 0x91, 0xa2, 0xc4, 0x88, 0x11, 0x00][..], u64::MAX / 15),
    ];

    for (data, expected) in data {
        let mut slice = black_box(EndianSlice::new(data, NativeEndian));
        let v = leb128::read::unsigned(&mut slice).unwrap();
        assert_eq!(v, expected);
    }

    let () = b.iter(|| {
        for (data, _) in data {
            let mut slice = black_box(EndianSlice::new(data, NativeEndian));
            let v = leb128::read::unsigned(&mut slice).unwrap();
            black_box(v);
        }
    });
}

/// Benchmark reading of small u16 LEB128 values.
fn bench_reading_leb128_u16_small(b: &mut Bencher) {
    let data = (0u16..255)
        .map(|n| {
            let mut buf = Vec::new();
            leb128::write::unsigned(&mut buf, u64::from(n)).unwrap();

            let mut slice = EndianSlice::new(buf.as_slice(), NativeEndian);
            assert_eq!(leb128::read::u16(&mut slice).unwrap(), n);

            (buf.into_boxed_slice(), n)
        })
        .collect::<Vec<_>>();

    let () = b.iter(|| {
        for (data, _) in &data {
            let mut slice = black_box(EndianSlice::new(data, NativeEndian));
            let v = leb128::read::u16(&mut slice).unwrap();
            black_box(v);
        }
    });
}

fn bench_read() {
    let mut c = Criterion::default().sample_size(50).configure_from_args();
    c.bench_function(
        "read::EntriesCursor<EndianSlice>",
        bench_entries_cursor::<1>,
    );
    c.bench_function(
        "read::EntriesCursor<EndianSlice> (attrs twice)",
        bench_entries_cursor::<2>,
    );
    c.bench_function(
        "read::EntriesCursor<EndianRcSlice>",
        bench_entries_cursor_rc::<1>,
    );
    c.bench_function(
        "read::EntriesCursor<EndianRcSlice> (attrs twice)",
        bench_entries_cursor_rc::<2>,
    );
    c.bench_function("read::EntriesTree", bench_entries_tree::<1>);
    c.bench_function("read::EntriesTree (attrs twice)", bench_entries_tree::<2>);
    c.bench_function("read::EntriesRaw::read_attribute", bench_entries_raw_call);
    c.bench_function(
        "read::EntriesRaw::read_attribute_inline",
        bench_entries_raw_inline,
    );
    c.bench_function("read::EntriesRaw::read_attributes", bench_entries_raw_bulk);

    let mut c = Criterion::default().configure_from_args();
    c.bench_function("parse .debug_abbrev", bench_parsing_debug_abbrev);
    c.bench_function("parse .debug_aranges", bench_parsing_debug_aranges);
    c.bench_function("parse .debug_pubnames", bench_parsing_debug_pubnames);
    c.bench_function("parse .debug_pubtypes", bench_parsing_debug_pubtypes);
    c.bench_function(
        "parse .debug_line opcodes",
        bench_parsing_line_number_program_opcodes,
    );
    c.bench_function(
        "parse .debug_line rows",
        bench_executing_line_number_programs,
    );
    c.bench_function("parse .debug_loc", bench_parsing_debug_loc);
    c.bench_function("parse .debug_ranges", bench_parsing_debug_ranges);
    c.bench_function(
        "parse .debug_info expressions",
        bench_parsing_debug_info_expressions,
    );
    c.bench_function(
        "evaluate .debug_info expressions",
        bench_evaluating_debug_info_expressions,
    );
    c.bench_function(
        "parse .debug_loc expressions",
        bench_parsing_debug_loc_expressions,
    );
    c.bench_function(
        "evaluate .debug_loc expressions",
        bench_evaluating_debug_loc_expressions,
    );
}

pub fn try_read_section(section: &str) -> Option<Vec<u8>> {
    let mut path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into()));
    path.push("./fixtures/self/");
    path.push(section);

    let mut file = File::open(&path).ok()?;
    assert!(path.is_file());

    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();
    Some(buf)
}

pub fn read_section(section: &str) -> Vec<u8> {
    try_read_section(section).unwrap()
}

fn bench_parsing_debug_abbrev(b: &mut Bencher) {
    let debug_info = read_section("debug_info");
    let debug_info = DebugInfo::new(&debug_info, LittleEndian);
    let unit = debug_info
        .units()
        .next()
        .expect("Should have at least one compilation unit")
        .expect("And it should parse OK");

    let debug_abbrev = read_section("debug_abbrev");

    b.iter(|| {
        let debug_abbrev = DebugAbbrev::new(&debug_abbrev, LittleEndian);
        black_box(
            unit.abbreviations(&debug_abbrev)
                .expect("Should parse abbreviations"),
        );
    });
}

#[inline]
fn impl_bench_parsing_debug_info<const COUNT: usize, R: Reader>(
    debug_info: DebugInfo<R>,
    debug_abbrev: DebugAbbrev<R>,
) {
    let mut iter = debug_info.units();
    while let Some(unit) = iter.next().expect("Should parse compilation unit") {
        let abbrevs = unit
            .abbreviations(&debug_abbrev)
            .expect("Should parse abbreviations");

        let mut cursor = unit.entries(&abbrevs);
        while let Some(entry) = cursor.next_dfs().expect("Should parse next dfs") {
            for _ in 0..COUNT {
                for attr in entry.attrs() {
                    let name = attr.name();
                    black_box(name);
                    let value = attr.raw_value();
                    black_box(value);
                }
            }
        }
    }
}

fn bench_entries_cursor<const COUNT: usize>(b: &mut Bencher) {
    let debug_info = read_section("debug_info");
    let debug_info = DebugInfo::new(&debug_info, LittleEndian);

    let debug_abbrev = read_section("debug_abbrev");
    let debug_abbrev = DebugAbbrev::new(&debug_abbrev, LittleEndian);

    b.iter(|| impl_bench_parsing_debug_info::<COUNT, _>(debug_info, debug_abbrev));
}

fn bench_entries_cursor_rc<const COUNT: usize>(b: &mut Bencher) {
    let debug_info = read_section("debug_info");
    let debug_info = Rc::from(&debug_info[..]);
    let debug_info = gimli::EndianRcSlice::new(debug_info, LittleEndian);
    let debug_info = DebugInfo::from(debug_info);

    let debug_abbrev = read_section("debug_abbrev");
    let debug_abbrev = Rc::from(&debug_abbrev[..]);
    let debug_abbrev = gimli::EndianRcSlice::new(debug_abbrev, LittleEndian);
    let debug_abbrev = DebugAbbrev::from(debug_abbrev);

    b.iter(|| impl_bench_parsing_debug_info::<COUNT, _>(debug_info.clone(), debug_abbrev.clone()));
}

fn bench_entries_tree<const COUNT: usize>(b: &mut Bencher) {
    let debug_abbrev = read_section("debug_abbrev");
    let debug_abbrev = DebugAbbrev::new(&debug_abbrev, LittleEndian);

    let debug_info = read_section("debug_info");

    b.iter(|| {
        let debug_info = DebugInfo::new(&debug_info, LittleEndian);

        let mut iter = debug_info.units();
        while let Some(unit) = iter.next().expect("Should parse compilation unit") {
            let abbrevs = unit
                .abbreviations(&debug_abbrev)
                .expect("Should parse abbreviations");

            let mut tree = unit
                .entries_tree(&abbrevs, None)
                .expect("Should have entries tree");
            let root = tree.root().expect("Should parse root entry");
            parse_debug_info_tree::<COUNT, _>(root);
        }
    });
}

fn parse_debug_info_tree<const COUNT: usize, R: Reader>(node: EntriesTreeNode<R>) {
    for _ in 0..COUNT {
        for attr in node.entry().attrs() {
            let name = attr.name();
            black_box(name);
            let value = attr.raw_value();
            black_box(value);
        }
    }
    let mut children = node.children();
    while let Some(child) = children.next().expect("Should parse child entry") {
        parse_debug_info_tree::<COUNT, R>(child);
    }
}

fn bench_entries_raw_call(b: &mut Bencher) {
    let debug_abbrev = read_section("debug_abbrev");
    let debug_abbrev = DebugAbbrev::new(&debug_abbrev, LittleEndian);

    let debug_info = read_section("debug_info");

    b.iter(|| {
        let debug_info = DebugInfo::new(&debug_info, LittleEndian);

        let mut iter = debug_info.units();
        while let Some(unit) = iter.next().expect("Should parse compilation unit") {
            let abbrevs = unit
                .abbreviations(&debug_abbrev)
                .expect("Should parse abbreviations");

            let mut raw = unit
                .entries_raw(&abbrevs, None)
                .expect("Should have entries");
            while !raw.is_empty() {
                if let Some(abbrev) = raw
                    .read_abbreviation()
                    .expect("Should parse abbreviation code")
                {
                    for spec in abbrev.attributes().iter().cloned() {
                        let attr = read_attribute(&mut raw, spec).expect("Should parse attribute");
                        let name = attr.name();
                        black_box(name);
                        let value = attr.raw_value();
                        black_box(value);
                    }
                }
            }
        }
    });
}

#[inline(never)]
fn read_attribute<R: Reader>(
    input: &mut EntriesRaw<R>,
    spec: AttributeSpecification,
) -> gimli::Result<Attribute<R>> {
    input.read_attribute_inline(spec)
}

fn bench_entries_raw_inline(b: &mut Bencher) {
    let debug_abbrev = read_section("debug_abbrev");
    let debug_abbrev = DebugAbbrev::new(&debug_abbrev, LittleEndian);

    let debug_info = read_section("debug_info");

    b.iter(|| {
        let debug_info = DebugInfo::new(&debug_info, LittleEndian);

        let mut iter = debug_info.units();
        while let Some(unit) = iter.next().expect("Should parse compilation unit") {
            let abbrevs = unit
                .abbreviations(&debug_abbrev)
                .expect("Should parse abbreviations");

            let mut raw = unit
                .entries_raw(&abbrevs, None)
                .expect("Should have entries");
            while !raw.is_empty() {
                if let Some(abbrev) = raw
                    .read_abbreviation()
                    .expect("Should parse abbreviation code")
                {
                    for spec in abbrev.attributes().iter().cloned() {
                        let attr = raw
                            .read_attribute_inline(spec)
                            .expect("Should parse attribute");
                        let name = attr.name();
                        black_box(name);
                        let value = attr.raw_value();
                        black_box(value);
                    }
                }
            }
        }
    });
}

fn bench_entries_raw_bulk(b: &mut Bencher) {
    let debug_abbrev = read_section("debug_abbrev");
    let debug_abbrev = DebugAbbrev::new(&debug_abbrev, LittleEndian);

    let debug_info = read_section("debug_info");

    b.iter(|| {
        let debug_info = DebugInfo::new(&debug_info, LittleEndian);

        let mut attrs = Vec::new();
        let mut iter = debug_info.units();
        while let Some(unit) = iter.next().expect("Should parse compilation unit") {
            let abbrevs = unit
                .abbreviations(&debug_abbrev)
                .expect("Should parse abbreviations");

            let mut raw = unit
                .entries_raw(&abbrevs, None)
                .expect("Should have entries");
            while !raw.is_empty() {
                if let Some(abbrev) = raw
                    .read_abbreviation()
                    .expect("Should parse abbreviation code")
                {
                    raw.read_attributes(abbrev.attributes(), &mut attrs)
                        .expect("Should parse attributes");
                    for attr in &attrs {
                        let name = attr.name();
                        black_box(name);
                        let value = attr.raw_value();
                        black_box(value);
                    }
                }
            }
        }
    });
}

fn bench_parsing_debug_aranges(b: &mut Bencher) {
    let debug_aranges = read_section("debug_aranges");
    let debug_aranges = DebugAranges::new(&debug_aranges, LittleEndian);

    b.iter(|| {
        let mut headers = debug_aranges.headers();
        while let Some(header) = headers.next().expect("Should parse arange header OK") {
            let mut entries = header.entries();
            while let Some(arange) = entries.next().expect("Should parse arange entry OK") {
                black_box(arange);
            }
        }
    });
}

fn bench_parsing_debug_pubnames(b: &mut Bencher) {
    let debug_pubnames = read_section("debug_pubnames");
    let debug_pubnames = DebugPubNames::new(&debug_pubnames, LittleEndian);

    b.iter(|| {
        let mut pubnames = debug_pubnames.items();
        while let Some(pubname) = pubnames.next().expect("Should parse pubname OK") {
            black_box(pubname);
        }
    });
}

fn bench_parsing_debug_pubtypes(b: &mut Bencher) {
    let debug_pubtypes = read_section("debug_pubtypes");
    let debug_pubtypes = DebugPubTypes::new(&debug_pubtypes, LittleEndian);

    b.iter(|| {
        let mut pubtypes = debug_pubtypes.items();
        while let Some(pubtype) = pubtypes.next().expect("Should parse pubtype OK") {
            black_box(pubtype);
        }
    });
}

// We happen to know that there is a line number program and header at
// offset 0 and that address size is 8 bytes. No need to parse DIEs to grab
// this info off of the compilation units.
const OFFSET: DebugLineOffset = DebugLineOffset(0);
const ADDRESS_SIZE: u8 = 8;

fn bench_parsing_line_number_program_opcodes(b: &mut Bencher) {
    let debug_line = read_section("debug_line");
    let debug_line = DebugLine::new(&debug_line, LittleEndian);

    b.iter(|| {
        let program = debug_line
            .program(OFFSET, ADDRESS_SIZE, None, None)
            .expect("Should parse line number program header");
        let header = program.header();

        let mut instructions = header.instructions();
        while let Some(instruction) = instructions
            .next_instruction(header)
            .expect("Should parse instruction")
        {
            black_box(instruction);
        }
    });
}

fn bench_executing_line_number_programs(b: &mut Bencher) {
    let debug_line = read_section("debug_line");
    let debug_line = DebugLine::new(&debug_line, LittleEndian);

    b.iter(|| {
        let program = debug_line
            .program(OFFSET, ADDRESS_SIZE, None, None)
            .expect("Should parse line number program header");

        let mut rows = program.rows();
        while let Some(row) = rows
            .next_row()
            .expect("Should parse and execute all rows in the line number program")
        {
            black_box(row);
        }
    });
}

fn bench_parsing_debug_loc(b: &mut Bencher) {
    let debug_info = read_section("debug_info");
    let debug_info = DebugInfo::new(&debug_info, LittleEndian);

    let debug_abbrev = read_section("debug_abbrev");
    let debug_abbrev = DebugAbbrev::new(&debug_abbrev, LittleEndian);

    let debug_addr = DebugAddr::from(EndianSlice::new(&[], LittleEndian));
    let debug_addr_base = DebugAddrBase(0);

    let debug_loc = read_section("debug_loc");
    let debug_loc = DebugLoc::new(&debug_loc, LittleEndian);
    let debug_loclists = DebugLocLists::new(&[], LittleEndian);
    let loclists = LocationLists::new(debug_loc, debug_loclists);

    let mut offsets = Vec::new();

    let mut iter = debug_info.units();
    while let Some(unit) = iter.next().expect("Should parse compilation unit") {
        let abbrevs = unit
            .abbreviations(&debug_abbrev)
            .expect("Should parse abbreviations");

        let mut cursor = unit.entries(&abbrevs);
        cursor.next_dfs().expect("Should parse next dfs");

        let mut low_pc = 0;

        {
            let unit_entry = cursor.current().expect("Should have a root entry");
            let low_pc_attr = unit_entry.attr_value(gimli::DW_AT_low_pc);
            if let Some(gimli::AttributeValue::Addr(address)) = low_pc_attr {
                low_pc = address;
            }
        }

        while cursor.next_dfs().expect("Should parse next dfs").is_some() {
            let entry = cursor.current().expect("Should have a current entry");
            for attr in entry.attrs() {
                if let gimli::AttributeValue::LocationListsRef(offset) = attr.value() {
                    offsets.push((offset, unit.encoding(), low_pc));
                }
            }
        }
    }

    b.iter(|| {
        for &(offset, encoding, base_address) in &*offsets {
            let mut locs = loclists
                .locations(offset, encoding, base_address, &debug_addr, debug_addr_base)
                .expect("Should parse locations OK");
            while let Some(loc) = locs.next().expect("Should parse next location") {
                black_box(loc);
            }
        }
    });
}

fn bench_parsing_debug_ranges(b: &mut Bencher) {
    let debug_info = read_section("debug_info");
    let debug_info = DebugInfo::new(&debug_info, LittleEndian);

    let debug_abbrev = read_section("debug_abbrev");
    let debug_abbrev = DebugAbbrev::new(&debug_abbrev, LittleEndian);

    let debug_addr = DebugAddr::from(EndianSlice::new(&[], LittleEndian));
    let debug_addr_base = DebugAddrBase(0);

    let debug_ranges = read_section("debug_ranges");
    let debug_ranges = DebugRanges::new(&debug_ranges, LittleEndian);
    let debug_rnglists = DebugRngLists::new(&[], LittleEndian);
    let rnglists = RangeLists::new(debug_ranges, debug_rnglists);

    let mut offsets = Vec::new();

    let mut iter = debug_info.units();
    while let Some(unit) = iter.next().expect("Should parse compilation unit") {
        let abbrevs = unit
            .abbreviations(&debug_abbrev)
            .expect("Should parse abbreviations");

        let mut cursor = unit.entries(&abbrevs);
        cursor.next_dfs().expect("Should parse next dfs");

        let mut low_pc = 0;

        {
            let unit_entry = cursor.current().expect("Should have a root entry");
            let low_pc_attr = unit_entry.attr_value(gimli::DW_AT_low_pc);
            if let Some(gimli::AttributeValue::Addr(address)) = low_pc_attr {
                low_pc = address;
            }
        }

        while cursor.next_dfs().expect("Should parse next dfs").is_some() {
            let entry = cursor.current().expect("Should have a current entry");
            for attr in entry.attrs() {
                if let gimli::AttributeValue::RangeListsRef(offset) = attr.value() {
                    offsets.push((RangeListsOffset(offset.0), unit.encoding(), low_pc));
                }
            }
        }
    }

    b.iter(|| {
        for &(offset, encoding, base_address) in &*offsets {
            let mut ranges = rnglists
                .ranges(offset, encoding, base_address, &debug_addr, debug_addr_base)
                .expect("Should parse ranges OK");
            while let Some(range) = ranges.next().expect("Should parse next range") {
                black_box(range);
            }
        }
    });
}

fn debug_info_expressions<R: Reader>(
    debug_info: &DebugInfo<R>,
    debug_abbrev: &DebugAbbrev<R>,
) -> Vec<(Expression<R>, Encoding)> {
    let mut expressions = Vec::new();

    let mut iter = debug_info.units();
    while let Some(unit) = iter.next().expect("Should parse compilation unit") {
        let abbrevs = unit
            .abbreviations(debug_abbrev)
            .expect("Should parse abbreviations");

        let mut cursor = unit.entries(&abbrevs);
        while let Some(entry) = cursor.next_dfs().expect("Should parse next dfs") {
            for attr in entry.attrs() {
                if let AttributeValue::Exprloc(expression) = attr.value() {
                    expressions.push((expression, unit.encoding()));
                }
            }
        }
    }

    expressions
}

fn bench_parsing_debug_info_expressions(b: &mut Bencher) {
    let debug_abbrev = read_section("debug_abbrev");
    let debug_abbrev = DebugAbbrev::new(&debug_abbrev, LittleEndian);

    let debug_info = read_section("debug_info");
    let debug_info = DebugInfo::new(&debug_info, LittleEndian);

    let expressions = debug_info_expressions(&debug_info, &debug_abbrev);

    b.iter(|| {
        for &(expression, encoding) in &*expressions {
            let mut pc = expression.0;
            while !pc.is_empty() {
                Operation::parse(&mut pc, encoding).expect("Should parse operation");
            }
        }
    });
}

fn bench_evaluating_debug_info_expressions(b: &mut Bencher) {
    let debug_abbrev = read_section("debug_abbrev");
    let debug_abbrev = DebugAbbrev::new(&debug_abbrev, LittleEndian);

    let debug_info = read_section("debug_info");
    let debug_info = DebugInfo::new(&debug_info, LittleEndian);

    let expressions = debug_info_expressions(&debug_info, &debug_abbrev);

    b.iter(|| {
        for &(expression, encoding) in &*expressions {
            let mut eval = expression.evaluation(encoding);
            eval.set_initial_value(0);
            let result = eval.evaluate().expect("Should evaluate expression");
            black_box(result);
        }
    });
}

fn debug_loc_expressions<R: Reader>(
    debug_info: &DebugInfo<R>,
    debug_abbrev: &DebugAbbrev<R>,
    debug_addr: &DebugAddr<R>,
    loclists: &LocationLists<R>,
) -> Vec<(Expression<R>, Encoding)> {
    let debug_addr_base = DebugAddrBase(R::Offset::from_u8(0));

    let mut expressions = Vec::new();

    let mut iter = debug_info.units();
    while let Some(unit) = iter.next().expect("Should parse compilation unit") {
        let abbrevs = unit
            .abbreviations(debug_abbrev)
            .expect("Should parse abbreviations");

        let mut cursor = unit.entries(&abbrevs);
        cursor.next_dfs().expect("Should parse next dfs");

        let mut low_pc = 0;

        {
            let unit_entry = cursor.current().expect("Should have a root entry");
            let low_pc_attr = unit_entry.attr_value(gimli::DW_AT_low_pc);
            if let Some(gimli::AttributeValue::Addr(address)) = low_pc_attr {
                low_pc = address;
            }
        }

        while cursor.next_dfs().expect("Should parse next dfs").is_some() {
            let entry = cursor.current().expect("Should have a current entry");
            for attr in entry.attrs() {
                if let gimli::AttributeValue::LocationListsRef(offset) = attr.value() {
                    let mut locs = loclists
                        .locations(offset, unit.encoding(), low_pc, debug_addr, debug_addr_base)
                        .expect("Should parse locations OK");
                    while let Some(loc) = locs.next().expect("Should parse next location") {
                        expressions.push((loc.data, unit.encoding()));
                    }
                }
            }
        }
    }

    expressions
}

fn bench_parsing_debug_loc_expressions(b: &mut Bencher) {
    let debug_info = read_section("debug_info");
    let debug_info = DebugInfo::new(&debug_info, LittleEndian);

    let debug_abbrev = read_section("debug_abbrev");
    let debug_abbrev = DebugAbbrev::new(&debug_abbrev, LittleEndian);

    let debug_addr = DebugAddr::from(EndianSlice::new(&[], LittleEndian));

    let debug_loc = read_section("debug_loc");
    let debug_loc = DebugLoc::new(&debug_loc, LittleEndian);
    let debug_loclists = DebugLocLists::new(&[], LittleEndian);
    let loclists = LocationLists::new(debug_loc, debug_loclists);

    let expressions = debug_loc_expressions(&debug_info, &debug_abbrev, &debug_addr, &loclists);

    b.iter(|| {
        for &(expression, encoding) in &*expressions {
            let mut pc = expression.0;
            while !pc.is_empty() {
                Operation::parse(&mut pc, encoding).expect("Should parse operation");
            }
        }
    });
}

fn bench_evaluating_debug_loc_expressions(b: &mut Bencher) {
    let debug_info = read_section("debug_info");
    let debug_info = DebugInfo::new(&debug_info, LittleEndian);

    let debug_abbrev = read_section("debug_abbrev");
    let debug_abbrev = DebugAbbrev::new(&debug_abbrev, LittleEndian);

    let debug_addr = DebugAddr::from(EndianSlice::new(&[], LittleEndian));

    let debug_loc = read_section("debug_loc");
    let debug_loc = DebugLoc::new(&debug_loc, LittleEndian);
    let debug_loclists = DebugLocLists::new(&[], LittleEndian);
    let loclists = LocationLists::new(debug_loc, debug_loclists);

    let expressions = debug_loc_expressions(&debug_info, &debug_abbrev, &debug_addr, &loclists);

    b.iter(|| {
        for &(expression, encoding) in &*expressions {
            let mut eval = expression.evaluation(encoding);
            eval.set_initial_value(0);
            let result = eval.evaluate().expect("Should evaluate expression");
            black_box(result);
        }
    });
}

mod cfi {
    use super::*;

    use gimli::{
        BaseAddresses, CieOrFde, EhFrame, FrameDescriptionEntry, LittleEndian, UnwindContext,
        UnwindSection,
    };

    pub(super) fn bench_cfi() {
        let mut c = Criterion::default().configure_from_args();
        c.bench_function(
            "parse .eh_frame CIEs",
            iterate_entries_and_do_not_parse_any_fde,
        );
        c.bench_function("parse .eh_frame FDEs", iterate_entries_and_parse_every_fde);
        c.bench_function(
            "parse .eh_frame FDE instructions",
            iterate_entries_and_parse_every_fde_and_instructions,
        );
        c.bench_function(
            "parse .eh_frame FDE rows",
            iterate_entries_evaluate_every_fde,
        );
        c.bench_function(
            "parse .eh_frame longest FDE instructions",
            parse_longest_fde_instructions,
        );
        c.bench_function(
            "parse .eh_frame longest FDE rows, new ctx",
            eval_longest_fde_instructions_new_ctx_everytime,
        );
        c.bench_function(
            "parse .eh_frame longest FDE rows, reuse ctx",
            eval_longest_fde_instructions_same_ctx,
        );
    }

    fn iterate_entries_and_do_not_parse_any_fde(b: &mut Bencher) {
        let eh_frame = read_section("eh_frame");
        let mut eh_frame = EhFrame::new(&eh_frame, LittleEndian);
        // The `.eh_frame` fixture data was created on a 64-bit machine.
        eh_frame.set_address_size(8);

        let bases = BaseAddresses::default()
            .set_eh_frame(0)
            .set_got(0)
            .set_text(0);

        b.iter(|| {
            let mut entries = eh_frame.entries(&bases);
            while let Some(entry) = entries.next().expect("Should parse CFI entry OK") {
                black_box(entry);
            }
        });
    }

    fn iterate_entries_and_parse_every_fde(b: &mut Bencher) {
        let eh_frame = read_section("eh_frame");
        let mut eh_frame = EhFrame::new(&eh_frame, LittleEndian);
        // The `.eh_frame` fixture data was created on a 64-bit machine.
        eh_frame.set_address_size(8);

        let bases = BaseAddresses::default()
            .set_eh_frame(0)
            .set_got(0)
            .set_text(0);

        b.iter(|| {
            let mut entries = eh_frame.entries(&bases);
            while let Some(entry) = entries.next().expect("Should parse CFI entry OK") {
                match entry {
                    CieOrFde::Cie(cie) => {
                        black_box(cie);
                    }
                    CieOrFde::Fde(partial) => {
                        let fde = partial
                            .parse(EhFrame::cie_from_offset)
                            .expect("Should be able to get CIE for FED");
                        black_box(fde);
                    }
                };
            }
        });
    }

    fn iterate_entries_and_parse_every_fde_and_instructions(b: &mut Bencher) {
        let eh_frame = read_section("eh_frame");
        let mut eh_frame = EhFrame::new(&eh_frame, LittleEndian);
        // The `.eh_frame` fixture data was created on a 64-bit machine.
        eh_frame.set_address_size(8);

        let bases = BaseAddresses::default()
            .set_eh_frame(0)
            .set_got(0)
            .set_text(0);

        b.iter(|| {
            let mut entries = eh_frame.entries(&bases);
            while let Some(entry) = entries.next().expect("Should parse CFI entry OK") {
                match entry {
                    CieOrFde::Cie(cie) => {
                        let mut instrs = cie.instructions(&eh_frame, &bases);
                        while let Some(i) =
                            instrs.next().expect("Can parse next CFI instruction OK")
                        {
                            black_box(i);
                        }
                    }
                    CieOrFde::Fde(partial) => {
                        let fde = partial
                            .parse(EhFrame::cie_from_offset)
                            .expect("Should be able to get CIE for FED");
                        let mut instrs = fde.instructions(&eh_frame, &bases);
                        while let Some(i) =
                            instrs.next().expect("Can parse next CFI instruction OK")
                        {
                            black_box(i);
                        }
                    }
                };
            }
        });
    }

    fn iterate_entries_evaluate_every_fde(b: &mut Bencher) {
        let eh_frame = read_section("eh_frame");
        let mut eh_frame = EhFrame::new(&eh_frame, LittleEndian);
        // The `.eh_frame` fixture data was created on a 64-bit machine.
        eh_frame.set_address_size(8);

        let bases = BaseAddresses::default()
            .set_eh_frame(0)
            .set_got(0)
            .set_text(0);

        let mut ctx = Box::new(UnwindContext::new());

        b.iter(|| {
            let mut entries = eh_frame.entries(&bases);
            while let Some(entry) = entries.next().expect("Should parse CFI entry OK") {
                match entry {
                    CieOrFde::Cie(_) => {}
                    CieOrFde::Fde(partial) => {
                        let fde = partial
                            .parse(EhFrame::cie_from_offset)
                            .expect("Should be able to get CIE for FED");
                        let mut table = fde
                            .rows(&eh_frame, &bases, &mut ctx)
                            .expect("Should be able to initialize ctx");
                        while let Some(row) =
                            table.next_row().expect("Should get next unwind table row")
                        {
                            black_box(row);
                        }
                    }
                };
            }
        });
    }

    fn instrs_len<R: Reader>(
        eh_frame: &EhFrame<R>,
        bases: &BaseAddresses,
        fde: &FrameDescriptionEntry<R>,
    ) -> usize {
        fde.instructions(eh_frame, bases)
            .try_fold(0, |count, i| i.map(|_| count + 1))
            .expect("fold over instructions OK")
    }

    fn get_fde_with_longest_cfi_instructions<R: Reader>(
        eh_frame: &EhFrame<R>,
        bases: &BaseAddresses,
    ) -> FrameDescriptionEntry<R> {
        let mut longest: Option<(usize, FrameDescriptionEntry<_>)> = None;

        let mut entries = eh_frame.entries(bases);
        while let Some(entry) = entries.next().expect("Should parse CFI entry OK") {
            match entry {
                CieOrFde::Cie(_) => {}
                CieOrFde::Fde(partial) => {
                    let fde = partial
                        .parse(EhFrame::cie_from_offset)
                        .expect("Should be able to get CIE for FED");

                    let this_len = instrs_len(eh_frame, bases, &fde);

                    let found_new_longest = match longest {
                        None => true,
                        Some((longest_len, ref _fde)) => this_len > longest_len,
                    };

                    if found_new_longest {
                        longest = Some((this_len, fde));
                    }
                }
            };
        }

        longest.expect("At least one FDE in .eh_frame").1
    }

    fn parse_longest_fde_instructions(b: &mut Bencher) {
        let eh_frame = read_section("eh_frame");
        let mut eh_frame = EhFrame::new(&eh_frame, LittleEndian);
        // The `.eh_frame` fixture data was created on a 64-bit machine.
        eh_frame.set_address_size(8);
        let bases = BaseAddresses::default()
            .set_eh_frame(0)
            .set_got(0)
            .set_text(0);
        let fde = get_fde_with_longest_cfi_instructions(&eh_frame, &bases);

        b.iter(|| {
            let mut instrs = fde.instructions(&eh_frame, &bases);
            while let Some(i) = instrs.next().expect("Should parse instruction OK") {
                black_box(i);
            }
        });
    }

    fn eval_longest_fde_instructions_new_ctx_everytime(b: &mut Bencher) {
        let eh_frame = read_section("eh_frame");
        let mut eh_frame = EhFrame::new(&eh_frame, LittleEndian);
        // The `.eh_frame` fixture data was created on a 64-bit machine.
        eh_frame.set_address_size(8);
        let bases = BaseAddresses::default()
            .set_eh_frame(0)
            .set_got(0)
            .set_text(0);
        let fde = get_fde_with_longest_cfi_instructions(&eh_frame, &bases);

        b.iter(|| {
            let mut ctx = Box::new(UnwindContext::new());
            let mut table = fde
                .rows(&eh_frame, &bases, &mut ctx)
                .expect("Should initialize the ctx OK");
            while let Some(row) = table.next_row().expect("Should get next unwind table row") {
                black_box(row);
            }
        });
    }

    fn eval_longest_fde_instructions_same_ctx(b: &mut Bencher) {
        let eh_frame = read_section("eh_frame");
        let mut eh_frame = EhFrame::new(&eh_frame, LittleEndian);
        // The `.eh_frame` fixture data was created on a 64-bit machine.
        eh_frame.set_address_size(8);
        let bases = BaseAddresses::default()
            .set_eh_frame(0)
            .set_got(0)
            .set_text(0);
        let fde = get_fde_with_longest_cfi_instructions(&eh_frame, &bases);

        let mut ctx = Box::new(UnwindContext::new());

        b.iter(|| {
            let mut table = fde
                .rows(&eh_frame, &bases, &mut ctx)
                .expect("Should initialize the ctx OK");
            while let Some(row) = table.next_row().expect("Should get next unwind table row") {
                black_box(row);
            }
        });
    }
}

mod write {
    use super::*;
    use gimli::{read, write};

    pub(super) fn bench_write() {
        let mut c = Criterion::default().configure_from_args();
        c.bench_function("convert simple", convert_simple);
        c.bench_function("convert incremental", convert_incremental);
    }

    fn convert_simple(b: &mut Bencher) {
        let read_sections = read::DwarfSections::load::<_, ()>(|id| {
            let mut name = id.name().chars();
            name.next();
            Ok(try_read_section(name.as_str()).unwrap_or_default())
        })
        .unwrap();
        let read_dwarf = read_sections.borrow(|s| EndianSlice::new(s, LittleEndian));

        b.iter(|| {
            let mut write_sections = write::Sections::new(write::EndianVec::new(LittleEndian));
            let mut write_dwarf = write::Dwarf::from(&read_dwarf, &|address| {
                Some(write::Address::Constant(address))
            })
            .unwrap();
            write_dwarf.write(&mut write_sections).unwrap();
            black_box(write_sections)
        });
    }

    fn convert_incremental(b: &mut Bencher) {
        let read_sections = read::DwarfSections::load::<_, ()>(|id| {
            let mut name = id.name().chars();
            name.next();
            Ok(try_read_section(name.as_str()).unwrap_or_default())
        })
        .unwrap();
        let read_dwarf = read_sections.borrow(|s| EndianSlice::new(s, LittleEndian));

        b.iter(|| {
            let mut write_sections = write::Sections::new(write::EndianVec::new(LittleEndian));
            let mut write_dwarf = write::Dwarf::new();
            let mut convert_dwarf = write_dwarf.convert(&read_dwarf).unwrap();
            while let Some((mut unit, root)) = convert_dwarf.read_unit().unwrap() {
                unit.convert(root, &|address| Some(write::Address::Constant(address)))
                    .unwrap();
                unit.write(&mut write_sections).unwrap();
            }
            write_dwarf.write(&mut write_sections).unwrap();
            black_box(write_sections)
        });
    }
}
