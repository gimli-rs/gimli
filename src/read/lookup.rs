use crate::common::{DebugInfoOffset, Format};
use crate::read::{Error, Reader, ReaderOffset, Result, UnitOffset};

// Common parsing for the `.debug_pub*` sections (DWARF v4 Section 6.1.1, Lookup by Name).
//
// These sections consist of sets of data. Each set has a header with metadata followed by
// a series of entries.

#[derive(Clone, Debug)]
pub(crate) struct DebugPubSet<R: Reader> {
    pub(crate) section: R,
}

impl<R: Reader> DebugPubSet<R> {
    pub(crate) fn items(&self) -> PubSetEntryIter<R> {
        PubSetEntryIter {
            current_set: None,
            remaining_input: self.section.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PubSetEntryIter<R: Reader> {
    current_set: Option<(R, PubSetHeader<R::Offset>)>, // Only none at the very beginning and end.
    remaining_input: R,
}

impl<R: Reader> PubSetEntryIter<R> {
    /// Advance the iterator and return the next entry.
    ///
    /// Returns the newly parsed entry as `Ok(Some(PubSetEntry))`. Returns
    /// `Ok(None)` when iteration is complete and all entries have already been
    /// parsed and yielded. If an error occurs while parsing the next entry,
    /// then this error is returned as `Err(e)`, and all subsequent calls return
    /// `Ok(None)`.
    pub(crate) fn next(&mut self) -> Result<Option<PubSetEntry<R>>> {
        loop {
            if let Some((ref mut input, ref header)) = self.current_set
                && !input.is_empty()
            {
                match PubSetEntry::parse(input, header) {
                    Ok(Some(entry)) => return Ok(Some(entry)),
                    Ok(None) => {}
                    Err(e) => {
                        input.empty();
                        self.remaining_input.empty();
                        return Err(e);
                    }
                }
            }
            if self.remaining_input.is_empty() {
                self.current_set = None;
                return Ok(None);
            }
            match PubSetHeader::parse(&mut self.remaining_input) {
                Ok(set) => {
                    self.current_set = Some(set);
                }
                Err(e) => {
                    self.current_set = None;
                    self.remaining_input.empty();
                    return Err(e);
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PubSetHeader<T = usize> {
    format: Format,
    length: T,
    version: u16,
    unit_offset: DebugInfoOffset<T>,
    unit_length: T,
}

impl<T: ReaderOffset> PubSetHeader<T> {
    /// Parse a set header. Returns a tuple of the entry data to be parsed for
    /// this set, and the newly created `PubSetHeader` struct.
    fn parse<R: Reader<Offset = T>>(input: &mut R) -> Result<(R, PubSetHeader<R::Offset>)> {
        let (length, format) = input.read_initial_length()?;
        let mut rest = input.split(length)?;

        let version = rest.read_u16()?;
        if version != 2 {
            return Err(Error::UnknownVersion(u64::from(version)));
        }

        let unit_offset = rest.read_offset(format).map(DebugInfoOffset)?;
        let unit_length = rest.read_length(format)?;

        let header = PubSetHeader {
            format,
            length,
            version,
            unit_offset,
            unit_length,
        };
        Ok((rest, header))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PubSetEntry<R: Reader> {
    pub(crate) unit_header_offset: DebugInfoOffset<R::Offset>,
    pub(crate) die_offset: UnitOffset<R::Offset>,
    pub(crate) name: R,
}

impl<R: Reader> PubSetEntry<R> {
    /// Parse a single set entry. Return `None` for the null entry.
    fn parse(input: &mut R, header: &PubSetHeader<R::Offset>) -> Result<Option<PubSetEntry<R>>> {
        let offset = input.read_offset(header.format)?;
        if offset.into_u64() == 0 {
            input.empty();
            Ok(None)
        } else {
            let name = input.read_null_terminated_slice()?;
            Ok(Some(PubSetEntry {
                die_offset: UnitOffset(offset),
                name,
                unit_header_offset: header.unit_offset,
            }))
        }
    }
}
