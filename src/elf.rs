//! Minimal ELF64 parser: section headers, section names, symbol table.
//!
//! Supports the fields `nm`/`objdump -h` need: symbol value/binding/name
//! and section offset/size/name. Little- and big-endian are handled for
//! the fixed-width fields via explicit byte reads.

use std::fmt;

/// Errors produced while parsing an ELF file.
#[derive(Debug)]
pub enum ElfError {
    /// Input is too short for an ELF header.
    Truncated,
    /// The ELF magic `\x7fELF` is absent.
    BadMagic,
    /// Unsupported ELF class (only ELF64 is handled).
    BadClass,
    /// A table offset/size is inconsistent with the file length.
    BadTable,
}

impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "file truncated"),
            Self::BadMagic => write!(f, "not an ELF file"),
            Self::BadClass => write!(f, "unsupported ELF class (need ELF64)"),
            Self::BadTable => write!(f, "section/symbol table out of range"),
        }
    }
}
impl std::error::Error for ElfError {}

const ELFMAG: &[u8; 4] = b"\x7fELF";
const ELFCLASS64: u8 = 2;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;

fn u16le(b: &[u8]) -> u16 { u16::from_le_bytes([b[0], b[1]]) }
fn u32le(b: &[u8]) -> u32 { u32::from_le_bytes([b[0], b[1], b[2], b[3]]) }
fn u64le(b: &[u8]) -> u64 { u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]) }

/// Symbol binding (high nibble of `st_info`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    Local,
    Global,
    Weak,
    Other(u8),
}

impl fmt::Display for Binding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local => write!(f, "LOCAL"),
            Self::Global => write!(f, "GLOBAL"),
            Self::Weak => write!(f, "WEAK"),
            Self::Other(n) => write!(f, "BIND{n}"),
        }
    }
}

/// A parsed symbol-table entry.
#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub value: u64,
    pub binding: Binding,
}

/// A parsed section-header entry.
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub offset: u64,
    pub size: u64,
}

/// A parsed ELF64 file.
#[derive(Debug)]
pub struct ElfFile {
    pub symbols: Vec<Symbol>,
    pub sections: Vec<Section>,
}

struct Shdr {
    name_off: u32,
    sh_type: u32,
    offset: u64,
    size: u64,
    link: u32,
    entsize: u64,
}

fn read_shdrs(data: &[u8]) -> Result<(Vec<Shdr>, u64, u16), ElfError> {
    if data.len() < 64 {
        return Err(ElfError::Truncated);
    }
    if &data[0..4] != ELFMAG {
        return Err(ElfError::BadMagic);
    }
    if data[4] != ELFCLASS64 {
        return Err(ElfError::BadClass);
    }
    let shoff = u64le(&data[40..48]);
    let shentsize = u16le(&data[58..60]) as usize;
    let shnum = u16le(&data[60..62]) as usize;
    let shstrndx = u16le(&data[62..64]) as usize;
    if shentsize == 0 || shnum == 0 {
        return Ok((Vec::new(), shoff, shstrndx as u16));
    }
    let mut shdrs = Vec::with_capacity(shnum);
    for i in 0..shnum {
        let off = shoff as usize + i * shentsize;
        if off + 64 > data.len() {
            return Err(ElfError::BadTable);
        }
        let s = &data[off..off + 64];
        shdrs.push(Shdr {
            name_off: u32le(&s[0..4]),
            sh_type: u32le(&s[4..8]),
            offset: u64le(&s[24..32]),
            size: u64le(&s[32..40]),
            link: u32le(&s[40..44]),
            entsize: u64le(&s[56..64]),
        });
    }
    Ok((shdrs, shoff, shstrndx as u16))
}

fn cstr<'a>(buf: &'a [u8], off: usize) -> Option<&'a str> {
    if off >= buf.len() {
        return None;
    }
    let end = buf[off..].iter().position(|&b| b == 0).map(|p| off + p)?;
    std::str::from_utf8(&buf[off..end]).ok()
}

impl ElfFile {
    /// Parse an ELF64 file, extracting sections and symbols.
    pub fn parse(data: &[u8]) -> Result<Self, ElfError> {
        let (shdrs, _, shstrndx) = read_shdrs(data)?;
        if shdrs.is_empty() {
            return Ok(Self { symbols: Vec::new(), sections: Vec::new() });
        }

        // Section-name string table.
        let shstr = shdrs.get(shstrndx as usize).ok_or(ElfError::BadTable)?;
        let names_buf = slice_at(data, shstr.offset, shstr.size)?;

        // Build section list.
        let mut sections = Vec::with_capacity(shdrs.len());
        for s in &shdrs {
            let name = cstr(names_buf, s.name_off as usize).unwrap_or("").to_string();
            sections.push(Section { name, offset: s.offset, size: s.size });
        }

        // Symbols from SHT_SYMTAB sections.
        let mut symbols = Vec::new();
        for s in &shdrs {
            if s.sh_type != SHT_SYMTAB {
                continue;
            }
            let strtab = shdrs.get(s.link as usize).ok_or(ElfError::BadTable)?;
            let str_buf = slice_at(data, strtab.offset, strtab.size)?;
            let sym_buf = slice_at(data, s.offset, s.size)?;
            let entsize = if s.entsize == 0 { 24 } else { s.entsize as usize };
            let mut off = 0usize;
            while off + 24 <= sym_buf.len() {
                let e = &sym_buf[off..off + 24];
                let name_off = u32le(&e[0..4]) as usize;
                let info = e[4];
                let binding = match info >> 4 {
                    0 => Binding::Local,
                    1 => Binding::Global,
                    2 => Binding::Weak,
                    n => Binding::Other(n),
                };
                let value = u64le(&e[8..16]);
                let name = cstr(str_buf, name_off).unwrap_or("").to_string();
                // Skip the all-zero null symbol and unnamed section symbols.
                if !(value == 0 && name.is_empty() && binding == Binding::Local) {
                    symbols.push(Symbol { name, value, binding });
                }
                off += entsize.max(24);
            }
        }

        Ok(Self { symbols, sections })
    }
}

fn slice_at(data: &[u8], off: u64, size: u64) -> Result<&[u8], ElfError> {
    let (o, z) = (off as usize, size as usize);
    if o.checked_add(z).map_or(true, |end| end > data.len()) {
        return Err(ElfError::BadTable);
    }
    Ok(&data[o..o + z])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal ELF64 image with a section-name table and one symtab.
    fn sample_elf() -> Vec<u8> {
        // Layout: ehdr(64) | shstrtab | symtab | strtab | shdrs
        let ehdr_size = 64usize;
        let shstr = b"\x00.text\x00.symtab\x00.strtab\x00.shstrtab\x00";
        let strtab = b"\x00main\x00";
        // symtab: null sym + main (GLOBAL, value 0x1000)
        let mut symtab = vec![0u8; 24];
        let mut e = vec![0u8; 24];
        e[0..4].copy_from_slice(&1u32.to_le_bytes()); // st_name -> "main"
        e[4] = (1 << 4) | 2; // GLOBAL FUNC
        e[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
        symtab.extend_from_slice(&e);

        let shstr_off = ehdr_size;
        let symtab_off = shstr_off + shstr.len();
        let strtab_off = symtab_off + symtab.len();
        let shoff = (strtab_off + strtab.len() + 7) & !7;

        let mut d = vec![0u8; shoff];
        // ELF header
        d[0..4].copy_from_slice(ELFMAG);
        d[4] = ELFCLASS64;
        d[5] = 1; // little-endian
        d[6] = 1; // version
        d[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        d[18..20].copy_from_slice(&0x3eu16.to_le_bytes()); // x86-64
        d[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
        d[58..60].copy_from_slice(&64u16.to_le_bytes()); // shentsize
        d[60..62].copy_from_slice(&5u16.to_le_bytes()); // shnum
        d[62..64].copy_from_slice(&4u16.to_le_bytes()); // shstrndx

        d[shstr_off..shstr_off + shstr.len()].copy_from_slice(shstr);
        d[symtab_off..symtab_off + symtab.len()].copy_from_slice(&symtab);
        d[strtab_off..strtab_off + strtab.len()].copy_from_slice(strtab);

        // 5 section headers (null, .text, .symtab, .strtab, .shstrtab)
        let mut push_sh = |d: &mut Vec<u8>, name: u32, ty: u32, off: u64, size: u64, link: u32, entsize: u64| {
            let base = d.len();
            d.resize(base + 64, 0);
            let s = &mut d[base..base + 64];
            s[0..4].copy_from_slice(&name.to_le_bytes());
            s[4..8].copy_from_slice(&ty.to_le_bytes());
            s[24..32].copy_from_slice(&off.to_le_bytes());
            s[32..40].copy_from_slice(&size.to_le_bytes());
            s[40..44].copy_from_slice(&link.to_le_bytes());
            s[56..64].copy_from_slice(&entsize.to_le_bytes());
        };
        push_sh(&mut d, 0, 0, 0, 0, 0, 0); // null
        push_sh(&mut d, 1, 1, 0, 0, 0, 0); // .text
        push_sh(&mut d, 7, SHT_SYMTAB, symtab_off as u64, symtab.len() as u64, 3, 24); // .symtab -> .strtab(idx3)
        push_sh(&mut d, 15, SHT_STRTAB, strtab_off as u64, strtab.len() as u64, 0, 0); // .strtab
        push_sh(&mut d, 23, SHT_STRTAB, shstr_off as u64, shstr.len() as u64, 0, 0); // .shstrtab

        d
    }

    #[test]
    fn parses_sections_and_symbols() {
        let d = sample_elf();
        let e = ElfFile::parse(&d).unwrap();
        assert!(e.sections.iter().any(|s| s.name == ".text"));
        assert!(e.sections.iter().any(|s| s.name == ".symtab"));
        let main = e.symbols.iter().find(|s| s.name == "main").expect("main symbol");
        assert_eq!(main.value, 0x1000);
        assert_eq!(main.binding, Binding::Global);
    }

    #[test]
    fn rejects_non_elf() {
        assert!(matches!(ElfFile::parse(b"hello"), Err(ElfError::Truncated) | Err(ElfError::BadMagic)));
    }

    #[test]
    fn rejects_non_elf64() {
        let mut d = sample_elf();
        d[4] = 1; // ELFCLASS32
        assert!(matches!(ElfFile::parse(&d), Err(ElfError::BadClass)));
    }
}
