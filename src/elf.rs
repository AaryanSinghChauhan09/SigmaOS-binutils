//! ELF64 object inspection — the `nm`/`objdump -h` primitives.

use crate::error::BinutilsError;

const ELFMAG: &[u8; 4] = b"\x7fELF";
const ET_REL: u16 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;

/// ELF section header (64-bit).
#[derive(Debug, Clone, Copy)]
struct Shdr {
    name: u32,
    sh_type: u32,
    offset: u64,
    size: u64,
    link: u32,
    entsize: u64,
}

/// One ELF section.
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub sh_type: u32,
    pub offset: u64,
    pub size: u64,
}

/// Symbol binding/type classification (`nm` output letters).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    Function,
    Object,
    Section,
    File,
    Other,
}

/// One ELF symbol.
#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub kind: SymbolKind,
    pub binding: char, // 'T','t','D','d','B','b','U' style
}

/// Parsed ELF64 relocatable/executable image (headers + tables only).
#[derive(Debug)]
pub struct ElfFile {
    pub is_64: bool,
    pub is_lsb: bool,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
}

impl ElfFile {
    /// Parse an ELF64 file (little- or big-endian).
    pub fn parse(data: &[u8]) -> Result<Self, BinutilsError> {
        if data.len() < 64 || &data[..4] != ELFMAG {
            return Err(BinutilsError::BadFormat("not an ELF file"));
        }
        let class = data[4];
        let endian = data[5];
        if class != 2 {
            return Err(BinutilsError::BadFormat("ELF32 not supported"));
        }
        let le = match endian {
            1 => true,
            2 => false,
            _ => return Err(BinutilsError::Malformed("bad ELF data encoding")),
        };
        let rd16 = |o: usize| -> u16 {
            let b = [data[o], data[o + 1]];
            if le { u16::from_le_bytes(b) } else { u16::from_be_bytes(b) }
        };
        let rd32 = |o: usize| -> u32 {
            let b = data[o..o + 4].try_into().unwrap();
            if le { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) }
        };
        let rd64 = |o: usize| -> u64 {
            let b = data[o..o + 8].try_into().unwrap();
            if le { u64::from_le_bytes(b) } else { u64::from_be_bytes(b) }
        };
        let _etype = rd16(16);
        let shoff = rd64(40) as usize;
        let shentsize = rd16(58) as usize;
        let shnum = rd16(60) as usize;
        let shstrndx = rd16(62) as usize;

        if shentsize < 64 || shoff + shnum * shentsize > data.len() {
            return Err(BinutilsError::Malformed("bad section table"));
        }
        let mut shdrs = Vec::with_capacity(shnum);
        for i in 0..shnum {
            let b = shoff + i * shentsize;
            shdrs.push(Shdr {
                name: rd32(b),
                sh_type: rd32(b + 4),
                offset: rd64(b + 24),
                size: rd64(b + 32),
                link: rd32(b + 40),
                entsize: rd64(b + 56),
            });
        }
        // Section names via shstrtab.
        let names = if shstrndx < shnum {
            let s = &shdrs[shstrndx];
            strtab(data, s.offset as usize, s.size as usize)?
        } else {
            Vec::new()
        };
        let section_name = |n: u32| -> String {
            let end = names[n as usize..]
                .iter()
                .position(|&c| c == 0)
                .map(|i| n as usize + i)
                .unwrap_or(names.len());
            String::from_utf8_lossy(&names[n as usize..end]).into_owned()
        };
        let sections: Vec<Section> = shdrs
            .iter()
            .map(|s| Section {
                name: section_name(s.name),
                sh_type: s.sh_type,
                offset: s.offset,
                size: s.size,
            })
            .collect();

        // Symbols via SHT_SYMTAB.
        let mut symbols = Vec::new();
        for s in &shdrs {
            if s.sh_type != SHT_SYMTAB || s.entsize == 0 {
                continue;
            }
            let strsec = &shdrs[s.link as usize];
            let strs = strtab(data, strsec.offset as usize, strsec.size as usize)?;
            let count = s.size / s.entsize;
            for i in 0..count {
                let b = s.offset as usize + i as usize * s.entsize as usize;
                if b + 24 > data.len() {
                    return Err(BinutilsError::Malformed("symbol overruns file"));
                }
                let name_off = rd32(b) as usize;
                let info = data[b + 4];
                let other = data[b + 5];
                let shndx = rd16(b + 6);
                let value = rd64(b + 8);
                let size = rd64(b + 16);
                let name = cstr(&strs, name_off);
                if name.is_empty() && shndx == 0 {
                    continue;
                }
                let bind = info >> 4;
                let typ = info & 0xf;
                let binding = match bind {
                    0 => 'U', // LOCAL→'t'/'d' handled below; keep simple
                    1 => 'U',
                    2 => 'W',
                    _ => 'U',
                };
                let kind = match typ {
                    2 => SymbolKind::Function,
                    1 => SymbolKind::Object,
                    3 => SymbolKind::Section,
                    4 => SymbolKind::File,
                    _ => SymbolKind::Other,
                };
                // nm-style letter: global text/data/bss.
                let letter = match (bind, typ, shndx) {
                    (1, _, 0) => 'U',
                    (1, 2, _) => 'T',
                    (1, 1, _) => 'D',
                    (0, 2, _) => 't',
                    (0, 1, _) => 'd',
                    (_, _, 0) => 'U',
                    _ => binding,
                };
                let _ = other;
                symbols.push(Symbol { name, value, size, kind, binding: letter });
            }
        }
        Ok(Self { is_64: true, is_lsb: le, sections, symbols })
    }
}

fn strtab(data: &[u8], off: usize, size: usize) -> Result<Vec<u8>, BinutilsError> {
    if off + size > data.len() {
        return Err(BinutilsError::Malformed("string table overruns file"));
    }
    Ok(data[off..off + size].to_vec())
}

fn cstr(tab: &[u8], off: usize) -> String {
    if off >= tab.len() {
        return String::new();
    }
    let end = tab[off..]
        .iter()
        .position(|&c| c == 0)
        .map(|i| off + i)
        .unwrap_or(tab.len());
    String::from_utf8_lossy(&tab[off..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_elf() {
        assert!(ElfFile::parse(b"hello").is_err());
        assert!(ElfFile::parse(&[0x7f, b'E', b'L', b'F', 1, 1, 1, 0]).is_err()); // ELF32
    }

    #[test]
    fn parses_minimal_elf64() {
        // Hand-built ELF64 LE header + shstrtab + empty section table.
        let mut d = vec![0u8; 64];
        d[0..4].copy_from_slice(b"\x7fELF");
        d[4] = 2; d[5] = 1; d[6] = 1;
        // e_shoff=64, shentsize=64, shnum=3, shstrndx=2 — wait need room; place table at 64.
        // Simpler: shoff points past ident+header = 64; 3 sections × 64 bytes.
        d[40..48].copy_from_slice(&64u64.to_le_bytes());
        d[58..60].copy_from_slice(&64u16.to_le_bytes());
        d[60..62].copy_from_slice(&3u16.to_le_bytes());
        d[62..64].copy_from_slice(&2u16.to_le_bytes());
        // Extend file: shstrtab content at 64+3*64=256
        d.resize(320, 0);
        let stroff = 256usize;
        d[stroff..stroff + 25].copy_from_slice(b"\0.text\0.shstrtab\0.symtab\0");
        // shdr[0] null; shdr[1] .text (name=1,type=1); shdr[2] .shstrtab (name=7,type=3,off=256,size=22,link=0)
        let w = |b: &mut [u8], o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
        let w64 = |b: &mut [u8], o: usize, v: u64| b[o..o + 8].copy_from_slice(&v.to_le_bytes());
        let s1 = 128; // shdr1
        w(&mut d, s1, 1); w(&mut d, s1 + 4, 1); // name,type
        w64(&mut d, s1 + 24, 0); w64(&mut d, s1 + 32, 0);
        let s2 = 192; // shdr2
        w(&mut d, s2, 7); w(&mut d, s2 + 4, 3);
        w64(&mut d, s2 + 24, stroff as u64); w64(&mut d, s2 + 32, 22);
        w(&mut d, s2 + 40, 0);
        let e = ElfFile::parse(&d).unwrap();
        assert_eq!(e.sections.len(), 3);
        assert_eq!(e.sections[1].name, ".text");
        assert_eq!(e.sections[2].name, ".shstrtab");
    }
}
