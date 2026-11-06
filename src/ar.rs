//! `ar` (archiver) format — static libraries (`.a` files).
//!
//! Layout: `!<arch>\n` magic, then 60-byte headers per member:
//! name[16] mtime[12] uid[6] gid[6] mode[8] size[10] fmag[2]="`\n",
//! name terminated by `/\n`, long names (>15) via `//` string table.

use crate::error::BinutilsError;
use std::collections::BTreeMap;

const MAGIC: &[u8; 8] = b"!<arch>\n";
const HEADER_LEN: usize = 60;
const GLOBAL_NAME: &str = "//";

/// Kind of archive member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberKind {
    /// Regular object member.
    Object,
    /// Symbol table (`/` or `/SYM64/`).
    SymbolTable,
    /// Long-name string table (`//`).
    NameTable,
}

/// One member of an archive.
#[derive(Debug, Clone)]
pub struct Member {
    pub name: String,
    pub kind: MemberKind,
    pub data: Vec<u8>,
}

/// Parsed `ar` archive.
#[derive(Debug, Default)]
pub struct Archive {
    pub members: Vec<Member>,
}

/// Builder producing deterministic archives (sorted members, zeroed metadata).
#[derive(Debug, Default)]
pub struct ArchiveBuilder {
    members: BTreeMap<String, Vec<u8>>,
}

impl ArchiveBuilder {
    pub fn new() -> Self { Self::default() }

    /// Add/replace a member; name must be ≤15 bytes or stored via name table.
    pub fn add(&mut self, name: impl Into<String>, data: Vec<u8>) -> &mut Self {
        self.members.insert(name.into(), data);
        self
    }

    /// Serialise to the `ar` format.
    pub fn build(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        // Long-name table for names > 15 chars.
        let mut name_table = Vec::new();
        let mut offsets: BTreeMap<String, usize> = BTreeMap::new();
        for name in self.members.keys() {
            if name.len() > 15 {
                offsets.insert(name.clone(), name_table.len());
                name_table.extend_from_slice(name.as_bytes());
                name_table.push(b'/');
                name_table.push(b'\n');
            }
        }
        if !name_table.is_empty() {
            write_header(&mut out, GLOBAL_NAME, name_table.len() as u64, 0o100644);
            out.extend_from_slice(&name_table);
            pad(&mut out);
        }
        for (name, data) in &self.members {
            let field = if name.len() > 15 {
                format!("/{}/", offsets[name])
            } else {
                format!("{name}/")
            };
            write_header(&mut out, &field, data.len() as u64, 0o100644);
            out.extend_from_slice(data);
            pad(&mut out);
        }
        out
    }
}

impl Archive {
    /// Parse an archive from bytes.
    pub fn parse(data: &[u8]) -> Result<Self, BinutilsError> {
        if data.len() < 8 || &data[..8] != MAGIC {
            return Err(BinutilsError::BadFormat("not an ar archive"));
        }
        let mut members = Vec::new();
        let mut pos = 8usize;
        let mut name_table: Vec<u8> = Vec::new();
        while pos + HEADER_LEN <= data.len() {
            let hdr = &data[pos..pos + HEADER_LEN];
            if &hdr[58..60] != b"`\n" {
                return Err(BinutilsError::Malformed("bad member magic"));
            }
            let raw_name = std::str::from_utf8(&hdr[0..16])
                .map_err(|_| BinutilsError::Malformed("bad member name"))?
                .trim()
                .trim_end_matches('/');
            let size: u64 = std::str::from_utf8(&hdr[48..58])
                .map_err(|_| BinutilsError::Malformed("bad member size"))?
                .trim()
                .parse()
                .map_err(|_| BinutilsError::Malformed("bad member size"))?;
            pos += HEADER_LEN;
            let end = pos + size as usize;
            if end > data.len() {
                return Err(BinutilsError::Malformed("member overruns archive"));
            }
            let body = &data[pos..end];
            let name = if raw_name == GLOBAL_NAME.trim_end_matches('/') {
                // "//" — name table
                name_table = body.to_vec();
                pos = end + (end & 1); // members are 2-byte aligned
                continue;
            } else if raw_name.starts_with('/') && raw_name.len() > 1
                && raw_name[1..].chars().all(|c| c.is_ascii_digit())
            {
                // "/<offset>" — long name reference (trailing '/' trimmed above)
                let off: usize = raw_name[1..]
                    .parse()
                    .map_err(|_| BinutilsError::Malformed("bad long-name offset"))?;
                let rel_end = name_table[off..]
                    .iter()
                    .position(|&b| b == b'\n')
                    .map(|i| off + i)
                    .ok_or(BinutilsError::Malformed("unterminated long name"))?;
                String::from_utf8_lossy(&name_table[off..rel_end])
                    .trim_end_matches('/')
                    .to_string()
            } else if raw_name == "/" || raw_name.starts_with("/SYM") {
                pos = end + (end & 1);
                continue; // symbol table — skipped by this tool
            } else {
                raw_name.to_string()
            };
            members.push(Member {
                name,
                kind: MemberKind::Object,
                data: body.to_vec(),
            });
            pos = end + (end & 1);
        }
        Ok(Self { members })
    }

    /// Find a member by name.
    pub fn member(&self, name: &str) -> Result<&Member, BinutilsError> {
        self.members
            .iter()
            .find(|m| m.name == name)
            .ok_or_else(|| BinutilsError::NotFound(name.to_string()))
    }
}

fn write_header(out: &mut Vec<u8>, name: &str, size: u64, mode: u32) {
    out.extend_from_slice(format!("{name:<16}").as_bytes());
    out.extend_from_slice(b"0           "); // mtime
    out.extend_from_slice(b"0     0     "); // uid gid
    out.extend_from_slice(format!("{mode:<8o}").as_bytes());
    out.extend_from_slice(format!("{size:<10}").as_bytes());
    out.extend_from_slice(b"`\n");
}

fn pad(out: &mut Vec<u8>) {
    if out.len() % 2 == 1 {
        out.push(b'\n');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_parse_roundtrip() {
        let mut b = ArchiveBuilder::new();
        b.add("foo.o", vec![1, 2, 3]).add("bar.o", vec![4, 5]);
        let bytes = b.build();
        assert_eq!(&bytes[..8], MAGIC);
        let a = Archive::parse(&bytes).unwrap();
        assert_eq!(a.members.len(), 2);
        assert_eq!(a.member("foo.o").unwrap().data, vec![1, 2, 3]);
    }

    #[test]
    fn long_names_use_name_table() {
        let mut b = ArchiveBuilder::new();
        b.add("a-very-long-object-name.o", vec![9]);
        let bytes = b.build();
        assert!(bytes.windows(2).any(|w| w == b"//"));
        let a = Archive::parse(&bytes).unwrap();
        assert_eq!(a.members[0].name, "a-very-long-object-name.o");
    }

    #[test]
    fn rejects_bad_magic() {
        assert!(Archive::parse(b"nope").is_err());
    }
}
