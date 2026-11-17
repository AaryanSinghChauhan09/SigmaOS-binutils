//! `ar` static-archive parser (GNU/BSD variants).
//!
//! Archive layout: 8-byte magic `!<arch>\n`, then a sequence of 60-byte
//! member headers each followed by `size` bytes of data (padded to even).

use std::fmt;

/// Errors produced while parsing an archive.
#[derive(Debug)]
pub enum ArError {
    /// Input is too short to contain the magic or a member header.
    Truncated,
    /// The leading magic bytes are not `!<arch>\n`.
    BadMagic,
    /// A numeric header field could not be parsed.
    BadField(&'static str),
    /// A member name referenced the string table out of range.
    BadNameRef,
    /// A requested member was not present.
    MemberNotFound(String),
}

impl fmt::Display for ArError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "archive truncated"),
            Self::BadMagic => write!(f, "not an ar archive (bad magic)"),
            Self::BadField(field) => write!(f, "bad numeric field: {field}"),
            Self::BadNameRef => write!(f, "member name reference out of range"),
            Self::MemberNotFound(n) => write!(f, "member not found: {n}"),
        }
    }
}
impl std::error::Error for ArError {}

/// A single member of an `ar` archive.
#[derive(Debug, Clone)]
pub struct Member {
    pub name: String,
    pub data: Vec<u8>,
}

/// A parsed `ar` archive.
#[derive(Debug)]
pub struct Archive {
    pub members: Vec<Member>,
    string_table: Vec<u8>,
}

const MAGIC: &[u8; 8] = b"!<arch>\n";
const HDR_LEN: usize = 60;

fn parse_num(field: &[u8], what: &'static str) -> Result<usize, ArError> {
    let s = std::str::from_utf8(field).map_err(|_| ArError::BadField(what))?;
    s.trim().parse::<usize>().map_err(|_| ArError::BadField(what))
}

/// Resolve a raw member name field to a real name.
fn resolve_name(raw: &str, string_table: &[u8], data_head: &[u8]) -> Result<String, ArError> {
    let raw = raw.trim_end_matches(|c| c == ' ' || c == '\0');
    // BSD-style long name: "#1/<len>" — name is the first <len> bytes of data.
    if let Some(rest) = raw.strip_prefix("#1/") {
        if let Ok(len) = rest.trim().parse::<usize>() {
            return Ok(String::from_utf8_lossy(&data_head[..len.min(data_head.len())]).into_owned());
        }
        return Ok(raw.to_string());
    }
    // String-table reference: "/<offset>" (offset "/" alone is the table itself).
    if let Some(off_str) = raw.strip_prefix('/') {
        if off_str.is_empty() {
            return Ok(String::new()); // the string table member
        }
        if let Ok(off) = off_str.trim().parse::<usize>() {
            let end = string_table[off..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| off + p)
                .unwrap_or(string_table.len());
            if off > string_table.len() || end > string_table.len() {
                return Err(ArError::BadNameRef);
            }
            return Ok(String::from_utf8_lossy(&string_table[off..end]).into_owned());
        }
    }
    // GNU-style: trailing '/' terminator.
    Ok(raw.trim_end_matches('/').to_string())
}

impl Archive {
    /// Parse an `ar` archive from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, ArError> {
        if data.len() < MAGIC.len() {
            return Err(ArError::Truncated);
        }
        if &data[..MAGIC.len()] != MAGIC {
            return Err(ArError::BadMagic);
        }
        let mut members = Vec::new();
        let mut string_table: Vec<u8> = Vec::new();
        let mut pos = MAGIC.len();

        while pos + HDR_LEN <= data.len() {
            let hdr = &data[pos..pos + HDR_LEN];
            if &hdr[58..60] != b"`\n" {
                break; // not a valid member header — end of archive
            }
            let name_raw = std::str::from_utf8(&hdr[0..16]).unwrap_or("").to_string();
            let size = parse_num(&hdr[48..58], "size")?;
            let data_start = pos + HDR_LEN;
            let data_end = data_start.saturating_add(size);
            if data_end > data.len() {
                return Err(ArError::Truncated);
            }
            let member_data = &data[data_start..data_end];

            // Long-name data head for BSD "#1/" names is inside member_data.
            let name = resolve_name(&name_raw, &string_table, member_data)?;

            // String table member: "/" or "//" stores long names for later members.
            if name_raw.trim_end().starts_with("//") {
                string_table = member_data.to_vec();
            } else if !name.is_empty() {
                members.push(Member { name, data: member_data.to_vec() });
            }

            // Members are padded to an even boundary.
            pos = data_end + (size & 1);
        }

        Ok(Self { members, string_table })
    }

    /// Look up a member by exact name.
    pub fn member(&self, name: &str) -> Result<&Member, ArError> {
        self.members
            .iter()
            .find(|m| m.name == name)
            .ok_or_else(|| ArError::MemberNotFound(name.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ar_member(name: &str, body: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        let mut n = name.as_bytes().to_vec();
        n.resize(16, b' ');
        v.extend_from_slice(&n);
        v.extend_from_slice(b"0           0     0     100644  ");
        let sz = format!("{:>10}", body.len());
        v.extend_from_slice(sz.as_bytes());
        v.extend_from_slice(b"`\n");
        v.extend_from_slice(body);
        if body.len() & 1 == 1 {
            v.push(b'\n');
        }
        v
    }

    #[test]
    fn parses_simple_archive() {
        let mut data = MAGIC.to_vec();
        data.extend(ar_member("foo.o/", b"OBJECT-A"));
        data.extend(ar_member("bar.o/", b"OBJECT-BB"));
        let a = Archive::parse(&data).unwrap();
        assert_eq!(a.members.len(), 2);
        assert_eq!(a.members[0].name, "foo.o");
        assert_eq!(a.members[0].data, b"OBJECT-A");
        assert_eq!(a.members[1].name, "bar.o");
    }

    #[test]
    fn member_lookup() {
        let mut data = MAGIC.to_vec();
        data.extend(ar_member("x.o/", b"X"));
        let a = Archive::parse(&data).unwrap();
        assert!(a.member("x.o").is_ok());
        assert!(a.member("nope.o").is_err());
    }

    #[test]
    fn rejects_bad_magic() {
        assert!(matches!(Archive::parse(b"not an archive"), Err(ArError::BadMagic)));
    }

    #[test]
    fn rejects_truncated() {
        assert!(matches!(Archive::parse(b"!<arch>"), Err(ArError::Truncated)));
    }
}
