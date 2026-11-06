//! SigmaOS-binutils — binary tools for SigmaOS.
//!
//! Implements the core primitives of GNU binutils:
//! - `ar` archive format: create, list, extract members
//! - ELF object inspection: section/symbol tables (`nm`, `objdump -h` style)

pub mod ar;
pub mod elf;
pub mod error;

pub use ar::{Archive, ArchiveBuilder, Member, MemberKind};
pub use elf::{ElfFile, Section, Symbol, SymbolKind};
pub use error::BinutilsError;
