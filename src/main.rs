use binutils::{ar::Archive, elf::ElfFile};
use std::env;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let Some(cmd) = args.first() else {
        eprintln!("usage: binutils <ar-t|ar-x|nm|objdump-h> <file> [member]");
        return ExitCode::from(2);
    };
    let Some(path) = args.get(1) else {
        eprintln!("missing file argument");
        return ExitCode::from(2);
    };
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => { eprintln!("{path}: {e}"); return ExitCode::FAILURE; }
    };
    match cmd.as_str() {
        "ar-t" => match Archive::parse(&data) {
            Ok(a) => { for m in &a.members { println!("{}", m.name); } ExitCode::SUCCESS }
            Err(e) => { eprintln!("{e}"); ExitCode::FAILURE }
        },
        "ar-x" => match Archive::parse(&data) {
            Ok(a) => {
                let name = args.get(2).map(|s| s.as_str()).unwrap_or("");
                match a.member(name) {
                    Ok(m) => { print!("{}", String::from_utf8_lossy(&m.data)); ExitCode::SUCCESS }
                    Err(e) => { eprintln!("{e}"); ExitCode::FAILURE }
                }
            }
            Err(e) => { eprintln!("{e}"); ExitCode::FAILURE }
        },
        "nm" => match ElfFile::parse(&data) {
            Ok(e) => {
                for s in &e.symbols { println!("{:016x} {} {}", s.value, s.binding, s.name); }
                ExitCode::SUCCESS
            }
            Err(e) => { eprintln!("{e}"); ExitCode::FAILURE }
        },
        "objdump-h" => match ElfFile::parse(&data) {
            Ok(e) => {
                for s in &e.sections { println!("{:08x} {:08x} {}", s.offset, s.size, s.name); }
                ExitCode::SUCCESS
            }
            Err(e) => { eprintln!("{e}"); ExitCode::FAILURE }
        },
        _ => { eprintln!("unknown command: {cmd}"); ExitCode::from(2) }
    }
}
