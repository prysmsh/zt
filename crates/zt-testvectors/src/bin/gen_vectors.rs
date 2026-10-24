//! Emit golden test vectors to disk.
//!
//! ```text
//! cargo run -p zt-testvectors --bin gen_vectors -- next
//! cargo run -p zt-testvectors --bin gen_vectors -- legacy
//! ```
//!
//! The `legacy` track is used in Track B: the same format is emitted by the
//! ZeroTier C++ oracle so the two implementations can be diffed directly.

use std::path::PathBuf;

use zt_testvectors::{generate_all, Track};

fn main() {
    let track = match std::env::args().nth(1).as_deref() {
        Some("next") | None => Track::Next,
        Some("legacy") => Track::Legacy,
        Some(other) => {
            eprintln!("unknown track: {other} (expected 'next' or 'legacy')");
            std::process::exit(2);
        }
    };

    let out_dir = PathBuf::from(std::env::args().nth(2).unwrap_or_else(|| ".".into()));

    let mut written = 0;
    for (rel, json) in generate_all(track) {
        let path = out_dir.join(&rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create output directory");
        }
        std::fs::write(&path, json).expect("write vector file");
        println!("wrote {}", path.display());
        written += 1;
    }

    println!(
        "{written} vector file(s) written for track '{}'",
        track.dir_name()
    );
}
