use chambers_core::audit::verify_audit_log;

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "chambers-verify", about = "Verify a Chambers audit log")]
struct Args {
    /// Path to the audit log file (NDJSON)
    #[arg(short, long)]
    audit: PathBuf,

    /// Session public signing key (hex-encoded, 64 chars)
    #[arg(short, long)]
    pubkey: String,
}

fn main() {
    let args = Args::parse();

    // Decode hex public key
    let pubkey_bytes = match hex_decode(&args.pubkey) {
        Some(bytes) if bytes.len() == 32 => bytes,
        Some(bytes) => {
            eprintln!("Error: public key must be 32 bytes (64 hex chars), got {} bytes", bytes.len());
            std::process::exit(1);
        }
        None => {
            eprintln!("Error: invalid hex string for public key");
            std::process::exit(1);
        }
    };

    println!("╔══════════════════════════════════════════╗");
    println!("║   CHAMBERS AUDIT LOG VERIFICATION        ║");
    println!("╚══════════════════════════════════════════╝");
    println!();
    println!("Audit log: {}", args.audit.display());
    println!("Public key: {}", args.pubkey);
    println!();

    match verify_audit_log(&args.audit, &pubkey_bytes) {
        Ok(result) => {
            println!("── Verification Result ──");
            println!();
            println!("  Total entries:    {}", result.total_entries);
            println!("  Hash chain:       {}", if result.hash_chain_intact { "INTACT" } else { "BROKEN" });
            println!("  Signatures:       {}", if result.all_signatures_valid {
                format!("ALL VALID ({}/{})", result.total_entries, result.total_entries)
            } else {
                format!("INVALID (first failure at entry {})", result.first_invalid_entry.unwrap_or(0))
            });
            println!("  Session ID:       {}", result.session_id);
            println!("  Manifest hash:    {}", hex_encode(&result.manifest_hash));
            println!("  Sealed events:    {}", result.sealed_events_count);
            println!("  Anomalies:        {}", result.anomalies_count);
            println!("  Data flow entries: {}", result.data_flow_count);
            println!();

            if result.all_signatures_valid && result.hash_chain_intact {
                println!("  ✓ VERIFICATION PASSED");
                std::process::exit(0);
            } else {
                println!("  ✗ VERIFICATION FAILED");
                if !result.hash_chain_intact {
                    println!("    Hash chain broken — log may have been tampered with");
                }
                if !result.all_signatures_valid {
                    println!("    Signature verification failed — wrong key or tampered entries");
                }
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Verification error: {}", e);
            std::process::exit(2);
        }
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
