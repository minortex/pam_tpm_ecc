use std::env;
use std::process;

use pam_tpm_ecc::diagnostic_sign;

fn main() {
    let args: Vec<String> = env::args().collect();
    let pin = args.get(1).map(String::as_str).unwrap_or("");
    let key_handle = args.get(2).map(String::as_str).unwrap_or("0x81020000");
    let tcti = args
        .get(3)
        .map(String::as_str)
        .unwrap_or("device:/dev/tpmrm0");

    let key_handle = match parse_handle(key_handle) {
        Some(value) => value,
        None => {
            eprintln!("invalid key handle: {key_handle}");
            process::exit(2);
        }
    };

    match diagnostic_sign(pin.as_bytes(), key_handle, tcti) {
        Ok(signature) => {
            println!("signature_raw_hex={}", hex(&signature));
        }
        Err(err) => {
            eprintln!("{err}");
            process::exit(1);
        }
    }
}

fn parse_handle(value: &str) -> Option<u32> {
    let parsed = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()?
    } else {
        value.parse::<u64>().ok()?
    };
    u32::try_from(parsed).ok()
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}
