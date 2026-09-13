//! Measures one password unlock with the default Argon2id parameters on this machine.
//!
//!     cargo run --release -p krypt-core --example kdf_timing

use std::time::Instant;

use krypt_core::crypto::{self, KdfParams, SALT_LEN};

fn main() {
    let params = KdfParams::DEFAULT;
    let salt = [7u8; SALT_LEN];
    crypto::argon2id(b"warm up", &salt, params).expect("argon2id");

    let runs = 5;
    let start = Instant::now();
    for _ in 0..runs {
        crypto::argon2id(b"correct horse battery staple", &salt, params).expect("argon2id");
    }
    let per_run = start.elapsed() / runs;
    println!(
        "Argon2id m={} KiB, t={}, p={}: {:.0} ms per unlock",
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        per_run.as_secs_f64() * 1000.0
    );
}
