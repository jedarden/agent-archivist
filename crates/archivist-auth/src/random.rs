// SPDX-License-Identifier: Apache-2.0

//! The OS entropy source every identity mint uses.
//!
//! There is deliberately no userland fallback: identity generation either
//! gets operating-system entropy from the kernel's blocking-post-DRBG pool
//! (`/dev/urandom` is fed by the same DRBG as `getrandom(2)` and never
//! blocks once initialized) or fails closed with
//! [`IdentityError::Entropy`](crate::IdentityError::Entropy). A software
//! fallback (time, PIDs, addresses) would mint identities an attacker could
//! reproduce.

use std::fs::File;
use std::io::Read;

use crate::error::IdentityError;

/// The kernel entropy pool device. Read through the file API so the usual
/// descriptor permission checks apply; the platform's `getrandom(2)`-class
/// syscall is not reachable dependency-free.
const URANDOM: &str = "/dev/urandom";

/// Fill `buf` entirely with cryptographically random bytes.
///
/// # Errors
/// [`IdentityError::Entropy`] when the entropy source cannot be opened,
/// returns short, or fails partway. The buffer's prior contents are
/// irrelevant on failure: callers must treat the operation as failed, not
/// as "some bytes were filled".
pub(crate) fn fill_random(buf: &mut [u8]) -> Result<(), IdentityError> {
    let mut file = File::open(URANDOM).map_err(|_io_error| IdentityError::Entropy)?;
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => return Err(IdentityError::Entropy),
            Ok(n) => filled += n,
            // A signal interrupting the read is not an entropy failure;
            // fall through to the next read attempt.
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(IdentityError::Entropy),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_the_whole_buffer_with_varied_bytes() {
        let mut a = [0u8; 64];
        fill_random(&mut a).expect("entropy source is available on every supported host");
        assert!(
            a.iter().any(|&b| b != 0),
            "64 random bytes are never all zero"
        );

        let mut b = [0u8; 64];
        fill_random(&mut b).expect("second read from the same source succeeds");
        assert_ne!(a, b, "two 64-byte draws never repeat");
    }
}
