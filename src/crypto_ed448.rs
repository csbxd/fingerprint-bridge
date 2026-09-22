//! Verification-only PureEd448 for the native TLS and X.509 paths.
//!
//! RFC 8032 Ed448 with an empty context is required by TLS and RFC 8410. The
//! pinned CRRL implementation checks canonical encodings and the scalar range.
//! We additionally require a non-neutral public key in the prime-order subgroup
//! so weak public keys cannot turn the cofactored verification equation into an
//! authentication bypass. No signing or private-key operations are exposed.

use crrl::ed448::PublicKey;
use std::ffi::c_int;
use std::sync::OnceLock;

type VerifyCallback = unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int;

extern "C" {
    fn EVP_set_bridge_ed448_verify_callback(callback: Option<VerifyCallback>) -> c_int;
    fn EVP_bridge_ed448_verify_available() -> c_int;
}

/// Verify PureEd448, with the empty context used by TLS and X.509.
///
/// The key and signature must have their exact RFC 8032 lengths. This accepts
/// only canonical public keys in the prime-order subgroup, excluding identity.
/// Verification handles only public data and need not conceal its timing.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if public_key.len() != 57 || signature.len() != 114 {
        return false;
    }
    let Some(key) = PublicKey::decode(public_key) else {
        return false;
    };
    if key.point.isneutral() != 0 || key.point.is_in_subgroup() == 0 {
        return false;
    }
    key.verify_raw(signature, message)
}

unsafe extern "C" fn verify_callback(
    public_key: *const u8,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
) -> c_int {
    if public_key.is_null()
        || signature.is_null()
        || message_len > isize::MAX as usize
        || (message_len != 0 && message.is_null())
    {
        return 0;
    }
    // SAFETY: the native EVP method supplies a 57-byte key, 114-byte signature
    // and message_len readable bytes for the duration of this synchronous call.
    // Empty messages may have a null pointer, which must not be passed to
    // from_raw_parts. Catch panics so Rust never unwinds across the C ABI.
    std::panic::catch_unwind(|| unsafe {
        let key = std::slice::from_raw_parts(public_key, 57);
        let sig = std::slice::from_raw_parts(signature, 114);
        let msg = if message_len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(message, message_len)
        };
        c_int::from(verify(key, msg, sig))
    })
    .unwrap_or(0)
}

/// Install the real provider before enabling Ed448 in an upstream profile.
/// Native installation is immutable; an absent or conflicting provider fails
/// closed. No undefined Rust symbols are required by native-only consumers.
pub fn register() -> bool {
    static REGISTERED: OnceLock<bool> = OnceLock::new();
    *REGISTERED.get_or_init(|| {
        // SAFETY: this function pointer has process lifetime, uses the declared
        // ABI, reads only public inputs, and never unwinds through the callback.
        unsafe {
            EVP_set_bridge_ed448_verify_callback(Some(verify_callback)) == 1
                && EVP_bridge_ed448_verify_available() == 1
        }
    })
}
