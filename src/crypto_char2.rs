//! Real sect283r1 provider, isolated from BoringSSL by static symbol prefixes.
//! Its opaque objects never cross between crypto implementations. BoringSSL
//! owns TLS negotiation, transcript validation, certificates and key schedule.

use std::ffi::{c_int, c_void};
use std::sync::OnceLock;

type Generate = unsafe extern "C" fn(*mut u8) -> *mut c_void;
type Derive = unsafe extern "C" fn(*mut c_void, *mut u8, *const u8, usize) -> c_int;
type Free = unsafe extern "C" fn(*mut c_void);

#[repr(C)]
struct Char2Callbacks {
    generate: Generate,
    derive: Derive,
    free: Free,
}

unsafe extern "C" {
    fn bridge_char2_generate(out: *mut u8) -> *mut c_void;
    fn bridge_char2_derive(
        context: *mut c_void,
        out: *mut u8,
        peer: *const u8,
        peer_len: usize,
    ) -> c_int;
    fn bridge_char2_free(context: *mut c_void);
    fn SSL_set_bridge_char2_callbacks(callbacks: *const Char2Callbacks) -> c_int;
}

static CALLBACKS: Char2Callbacks = Char2Callbacks {
    generate: bridge_char2_generate,
    derive: bridge_char2_derive,
    free: bridge_char2_free,
};

/// Register immutable, process-lifetime callbacks before any TLS configuration.
pub(crate) fn register() -> bool {
    static REGISTERED: OnceLock<bool> = OnceLock::new();
    *REGISTERED.get_or_init(|| {
        // SAFETY: these statically linked functions implement the fixed native
        // callback contracts. They retain no borrowed memory and cleanse their
        // private keys when the native key share invokes the free callback.
        unsafe { SSL_set_bridge_char2_callbacks(&CALLBACKS) == 1 }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Key(*mut c_void);
    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: Key uniquely owns this provider context.
            unsafe { bridge_char2_free(self.0) };
        }
    }

    fn generate() -> (Key, [u8; 73]) {
        let mut public = [0; 73];
        // SAFETY: provider writes the specified fixed-size public key buffer.
        let key = Key(unsafe { bridge_char2_generate(public.as_mut_ptr()) });
        assert!(!key.0.is_null());
        assert_eq!(public[0], 4);
        (key, public)
    }

    fn derive(key: &Key, peer: &[u8]) -> Option<[u8; 36]> {
        let mut secret = [0xa5; 36];
        // SAFETY: the context is live and the provided buffers are disjoint.
        let ok =
            unsafe { bridge_char2_derive(key.0, secret.as_mut_ptr(), peer.as_ptr(), peer.len()) };
        if ok == 1 {
            Some(secret)
        } else {
            assert_eq!(secret, [0; 36], "failed derivation exposed output");
            None
        }
    }

    #[test]
    fn char2_real_exchange_and_fresh_keys() {
        let (alice, alice_public) = generate();
        let (bob, bob_public) = generate();
        assert_ne!(alice_public, bob_public);
        let secret = derive(&alice, &bob_public).unwrap();
        assert_ne!(secret, [0; 36]);
        assert_eq!(derive(&bob, &alice_public), Some(secret));
        // Both compressed representatives are inverses on this curve. Their
        // ECDH results have the same x coordinate, regardless of the sign bit.
        for prefix in [2, 3] {
            let mut compressed = [0; 37];
            compressed[0] = prefix;
            compressed[1..].copy_from_slice(&bob_public[1..37]);
            assert_eq!(derive(&alice, &compressed), Some(secret));
        }
    }

    #[test]
    fn char2_rejects_invalid_encodings_and_clears_output() {
        let (key, public) = generate();
        for length in [0, 1, 36, 38, 72] {
            assert_eq!(derive(&key, &public[..length]), None);
        }
        let mut hybrid = public;
        hybrid[0] = 6;
        assert_eq!(derive(&key, &hybrid), None);
        let mut noncanonical = public;
        noncanonical[1] |= 0x80;
        assert_eq!(derive(&key, &noncanonical), None);
        let mut off_curve = [0; 73];
        off_curve[0] = 4;
        assert_eq!(derive(&key, &off_curve), None);
        assert_eq!(derive(&key, &[0]), None);
        // x = 0 is the characteristic-two point of order two. It is on the
        // curve, but must not be accepted by the prime-order ECDH subgroup.
        let mut order_two = [0; 37];
        order_two[0] = 2;
        assert_eq!(derive(&key, &order_two), None);
    }
}
