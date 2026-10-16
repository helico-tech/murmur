//! Peer and swarm identities.

use std::fmt;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// A peer: its ed25519 public key. With `murmur-iroh` it is also the iroh endpoint id.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PeerId(pub [u8; 32]);

/// A swarm: derived from the swarm secret, see [`SwarmKey`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SwarmId(pub [u8; 32]);

macro_rules! hex_id {
    ($t:ident) => {
        impl $t {
            pub fn to_hex(&self) -> String {
                data_encoding::HEXLOWER.encode(&self.0)
            }

            pub fn from_hex(s: &str) -> Option<$t> {
                let v = data_encoding::HEXLOWER_PERMISSIVE.decode(s.trim().as_bytes()).ok()?;
                <[u8; 32]>::try_from(v.as_slice()).ok().map($t)
            }

            /// The first 5 bytes in hex, for logs and people.
            pub fn short(&self) -> String {
                data_encoding::HEXLOWER.encode(&self.0[..5])
            }
        }

        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl fmt::Debug for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($t), self.short())
            }
        }
    };
}
hex_id!(PeerId);
hex_id!(SwarmId);

/// This peer's signing key. The same 32 secret bytes can be an iroh `SecretKey`.
#[derive(Clone)]
pub struct Identity {
    key: SigningKey,
}

impl Identity {
    pub fn from_secret(secret: [u8; 32]) -> Identity {
        Identity { key: SigningKey::from_bytes(&secret) }
    }

    pub fn secret(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    pub fn id(&self) -> PeerId {
        PeerId(self.key.verifying_key().to_bytes())
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.key.sign(msg).to_bytes()
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Identity({})", self.id().short())
    }
}

/// Checks an ed25519 signature by `author` over `msg`. Never panics on bad keys or signatures.
pub fn verify(author: &PeerId, msg: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(&author.0) else { return false };
    let sig = ed25519_dalek::Signature::from_bytes(sig);
    key.verify_strict(msg, &sig).is_ok()
}

/// What every member of a swarm knows: the swarm secret, from which the swarm id and the key
/// for connection proofs are derived.
#[derive(Clone)]
pub struct SwarmKey {
    id: SwarmId,
    auth: [u8; 32],
}

impl SwarmKey {
    pub fn from_secret(secret: &[u8; 32]) -> SwarmKey {
        SwarmKey { id: SwarmId(blake3::derive_key("murmur swarm id v1", secret)), auth: blake3::derive_key("murmur swarm auth v1", secret) }
    }

    pub fn id(&self) -> SwarmId {
        self.id
    }

    /// Proof that `from` knows the swarm secret, for a connection to `to`. Bound to both ids, so
    /// it can't be replayed on another connection.
    pub fn proof(&self, from: &PeerId, to: &PeerId) -> [u8; 32] {
        let mut msg = [0u8; 64];
        msg[..32].copy_from_slice(&from.0);
        msg[32..].copy_from_slice(&to.0);
        *blake3::keyed_hash(&self.auth, &msg).as_bytes()
    }

    /// Checks a proof in constant time.
    pub fn check(&self, from: &PeerId, to: &PeerId, proof: &[u8; 32]) -> bool {
        let mut msg = [0u8; 64];
        msg[..32].copy_from_slice(&from.0);
        msg[32..].copy_from_slice(&to.0);
        blake3::keyed_hash(&self.auth, &msg) == blake3::Hash::from_bytes(*proof)
    }
}

impl fmt::Debug for SwarmKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SwarmKey({})", self.id.short())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proofs_bind_both_peers_and_the_secret() {
        let k = SwarmKey::from_secret(&[7; 32]);
        let other = SwarmKey::from_secret(&[8; 32]);
        let (a, b, c) = (PeerId([1; 32]), PeerId([2; 32]), PeerId([3; 32]));
        let p = k.proof(&a, &b);
        assert!(k.check(&a, &b, &p));
        assert!(!k.check(&b, &a, &p), "direction matters");
        assert!(!k.check(&a, &c, &p), "receiver matters");
        assert!(!other.check(&a, &b, &p), "secret matters");
        assert_ne!(k.id(), other.id());
    }

    #[test]
    fn hex_round_trip_and_junk() {
        let id = Identity::from_secret([9; 32]).id();
        assert_eq!(PeerId::from_hex(&id.to_hex()), Some(id));
        assert_eq!(PeerId::from_hex("zz"), None);
        assert_eq!(PeerId::from_hex(&"ab".repeat(31)), None);
    }

    #[test]
    fn verify_rejects_bad_keys_and_signatures() {
        let me = Identity::from_secret([1; 32]);
        let sig = me.sign(b"hi");
        assert!(verify(&me.id(), b"hi", &sig));
        assert!(!verify(&me.id(), b"ho", &sig));
        assert!(!verify(&PeerId([0xff; 32]), b"hi", &sig));
        assert!(!verify(&me.id(), b"hi", &[0; 64]));
    }
}
