//! A rustls crypto provider with exactly one choice of each algorithm.
//!
//! | Role | Algorithm | Implementation |
//! |---|---|---|
//! | Cipher suite | `TLS13_CHACHA20_POLY1305_SHA256` | `chacha20poly1305`, `sha2`, `hmac` |
//! | Key exchange | X25519 | `x25519-dalek` |
//! | Signatures | ECDSA P-256 with SHA-256 | `p256` |
//! | Randomness | ChaCha20 generator | `osmium-rand` |
//!
//! Every mainstream browser and TLS library supports all of these. TLS 1.2
//! and every other algorithm are left out on purpose: fewer choices means
//! less code to trust.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Tag};
use hmac::Mac;
use osmium_rand::SharedRng;
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter, MessageEncrypter, Nonce,
    OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Tls13AeadAlgorithm, UnsupportedOperationError,
    make_tls13_aad,
};
use rustls::crypto::tls13::HkdfUsingHmac;
use rustls::crypto::{
    ActiveKeyExchange, CipherSuiteCommon, CryptoProvider, GetRandomFailed, SecureRandom, SharedSecret,
    SupportedKxGroup, WebPkiSupportedAlgorithms, hash, hmac as rhmac,
};
use rustls::{
    CipherSuite, ConnectionTrafficSecrets, ContentType, Error, NamedGroup, PeerMisbehaved, ProtocolVersion,
    SignatureScheme, SupportedCipherSuite, Tls13CipherSuite,
};

use crate::sign::{ECDSA_P256_SHA256, EcdsaKeyProvider};

const TAG_LEN: usize = 16;

/// A provider whose randomness comes from `rng`, which must already be
/// seeded: handshakes fail while it isn't.
///
/// Build it once and share it, for example in an `Arc`: each call leaks a
/// few bytes, because rustls wants `'static` references to its components.
pub fn provider(rng: &'static SharedRng) -> CryptoProvider {
    let random: &'static Random = Box::leak(Box::new(Random(rng)));
    CryptoProvider {
        cipher_suites: vec![TLS13_CHACHA20_POLY1305_SHA256],
        kx_groups: vec![Box::leak(Box::new(X25519(random)))],
        signature_verification_algorithms: SIGNATURE_ALGORITHMS,
        secure_random: random,
        key_provider: &EcdsaKeyProvider,
    }
}

/// The signature verification algorithms: ECDSA P-256 with SHA-256 only.
/// Servers use them only to check client certificates.
pub static SIGNATURE_ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[ECDSA_P256_SHA256],
    mapping: &[(SignatureScheme::ECDSA_NISTP256_SHA256, &[ECDSA_P256_SHA256])],
};

/// `TLS13_CHACHA20_POLY1305_SHA256`.
pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite = SupportedCipherSuite::Tls13(&Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        hash_provider: &Sha256,
        // No practical limit for ChaCha20-Poly1305 (draft-irtf-cfrg-aead-limits, section 5.2.1).
        confidentiality_limit: u64::MAX,
    },
    hkdf_provider: &HkdfUsingHmac(&HmacSha256),
    aead_alg: &Chacha20Poly1305Aead,
    quic: None,
});

/// rustls's randomness, drawn from an `osmium-rand` generator.
pub(crate) struct Random(pub(crate) &'static SharedRng);

impl core::fmt::Debug for Random {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Random")
    }
}

impl SecureRandom for Random {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        self.0.fill(buf).map_err(|_| GetRandomFailed)
    }
}

struct Sha256;

impl hash::Hash for Sha256 {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(Sha256Context(sha2::Sha256::default()))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        hash::Output::new(&<sha2::Sha256 as sha2::Digest>::digest(data))
    }

    fn output_len(&self) -> usize {
        32
    }

    fn algorithm(&self) -> hash::HashAlgorithm {
        hash::HashAlgorithm::SHA256
    }
}

#[derive(Clone)]
struct Sha256Context(sha2::Sha256);

impl hash::Context for Sha256Context {
    fn fork_finish(&self) -> hash::Output {
        hash::Output::new(&sha2::Digest::finalize(self.0.clone()))
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(self.clone())
    }

    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(&sha2::Digest::finalize(self.0))
    }

    fn update(&mut self, data: &[u8]) {
        sha2::Digest::update(&mut self.0, data);
    }
}

struct HmacSha256;

impl rhmac::Hmac for HmacSha256 {
    #[allow(clippy::unreachable, reason = "HMAC accepts keys of every length")]
    fn with_key(&self, key: &[u8]) -> Box<dyn rhmac::Key> {
        // HMAC accepts keys of any length, so this can't fail.
        Box::new(HmacSha256Key(
            hmac::Hmac::<sha2::Sha256>::new_from_slice(key).unwrap_or_else(|_| unreachable!("HMAC takes any key")),
        ))
    }

    fn hash_output_len(&self) -> usize {
        32
    }
}

struct HmacSha256Key(hmac::Hmac<sha2::Sha256>);

impl rhmac::Key for HmacSha256Key {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> rhmac::Tag {
        let mut mac = self.0.clone();
        mac.update(first);
        for m in middle {
            mac.update(m);
        }
        mac.update(last);
        rhmac::Tag::new(&mac.finalize().into_bytes())
    }

    fn tag_len(&self) -> usize {
        32
    }
}

struct Chacha20Poly1305Aead;

impl Tls13AeadAlgorithm for Chacha20Poly1305Aead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Chacha20Poly1305Cipher::new(&key, iv))
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Chacha20Poly1305Cipher::new(&key, iv))
    }

    fn key_len(&self) -> usize {
        32
    }

    fn extract_keys(&self, key: AeadKey, iv: Iv) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
    }
}

struct Chacha20Poly1305Cipher {
    aead: ChaCha20Poly1305,
    iv: Iv,
}

impl Chacha20Poly1305Cipher {
    #[allow(clippy::unreachable, reason = "rustls passes exactly key_len() = 32 bytes")]
    fn new(key: &AeadKey, iv: Iv) -> Self {
        // rustls hands over exactly `key_len()` bytes.
        let aead = ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap_or_else(|_| unreachable!("32-byte key"));
        Self { aead, iv }
    }

    fn nonce(&self, seq: u64) -> chacha20poly1305::Nonce {
        chacha20poly1305::Nonce::from(Nonce::new(&self.iv, seq).0)
    }
}

impl MessageEncrypter for Chacha20Poly1305Cipher {
    fn encrypt(&mut self, msg: OutboundPlainMessage<'_>, seq: u64) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());
        let tag = self
            .aead
            .encrypt_inout_detached(&self.nonce(seq), &make_tls13_aad(total_len), payload.as_mut().into())
            .map_err(|_| Error::EncryptError)?;
        payload.extend_from_slice(&tag);
        // TLS 1.3 records all carry the legacy version 0x0303 (RFC 8446, section 5.1).
        Ok(OutboundOpaqueMessage::new(ContentType::ApplicationData, ProtocolVersion::TLSv1_2, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG_LEN
    }
}

impl MessageDecrypter for Chacha20Poly1305Cipher {
    fn decrypt<'a>(&mut self, mut msg: InboundOpaqueMessage<'a>, seq: u64) -> Result<InboundPlainMessage<'a>, Error> {
        let len = msg.payload.len();
        let plain_len = len.checked_sub(TAG_LEN).ok_or(Error::DecryptError)?;
        let aad = make_tls13_aad(len);
        let (ciphertext, tag) = msg.payload.split_at_mut(plain_len);
        let tag = Tag::try_from(&*tag).map_err(|_| Error::DecryptError)?;
        self.aead
            .decrypt_inout_detached(&self.nonce(seq), &aad, ciphertext.into(), &tag)
            .map_err(|_| Error::DecryptError)?;
        msg.payload.truncate(plain_len);
        msg.into_tls13_unpadded_message()
    }
}

/// X25519 key exchange, with private keys drawn from the provider's generator.
#[derive(Debug)]
struct X25519(&'static Random);

impl SupportedKxGroup for X25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let mut bytes = [0u8; 32];
        self.0.fill(&mut bytes).map_err(|_| Error::FailedToGetRandomBytes)?;
        let secret = x25519_dalek::StaticSecret::from(bytes);
        osmium_rand::wipe(&mut bytes);
        let public = x25519_dalek::PublicKey::from(&secret);
        Ok(Box::new(X25519Exchange { secret, public: public.to_bytes() }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct X25519Exchange {
    secret: x25519_dalek::StaticSecret,
    public: [u8; 32],
}

impl ActiveKeyExchange for X25519Exchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let peer: [u8; 32] = peer_pub_key.try_into().map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
        let shared = self.secret.diffie_hellman(&x25519_dalek::PublicKey::from(peer));
        // A low-order peer point gives an all-zero secret (RFC 8446, section 7.4.2).
        if !shared.was_contributory() {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        Ok(SharedSecret::from(&shared.as_bytes()[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

/// The provider as an `Arc`, which is what rustls's config builders take.
pub fn shared_provider(rng: &'static SharedRng) -> Arc<CryptoProvider> {
    Arc::new(provider(rng))
}
