// SPDX-License-Identifier: GPL-2.0-only
//! ECDSA P-256 with SHA-256: signing for the server, and verification.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::pkcs8::DecodePrivateKey;
use rustls::crypto::KeyProvider;
use rustls::pki_types::{
    AlgorithmIdentifier, InvalidSignature, PrivateKeyDer, SignatureVerificationAlgorithm, SubjectPublicKeyInfoDer,
    alg_id,
};
use rustls::sign::{Signer, SigningKey};
use rustls::{Error, SignatureAlgorithm, SignatureScheme};

/// Loads P-256 private keys in PKCS#8 or SEC1 form. Anything else is refused.
#[derive(Debug)]
pub(crate) struct EcdsaKeyProvider;

impl KeyProvider for EcdsaKeyProvider {
    fn load_private_key(&self, key_der: PrivateKeyDer<'static>) -> Result<Arc<dyn SigningKey>, Error> {
        let key = match &key_der {
            PrivateKeyDer::Pkcs8(der) => p256::ecdsa::SigningKey::from_pkcs8_der(der.secret_pkcs8_der()).ok(),
            PrivateKeyDer::Sec1(der) => {
                p256::SecretKey::from_sec1_der(der.secret_sec1_der()).ok().map(|k| p256::ecdsa::SigningKey::from(&k))
            }
            _ => None,
        };
        let key = key.ok_or_else(|| Error::General("not an ECDSA P-256 private key".into()))?;
        Ok(Arc::new(EcdsaSigningKey::new(key)))
    }
}

/// A server's ECDSA P-256 key.
#[derive(Debug)]
pub struct EcdsaSigningKey {
    key: Arc<p256::ecdsa::SigningKey>,
}

impl EcdsaSigningKey {
    /// Wraps `key`.
    pub fn new(key: p256::ecdsa::SigningKey) -> Self {
        Self { key: Arc::new(key) }
    }

    /// The public key as an uncompressed SEC1 point (`04 || x || y`).
    pub fn public_point(&self) -> Vec<u8> {
        self.key.verifying_key().to_sec1_point(false).as_bytes().to_vec()
    }
}

impl SigningKey for EcdsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| Box::new(EcdsaSigner(self.key.clone())) as Box<dyn Signer>)
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(rustls::sign::public_key_to_spki(&alg_id::ECDSA_P256, self.public_point()))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

#[derive(Debug)]
struct EcdsaSigner(Arc<p256::ecdsa::SigningKey>);

impl Signer for EcdsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        // RFC 6979 deterministic nonces: no randomness needed, so none can be weak.
        let sig: p256::ecdsa::Signature = self.0.sign(message);
        Ok(sig.to_der().as_bytes().to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

/// ECDSA P-256 with SHA-256, for checking certificates and handshake signatures.
pub static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm = &EcdsaP256Sha256;

#[derive(Debug)]
struct EcdsaP256Sha256;

impl SignatureVerificationAlgorithm for EcdsaP256Sha256 {
    fn verify_signature(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), InvalidSignature> {
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key).map_err(|_| InvalidSignature)?;
        let sig = p256::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
        key.verify(message, &sig).map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P256
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_SHA256
    }
}
