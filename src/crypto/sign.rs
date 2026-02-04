use crate::core::matter::tables as matter;
use crate::error::{err, Error, Result};

pub(crate) fn generate(code: &str) -> Result<Vec<u8>> {
    match code {
        matter::Codex::Ed25519
        | matter::Codex::Ed25519N
        | matter::Codex::Ed25519_Seed
        | matter::Codex::Ed25519_Sig => ed25519::generate(),
        matter::Codex::ECDSA_256k1
        | matter::Codex::ECDSA_256k1N
        | matter::Codex::ECDSA_256k1_Seed
        | matter::Codex::ECDSA_256k1_Sig => ecdsa_256k1::generate(),
        matter::Codex::ECDSA_256r1
        | matter::Codex::ECDSA_256r1N
        | matter::Codex::ECDSA_256r1_Seed
        | matter::Codex::ECDSA_256r1_Sig => ecdsa_256r1::generate(),
        matter::Codex::Ed448
        | matter::Codex::Ed448N
        | matter::Codex::Ed448_Seed
        | matter::Codex::Ed448_Sig => ed448::generate(),
        _ => err!(Error::UnexpectedCode(code.to_string())),
    }
}

pub(crate) fn public_key(code: &str, private_key: &[u8]) -> Result<Vec<u8>> {
    match code {
        matter::Codex::Ed25519
        | matter::Codex::Ed25519N
        | matter::Codex::Ed25519_Seed
        | matter::Codex::Ed25519_Sig => ed25519::public_key(private_key),
        matter::Codex::ECDSA_256k1
        | matter::Codex::ECDSA_256k1N
        | matter::Codex::ECDSA_256k1_Seed
        | matter::Codex::ECDSA_256k1_Sig => ecdsa_256k1::public_key(private_key),
        matter::Codex::ECDSA_256r1
        | matter::Codex::ECDSA_256r1N
        | matter::Codex::ECDSA_256r1_Seed
        | matter::Codex::ECDSA_256r1_Sig => ecdsa_256r1::public_key(private_key),
        matter::Codex::Ed448
        | matter::Codex::Ed448N
        | matter::Codex::Ed448_Seed
        | matter::Codex::Ed448_Sig => ed448::public_key(private_key),
        matter::Codex::X448 => ed448::x448_public_key(private_key),
        _ => err!(Error::UnexpectedCode(code.to_string())),
    }
}

/// Convert Ed448 public key to X448 public key
/// X448 is the Montgomery curve form used for Diffie-Hellman key exchange
#[allow(dead_code)]
pub(crate) fn ed448_to_x448(ed448_pubkey: &[u8]) -> Result<Vec<u8>> {
    ed448::ed448_to_x448(ed448_pubkey)
}

pub(crate) fn sign(code: &str, private_key: &[u8], ser: &[u8]) -> Result<Vec<u8>> {
    match code {
        matter::Codex::Ed25519
        | matter::Codex::Ed25519N
        | matter::Codex::Ed25519_Seed
        | matter::Codex::Ed25519_Sig => ed25519::sign(private_key, ser),
        matter::Codex::ECDSA_256k1
        | matter::Codex::ECDSA_256k1N
        | matter::Codex::ECDSA_256k1_Seed
        | matter::Codex::ECDSA_256k1_Sig => ecdsa_256k1::sign(private_key, ser),
        matter::Codex::ECDSA_256r1
        | matter::Codex::ECDSA_256r1N
        | matter::Codex::ECDSA_256r1_Seed
        | matter::Codex::ECDSA_256r1_Sig => ecdsa_256r1::sign(private_key, ser),
        matter::Codex::Ed448
        | matter::Codex::Ed448N
        | matter::Codex::Ed448_Seed
        | matter::Codex::Ed448_Sig => ed448::sign(private_key, ser),
        _ => err!(Error::UnexpectedCode(code.to_string())),
    }
}

pub(crate) fn verify(code: &str, public_key: &[u8], sig: &[u8], ser: &[u8]) -> Result<bool> {
    match code {
        matter::Codex::Ed25519
        | matter::Codex::Ed25519N
        | matter::Codex::Ed25519_Seed
        | matter::Codex::Ed25519_Sig => ed25519::verify(public_key, sig, ser),
        matter::Codex::ECDSA_256k1
        | matter::Codex::ECDSA_256k1N
        | matter::Codex::ECDSA_256k1_Seed
        | matter::Codex::ECDSA_256k1_Sig => ecdsa_256k1::verify(public_key, sig, ser),
        matter::Codex::ECDSA_256r1
        | matter::Codex::ECDSA_256r1N
        | matter::Codex::ECDSA_256r1_Seed
        | matter::Codex::ECDSA_256r1_Sig => ecdsa_256r1::verify(public_key, sig, ser),
        matter::Codex::Ed448
        | matter::Codex::Ed448N
        | matter::Codex::Ed448_Seed
        | matter::Codex::Ed448_Sig => ed448::verify(public_key, sig, ser),
        _ => err!(Error::UnexpectedCode(code.to_string())),
    }
}

mod ed25519 {
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
    use rand_core::OsRng;

    use crate::error::Result;

    pub(crate) fn generate() -> Result<Vec<u8>> {
        let mut csprng = OsRng {};
        let mut private_key = SigningKey::generate(&mut csprng);
        let verifying_key = private_key.verifying_key();
        let mut weak = verifying_key.is_weak();

        while weak {
            private_key = SigningKey::generate(&mut csprng);
            let verifying_key = private_key.verifying_key();
            weak = verifying_key.is_weak();
        }

        Ok(private_key.to_bytes().to_vec())
    }

    pub(crate) fn public_key(private_key: &[u8]) -> Result<Vec<u8>> {
        let private_key = SigningKey::from_bytes(&private_key[..32].try_into()?);
        let public_key: VerifyingKey = (&private_key).into();
        Ok(public_key.as_bytes().to_vec())
    }

    pub(crate) fn sign(private_key: &[u8], ser: &[u8]) -> Result<Vec<u8>> {
        let private_key = SigningKey::from_bytes(private_key.try_into()?);
        Ok(private_key.sign(ser).to_bytes().to_vec())
    }

    pub(crate) fn verify(public_key: &[u8], sig: &[u8], ser: &[u8]) -> Result<bool> {
        let public_key = VerifyingKey::from_bytes(public_key.try_into()?)?;
        let signature = Signature::from_bytes(sig.try_into()?);

        match public_key.verify(ser, &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

mod ecdsa_256k1 {
    use k256::ecdsa::{
        signature::{RandomizedSigner, Verifier},
        Signature, SigningKey, VerifyingKey,
    };
    use rand_core::OsRng;

    use crate::error::Result;

    pub(crate) fn generate() -> Result<Vec<u8>> {
        let mut csprng = OsRng {};
        let private_key = SigningKey::random(&mut csprng);
        Ok(private_key.to_bytes().to_vec())
    }

    pub(crate) fn public_key(private_key: &[u8]) -> Result<Vec<u8>> {
        let private_key = SigningKey::from_slice(private_key)?;
        let public_key = VerifyingKey::from(private_key);
        Ok(public_key.to_encoded_point(true).as_bytes().to_vec())
    }

    pub(crate) fn sign(private_key: &[u8], ser: &[u8]) -> Result<Vec<u8>> {
        let private_key = SigningKey::from_slice(private_key)?;
        let signature: Signature = private_key.sign_with_rng(&mut OsRng, ser);
        Ok(signature.to_vec())
    }

    pub(crate) fn verify(public_key: &[u8], sig: &[u8], ser: &[u8]) -> Result<bool> {
        let public_key = VerifyingKey::from_sec1_bytes(public_key)?;
        let signature = Signature::try_from(sig)?;

        match public_key.verify(ser, &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

mod ecdsa_256r1 {
    use p256::ecdsa::{
        signature::{RandomizedSigner, Verifier},
        Signature, SigningKey, VerifyingKey,
    };
    use rand_core::OsRng;

    use crate::error::Result;

    pub(crate) fn generate() -> Result<Vec<u8>> {
        let mut csprng = OsRng {};
        let private_key = SigningKey::random(&mut csprng);
        Ok(private_key.to_bytes().to_vec())
    }

    pub(crate) fn public_key(private_key: &[u8]) -> Result<Vec<u8>> {
        let private_key = SigningKey::from_slice(private_key)?;
        let public_key = VerifyingKey::from(private_key);
        Ok(public_key.to_encoded_point(true).as_bytes().to_vec())
    }

    pub(crate) fn sign(private_key: &[u8], ser: &[u8]) -> Result<Vec<u8>> {
        let private_key = SigningKey::from_slice(private_key)?;
        let signature: Signature = private_key.sign_with_rng(&mut OsRng, ser);
        Ok(signature.to_vec())
    }

    pub(crate) fn verify(public_key: &[u8], sig: &[u8], ser: &[u8]) -> Result<bool> {
        let public_key = VerifyingKey::from_sec1_bytes(public_key)?;
        let signature = Signature::try_from(sig)?;

        match public_key.verify(ser, &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

mod ed448 {
    use ed448_goldilocks_plus::{Signature, SigningKey, VerifyingKey};
    use rand_core::OsRng;

    use crate::error::Result;

    /// Ed448 seed/private key size is 57 bytes
    const ED448_SEED_SIZE: usize = 57;
    /// Ed448 public key size is 57 bytes
    const ED448_PUBLIC_KEY_SIZE: usize = 57;
    /// Ed448 signature size is 114 bytes
    const ED448_SIGNATURE_SIZE: usize = 114;
    /// X448 public key size is 56 bytes
    #[allow(dead_code)]
    const X448_PUBLIC_KEY_SIZE: usize = 56;

    pub(crate) fn generate() -> Result<Vec<u8>> {
        let signing_key = SigningKey::generate(&mut OsRng);
        Ok(signing_key.to_bytes().to_vec())
    }

    pub(crate) fn public_key(private_key: &[u8]) -> Result<Vec<u8>> {
        if private_key.len() < ED448_SEED_SIZE {
            return Err(anyhow::anyhow!(
                "Ed448 private key must be {} bytes, got {}",
                ED448_SEED_SIZE,
                private_key.len()
            ));
        }
        let seed: [u8; ED448_SEED_SIZE] = private_key[..ED448_SEED_SIZE].try_into()?;
        let signing_key = SigningKey::try_from(&seed[..])
            .map_err(|e| anyhow::anyhow!("Ed448 invalid seed: {}", e))?;
        let verifying_key = signing_key.verifying_key();
        Ok(verifying_key.to_bytes().to_vec())
    }

    /// Derive X448 public key from Ed448 private key (seed)
    /// X448 is the Montgomery form of Curve448, used for key exchange (Diffie-Hellman)
    pub(crate) fn x448_public_key(private_key: &[u8]) -> Result<Vec<u8>> {
        if private_key.len() < ED448_SEED_SIZE {
            return Err(anyhow::anyhow!(
                "Ed448 private key must be {} bytes, got {}",
                ED448_SEED_SIZE,
                private_key.len()
            ));
        }
        let seed: [u8; ED448_SEED_SIZE] = private_key[..ED448_SEED_SIZE].try_into()?;
        let signing_key = SigningKey::try_from(&seed[..])
            .map_err(|e| anyhow::anyhow!("Ed448 invalid seed: {}", e))?;
        let verifying_key = signing_key.verifying_key();
        // Convert Ed448 public key (EdwardsPoint) to X448 (MontgomeryPoint)
        let edwards_point = verifying_key.to_edwards();
        let montgomery_point = edwards_point.to_montgomery();
        Ok(montgomery_point.as_bytes().to_vec())
    }

    /// Convert Ed448 public key bytes to X448 public key bytes
    #[allow(dead_code)]
    pub(crate) fn ed448_to_x448(ed448_pubkey: &[u8]) -> Result<Vec<u8>> {
        if ed448_pubkey.len() != ED448_PUBLIC_KEY_SIZE {
            return Err(anyhow::anyhow!(
                "Ed448 public key must be {} bytes, got {}",
                ED448_PUBLIC_KEY_SIZE,
                ed448_pubkey.len()
            ));
        }
        let pk_bytes: [u8; ED448_PUBLIC_KEY_SIZE] =
            ed448_pubkey[..ED448_PUBLIC_KEY_SIZE].try_into()?;
        let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid Ed448 public key: {:?}", e))?;
        // Convert Ed448 public key (EdwardsPoint) to X448 (MontgomeryPoint)
        let edwards_point = verifying_key.to_edwards();
        let montgomery_point = edwards_point.to_montgomery();
        Ok(montgomery_point.as_bytes().to_vec())
    }

    pub(crate) fn sign(private_key: &[u8], ser: &[u8]) -> Result<Vec<u8>> {
        if private_key.len() < ED448_SEED_SIZE {
            return Err(anyhow::anyhow!(
                "Ed448 private key must be {} bytes, got {}",
                ED448_SEED_SIZE,
                private_key.len()
            ));
        }
        let seed: [u8; ED448_SEED_SIZE] = private_key[..ED448_SEED_SIZE].try_into()?;
        let signing_key = SigningKey::try_from(&seed[..])
            .map_err(|e| anyhow::anyhow!("Ed448 invalid seed: {}", e))?;
        // Ed448 uses pure EdDSA (no prehashing), with empty context
        let signature = signing_key.sign_raw(ser);
        Ok(signature.to_bytes().to_vec())
    }

    pub(crate) fn verify(public_key: &[u8], sig: &[u8], ser: &[u8]) -> Result<bool> {
        if public_key.len() != ED448_PUBLIC_KEY_SIZE {
            return Err(anyhow::anyhow!(
                "Ed448 public key must be {} bytes, got {}",
                ED448_PUBLIC_KEY_SIZE,
                public_key.len()
            ));
        }
        if sig.len() != ED448_SIGNATURE_SIZE {
            return Err(anyhow::anyhow!(
                "Ed448 signature must be {} bytes, got {}",
                ED448_SIGNATURE_SIZE,
                sig.len()
            ));
        }

        let pk_bytes: [u8; ED448_PUBLIC_KEY_SIZE] =
            public_key[..ED448_PUBLIC_KEY_SIZE].try_into()?;
        let verifying_key = match VerifyingKey::from_bytes(&pk_bytes) {
            Ok(vk) => vk,
            Err(_) => return Ok(false),
        };

        let sig_bytes: [u8; ED448_SIGNATURE_SIZE] = sig[..ED448_SIGNATURE_SIZE].try_into()?;
        let signature = match Signature::from_bytes(&sig_bytes) {
            Ok(s) => s,
            Err(_) => return Ok(false),
        };

        // Ed448 uses pure EdDSA (no prehashing), with empty context
        Ok(verifying_key.verify_raw(&signature, ser).is_ok())
    }
}

#[cfg(test)]
mod test {
    use crate::core::matter::tables as matter;
    use crate::crypto::sign;
    use rstest::rstest;

    #[rstest]
    fn end_to_end(
        #[values(
            matter::Codex::Ed25519,
            matter::Codex::ECDSA_256k1,
            matter::Codex::ECDSA_256r1,
            matter::Codex::Ed448
        )]
        code: &str,
    ) {
        let ser = b"abcdefghijklmnopqrstuvwxyz";
        let private_key = sign::generate(code).unwrap();
        let signature = sign::sign(code, &private_key, ser).unwrap();
        let public_key = sign::public_key(code, &private_key).unwrap();
        assert!(sign::verify(code, &public_key, &signature, ser).unwrap());
    }

    #[test]
    fn ed448_key_sizes() {
        let private_key = sign::generate(matter::Codex::Ed448).unwrap();
        assert_eq!(private_key.len(), 57); // Ed448 seed size
        let public_key = sign::public_key(matter::Codex::Ed448, &private_key).unwrap();
        assert_eq!(public_key.len(), 57); // Ed448 public key size
        let signature = sign::sign(matter::Codex::Ed448, &private_key, b"test").unwrap();
        assert_eq!(signature.len(), 114); // Ed448 signature size
    }

    #[test]
    fn ed448_roundtrip() {
        use ed448_goldilocks_plus::{Signature, SigningKey, VerifyingKey};

        // Test using ed448-goldilocks-plus directly
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        let verifying_key = signing_key.verifying_key();
        let message = b"abcdefghijklmnopqrstuvwxyz";
        let sig = signing_key.sign_raw(message);
        let result = verifying_key.verify_raw(&sig, message);
        println!("Direct ed448-goldilocks-plus test: {:?}", result);
        assert!(result.is_ok());

        // Now test via our wrapper
        let private_key_bytes = signing_key.to_bytes();
        let public_key_bytes = verifying_key.to_bytes();
        let signature_bytes = sig.to_bytes();

        println!("private_key len: {}", private_key_bytes.len());
        println!("public_key len: {}", public_key_bytes.len());
        println!("signature len: {}", signature_bytes.len());

        // First verify we can recreate the public key from bytes
        let recreated_pubkey = VerifyingKey::from_bytes(&public_key_bytes).unwrap();
        let recreated_sig = Signature::from_bytes(&signature_bytes).unwrap();
        let result = recreated_pubkey.verify_raw(&recreated_sig, message);
        println!("Recreated pubkey with recreated sig verify: {:?}", result);
        assert!(result.is_ok());

        // Verify using our wrapper
        let result =
            sign::verify(matter::Codex::Ed448, &public_key_bytes, &signature_bytes, message)
                .unwrap();
        println!("Wrapper verify result: {}", result);
        assert!(result);
    }

    #[test]
    fn ed448_verification_failure() {
        let private_key = sign::generate(matter::Codex::Ed448).unwrap();
        let public_key = sign::public_key(matter::Codex::Ed448, &private_key).unwrap();
        let signature = sign::sign(matter::Codex::Ed448, &private_key, b"original").unwrap();
        // Verification should fail for different message
        assert!(!sign::verify(matter::Codex::Ed448, &public_key, &signature, b"different").unwrap());
    }

    #[test]
    fn unhappy_paths() {
        let code = matter::Codex::SHA3_256;
        assert!(sign::generate(code).is_err());
        assert!(sign::public_key(code, &[]).is_err());
        assert!(sign::sign(code, &[], &[]).is_err());
        assert!(sign::verify(code, &[], &[], &[]).is_err());
    }

    #[test]
    fn ed448_unhappy_paths() {
        // Private key too short
        assert!(sign::public_key(matter::Codex::Ed448, &[0u8; 32]).is_err());
        assert!(sign::sign(matter::Codex::Ed448, &[0u8; 32], b"test").is_err());
        // Public key wrong size
        assert!(sign::verify(matter::Codex::Ed448, &[0u8; 32], &[0u8; 114], b"test").is_err());
        // Signature wrong size
        assert!(sign::verify(matter::Codex::Ed448, &[0u8; 57], &[0u8; 64], b"test").is_err());
    }

    #[test]
    fn x448_key_derivation() {
        // Generate Ed448 key pair
        let private_key = sign::generate(matter::Codex::Ed448).unwrap();
        assert_eq!(private_key.len(), 57); // Ed448 seed size

        // Derive X448 public key from Ed448 private key
        let x448_pubkey = sign::public_key(matter::Codex::X448, &private_key).unwrap();
        assert_eq!(x448_pubkey.len(), 56); // X448 public key is 56 bytes

        // Also test the direct conversion function
        let ed448_pubkey = sign::public_key(matter::Codex::Ed448, &private_key).unwrap();
        let x448_from_pubkey = sign::ed448_to_x448(&ed448_pubkey).unwrap();
        assert_eq!(x448_from_pubkey.len(), 56);

        // Both methods should produce the same X448 key
        assert_eq!(x448_pubkey, x448_from_pubkey);
    }

    #[test]
    fn x448_unhappy_paths() {
        // Private key too short for X448 derivation
        assert!(sign::public_key(matter::Codex::X448, &[0u8; 32]).is_err());

        // Invalid Ed448 public key for conversion
        assert!(sign::ed448_to_x448(&[0u8; 32]).is_err()); // Wrong size
    }
}
