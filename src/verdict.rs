//! Conservative decoding of the documented wasm-cosign verifier outcome.
//! Only complete, single-line rejection messages from a normally exited verifier
//! can select an operator exception. New/ambiguous diagnostics fail closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signature { Verified, Unsigned, Invalid }

impl Signature {
    pub fn rejected(reason: &[u8]) -> Option<Self> {
        let reason = std::str::from_utf8(reason).ok()?.strip_suffix('\n')?;
        match reason {
            "SIG_001: missing embedded WSEA custom section" => Some(Self::Unsigned),
            "SIG_004: exact module bytes do not match signature"
            | "SIG_003: invalid signature width"
            | "SIG_003: noncanonical ECDSA signature"
            | "SIG_003: noncanonical or small-order Ed25519 signature"
            | "SIG_003: Ed25519 signature does not satisfy the strict encoding profile" => Some(Self::Invalid),
            _ => {
                let algorithm = reason.strip_prefix("SIG_003: invalid ")?.strip_suffix(" digital signature")?;
                matches!(algorithm, "ES256" | "ESP256" | "ES384" | "ESP384" | "ES512" | "ESP512"
                    | "Ed25519" | "PS256" | "PS384" | "PS512" | "RS256" | "RS384" | "RS512")
                    .then_some(Self::Invalid)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn verification_failure_classes_remain_distinct() {
        assert_eq!(Signature::rejected(b"SIG_001: missing embedded WSEA custom section\n"), Some(Signature::Unsigned));
        assert_eq!(Signature::rejected(b"SIG_003: invalid Ed25519 digital signature\n"), Some(Signature::Invalid));
        for message in [b"SIG_004: complete signed module exceeds local size limit\n".as_slice(),
                        b"CERT_004: publisher key has a protected permanent revocation marker\n",
                        b"read error\nSIG_001: missing embedded WSEA custom section\n",
                        b"SIG_003: invalid unknown digital signature\n"] {
            assert_eq!(Signature::rejected(message), None);
        }
    }
}
