//! Legacy ZeroTier membership credentials.
//!
//! ZeroTier authorizes network membership with two credentials:
//!
//! - The **Certificate of Membership** (COM) proves that a node belongs to a
//!   network. It is issued by the network's controller and is a **bearer
//!   capability**: possession alone grants access, with no proof that the
//!   holder possesses the corresponding private key.
//! - The **Certificate of Ownership** (COO) proves that a node controls the
//!   MAC address and IP address it claims. It is self-signed and is
//!   presented alongside the COM.
//!
//! # Why this matters for ZT-next
//!
//! ZT-next replaces the COM with a short-lived, key-bound credential. To
//! interoperate, a ZT-next node that joins a ZeroTier network must still
//! present a valid COM — there is no way to substitute a stronger
//! credential, because ZeroTier peers will not understand it.
//!
//! The credential formats are therefore reproduced exactly, with the
//! security properties documented rather than hidden.

use crate::zerotier::{LegacyAddress, LegacyIdentity, LegacySignature};

/// Maximum number of qualifiers a COM may carry.
pub const MAX_QUALIFIERS: usize = 8;

/// Length of a ZeroTier address.
pub const ADDRESS_LEN: usize = 5;

/// Length of a ZeroTier signature.
pub const SIGNATURE_LEN: usize = 96;

/// The type byte that prefixes a serialized COM.
pub const COM_TYPE: u8 = 1;

/// The type byte that prefixes a serialized COO.
pub const COO_TYPE: u8 = 1;

/// The reserved qualifier identifier for the credential timestamp.
pub const COM_RESERVED_ID_TIMESTAMP: u64 = 0;
/// The reserved qualifier identifier for the network ID.
pub const COM_RESERVED_ID_NETWORK_ID: u64 = 1;
/// The reserved qualifier identifier for the address the COM was issued to.
pub const COM_RESERVED_ID_ISSUED_TO: u64 = 2;

/// Pack a five-byte ZeroTier address into a 64-bit integer.
///
/// The address occupies the **low** five bytes of the integer and is read as
/// a big-endian value, so `62 82 26 b5 f7` becomes `0x000000628226b5f7`.
pub fn address_to_u64(address: &LegacyAddress) -> u64 {
    let mut out = [0u8; 8];
    out[8 - ADDRESS_LEN..].copy_from_slice(address.as_bytes());
    u64::from_be_bytes(out)
}

/// A qualifier in a Certificate of Membership.
///
/// A qualifier asserts a fact about the member's presence in the network,
/// such as the timestamp it was last seen or the version it is running.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Qualifier {
    /// The qualifier identifier.
    pub id: u64,
    /// The qualifier value.
    pub value: u64,
    /// The maximum clock drift tolerated for this qualifier.
    pub max_delta: u64,
}

impl Qualifier {
    /// Build a qualifier.
    pub fn new(id: u64, value: u64, max_delta: u64) -> Self {
        Self {
            id,
            value,
            max_delta,
        }
    }
}

/// A Certificate of Membership.
///
/// This is ZeroTier's network membership credential. It is issued by a
/// network controller and proves only that the issuer vouched for the
/// member; it is not bound to the member's private key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateOfMembership {
    qualifiers: Vec<Qualifier>,
    signed_by: LegacyAddress,
    signature: Option<LegacySignature>,
}

impl CertificateOfMembership {
    /// Build an unsigned COM.
    pub fn new(qualifiers: Vec<Qualifier>) -> Self {
        Self {
            qualifiers,
            signed_by: LegacyAddress::from_bytes(&[0u8; ADDRESS_LEN]),
            signature: None,
        }
    }

    /// Build a COM the way a network controller does.
    ///
    /// The credential carries seven qualifiers: the timestamp, the network
    /// ID, the address it was issued to, and four words of a hash of the
    /// member's identity. The identity hash hardens the credential so that
    /// it cannot be replayed by a node with a different key.
    pub fn issue(
        timestamp: u64,
        timestamp_max_delta: u64,
        network_id: u64,
        issued_to: &LegacyIdentity,
    ) -> Self {
        let issued_to_address = issued_to.address();
        let identity_hash = issued_to.public_key_hash();

        let mut qualifiers = Vec::with_capacity(7);
        qualifiers.push(Qualifier::new(
            COM_RESERVED_ID_TIMESTAMP,
            timestamp,
            timestamp_max_delta,
        ));
        qualifiers.push(Qualifier::new(COM_RESERVED_ID_NETWORK_ID, network_id, 0));
        qualifiers.push(Qualifier::new(
            COM_RESERVED_ID_ISSUED_TO,
            address_to_u64(&issued_to_address),
            u64::MAX,
        ));
        // The identity hash is six 64-bit words. ZeroTier byte-swaps the
        // first four before storing them, so they are read big endian here.
        for index in 0..4usize {
            let offset = index * 8;
            let mut word = [0u8; 8];
            word.copy_from_slice(&identity_hash[offset..offset + 8]);
            qualifiers.push(Qualifier::new(
                index as u64 + 3,
                u64::from_be_bytes(word),
                u64::MAX,
            ));
        }

        Self::new(qualifiers)
    }

    /// The qualifiers.
    pub fn qualifiers(&self) -> &[Qualifier] {
        &self.qualifiers
    }

    /// Look up a qualifier by identifier.
    pub fn qualifier(&self, id: u64) -> Option<&Qualifier> {
        self.qualifiers.iter().find(|qualifier| qualifier.id == id)
    }

    /// The address of the controller that signed this credential.
    pub fn signed_by(&self) -> LegacyAddress {
        self.signed_by
    }

    /// The signature, if the credential has been signed.
    pub fn signature(&self) -> Option<&LegacySignature> {
        self.signature.as_ref()
    }

    /// Whether the credential carries a signature.
    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// The bytes covered by the COM signature.
    ///
    /// ZeroTier signs the qualifiers as a flat sequence of big-endian 64-bit
    /// triples: identifier, value, and maximum delta.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.qualifiers.len() * 24);
        for qualifier in &self.qualifiers {
            out.extend_from_slice(&qualifier.id.to_be_bytes());
            out.extend_from_slice(&qualifier.value.to_be_bytes());
            out.extend_from_slice(&qualifier.max_delta.to_be_bytes());
        }
        out
    }

    /// Sign the credential with a controller identity.
    pub fn sign(&mut self, controller: &LegacyIdentity) {
        self.signature = Some(controller.sign(&self.signing_bytes()));
        self.signed_by = controller.address();
    }

    /// Verify the signature against a controller's Ed25519 public key.
    pub fn verify(&self, ed25519_public_key: &[u8; 32]) -> bool {
        let Some(signature) = &self.signature else {
            return false;
        };
        LegacyIdentity::verify(ed25519_public_key, &self.signing_bytes(), signature)
    }

    /// Serialize the credential.
    ///
    /// The wire format is:
    ///
    /// ```text
    /// version (1)
    /// qualifier count (2, big endian)
    /// qualifiers (24 bytes each: id, value, max_delta)
    /// signed-by address (5)
    /// signature (96, only when signed)
    /// ```
    pub fn serialize(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(3 + self.qualifiers.len() * 24 + ADDRESS_LEN + SIGNATURE_LEN);
        out.push(COM_TYPE);
        out.extend_from_slice(&(self.qualifiers.len() as u16).to_be_bytes());
        for qualifier in &self.qualifiers {
            out.extend_from_slice(&qualifier.id.to_be_bytes());
            out.extend_from_slice(&qualifier.value.to_be_bytes());
            out.extend_from_slice(&qualifier.max_delta.to_be_bytes());
        }
        // The signer address and signature are only present once the
        // credential has been signed.
        if let Some(signature) = &self.signature {
            out.extend_from_slice(self.signed_by.as_bytes());
            out.extend_from_slice(signature.as_bytes());
        }
        out
    }

    /// Parse a credential from the wire format.
    pub fn deserialize(bytes: &[u8]) -> Option<CertificateOfMembership> {
        if bytes.len() < 3 {
            return None;
        }
        if bytes[0] != COM_TYPE {
            return None;
        }

        let count = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
        if count > MAX_QUALIFIERS {
            return None;
        }

        let mut offset = 3usize;
        let mut qualifiers = Vec::with_capacity(count);
        let mut last_id = 0u64;

        for _ in 0..count {
            if bytes.len() < offset + 24 {
                return None;
            }
            let id = u64::from_be_bytes(bytes[offset..offset + 8].try_into().ok()?);
            let value = u64::from_be_bytes(bytes[offset + 8..offset + 16].try_into().ok()?);
            let max_delta = u64::from_be_bytes(bytes[offset + 16..offset + 24].try_into().ok()?);
            // Qualifier identifiers must be non-decreasing.
            if id < last_id {
                return None;
            }
            last_id = id;
            qualifiers.push(Qualifier {
                id,
                value,
                max_delta,
            });
            offset += 24;
        }

        // The signer address and signature are present only when the
        // credential has been signed. ZeroTier's signed form always has
        // exactly ADDRESS_LEN + SIGNATURE_LEN bytes left over.
        let mut signed_by = LegacyAddress::from_bytes(&[0u8; ADDRESS_LEN]);
        let mut signature = None;

        if bytes.len() == offset + ADDRESS_LEN + SIGNATURE_LEN {
            let mut address = [0u8; ADDRESS_LEN];
            address.copy_from_slice(&bytes[offset..offset + ADDRESS_LEN]);
            signed_by = LegacyAddress::from_bytes(&address);
            offset += ADDRESS_LEN;

            let mut raw = [0u8; SIGNATURE_LEN];
            raw.copy_from_slice(&bytes[offset..offset + SIGNATURE_LEN]);
            signature = Some(LegacySignature::from_bytes(&raw));
        } else if bytes.len() != offset {
            // Trailing bytes that are neither a signer address nor a
            // signer address plus a signature are malformed.
            return None;
        }

        Some(CertificateOfMembership {
            qualifiers,
            signed_by,
            signature,
        })
    }
}

/// A Certificate of Ownership.
///
/// This proves that a node controls the MAC and IP addresses it claims. It
/// is self-signed by the node, so it carries the node's own public key set.
///
/// The wire layout is:
///
/// ```text
/// network id (8) │ timestamp (8) │ flags (8) │ id (4) │ thing count (2)
/// things (1 + 16 bytes each) │ issued to (5) │ signed by (5)
/// signature type (1) │ signature length (2) │ signature (96)
/// additional fields length (2)
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateOfOwnership {
    network_id: u64,
    timestamp: u64,
    flags: u64,
    id: u32,
    things: Vec<OwnedThing>,
    issued_to: LegacyAddress,
    signed_by: LegacyAddress,
    signature: Option<LegacySignature>,
}

/// Maximum size of a thing's value.
pub const MAX_THING_VALUE_SIZE: usize = 16;

/// Maximum number of things a Certificate of Ownership may claim.
pub const MAX_THINGS: usize = 16;

/// A claim made by a Certificate of Ownership.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedThing {
    /// The thing type.
    pub thing_type: u8,
    /// The thing's value.
    pub value: Vec<u8>,
}

/// The thing type for a MAC address.
pub const THING_MAC: u8 = 1;
/// The thing type for an IP address.
pub const THING_IP: u8 = 2;

/// The sentinel that brackets the signed portion of a COO.
const COO_SIGNING_SENTINEL: u64 = 0x7f7f_7f7f_7f7f_7f7f;

impl CertificateOfOwnership {
    /// Build an unsigned COO.
    pub fn new(
        network_id: u64,
        timestamp: u64,
        flags: u64,
        id: u32,
        things: Vec<OwnedThing>,
        issued_to: LegacyAddress,
        signed_by: LegacyAddress,
    ) -> Self {
        Self {
            network_id,
            timestamp,
            flags,
            id,
            things,
            issued_to,
            signed_by,
            signature: None,
        }
    }

    /// The network this certificate is for.
    pub fn network_id(&self) -> u64 {
        self.network_id
    }

    /// The node identifier this certificate claims.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// The claimed MAC and IP addresses.
    pub fn things(&self) -> &[OwnedThing] {
        &self.things
    }

    /// The address the certificate was issued to.
    pub fn issued_to(&self) -> LegacyAddress {
        self.issued_to
    }

    /// The address that signed the certificate.
    pub fn signed_by(&self) -> LegacyAddress {
        self.signed_by
    }

    /// The signature, if the certificate has been signed.
    pub fn signature(&self) -> Option<&LegacySignature> {
        self.signature.as_ref()
    }

    /// The bytes that are covered by the signature.
    ///
    /// ZeroTier brackets the signed region with a sentinel value so that the
    /// signed bytes cannot be confused with the surrounding structure.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(&COO_SIGNING_SENTINEL.to_be_bytes());
        out.extend_from_slice(&self.network_id.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&(self.things.len() as u16).to_be_bytes());
        for thing in &self.things {
            out.push(thing.thing_type);
            let mut value = thing.value.clone();
            value.resize(MAX_THING_VALUE_SIZE, 0);
            out.extend_from_slice(&value);
        }
        out.extend_from_slice(self.issued_to.as_bytes());
        out.extend_from_slice(self.signed_by.as_bytes());
        out.extend_from_slice(&COO_SIGNING_SENTINEL.to_be_bytes());
        out
    }

    /// Sign the certificate with a node identity.
    pub fn sign(&mut self, identity: &LegacyIdentity) {
        self.signature = Some(identity.sign(&self.signing_bytes()));
    }

    /// Serialize the certificate.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(&self.network_id.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&(self.things.len() as u16).to_be_bytes());
        for thing in &self.things {
            out.push(thing.thing_type);
            let mut value = thing.value.clone();
            value.resize(MAX_THING_VALUE_SIZE, 0);
            out.extend_from_slice(&value);
        }
        out.extend_from_slice(self.issued_to.as_bytes());
        out.extend_from_slice(self.signed_by.as_bytes());
        // The signature block is always present. When the certificate is
        // unsigned the signature bytes are zero.
        out.push(COO_TYPE);
        out.extend_from_slice(&(SIGNATURE_LEN as u16).to_be_bytes());
        match &self.signature {
            Some(signature) => out.extend_from_slice(signature.as_bytes()),
            None => out.extend_from_slice(&[0u8; SIGNATURE_LEN]),
        }
        // Length of additional fields, currently zero.
        out.extend_from_slice(&0u16.to_be_bytes());
        out
    }

    /// Parse a certificate from the wire format.
    pub fn deserialize(bytes: &[u8]) -> Option<CertificateOfOwnership> {
        // network id, timestamp, flags, id (5), thing count
        if bytes.len() < 8 + 8 + 8 + ADDRESS_LEN + 2 {
            return None;
        }
        let mut offset = 0usize;

        let network_id = u64::from_be_bytes(bytes[offset..offset + 8].try_into().ok()?);
        offset += 8;
        let timestamp = u64::from_be_bytes(bytes[offset..offset + 8].try_into().ok()?);
        offset += 8;
        let flags = u64::from_be_bytes(bytes[offset..offset + 8].try_into().ok()?);
        offset += 8;

        let id = u32::from_be_bytes(bytes[offset..offset + 4].try_into().ok()?);
        offset += 4;

        let thing_count = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;

        let mut things = Vec::with_capacity(thing_count);
        for _ in 0..thing_count {
            if bytes.len() < offset + 1 + MAX_THING_VALUE_SIZE {
                return None;
            }
            let thing_type = bytes[offset];
            offset += 1;
            let mut value = bytes[offset..offset + MAX_THING_VALUE_SIZE].to_vec();
            offset += MAX_THING_VALUE_SIZE;
            // Trailing zeroes are padding, not part of the value.
            while value.last() == Some(&0) {
                value.pop();
            }
            things.push(OwnedThing { thing_type, value });
        }

        if bytes.len() < offset + ADDRESS_LEN * 2 {
            return None;
        }
        let mut issued_to_bytes = [0u8; ADDRESS_LEN];
        issued_to_bytes.copy_from_slice(&bytes[offset..offset + ADDRESS_LEN]);
        offset += ADDRESS_LEN;
        let mut signed_by_bytes = [0u8; ADDRESS_LEN];
        signed_by_bytes.copy_from_slice(&bytes[offset..offset + ADDRESS_LEN]);
        offset += ADDRESS_LEN;

        let mut signature = None;
        if bytes.len() >= offset + 1 + 2 + SIGNATURE_LEN && bytes[offset] == COO_TYPE {
            offset += 1;
            let length = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
            offset += 2;
            if length != SIGNATURE_LEN || bytes.len() < offset + SIGNATURE_LEN {
                return None;
            }
            let mut raw = [0u8; SIGNATURE_LEN];
            raw.copy_from_slice(&bytes[offset..offset + SIGNATURE_LEN]);
            signature = Some(LegacySignature::from_bytes(&raw));
        }

        Some(CertificateOfOwnership {
            network_id,
            timestamp,
            flags,
            id,
            things,
            issued_to: LegacyAddress::from_bytes(&issued_to_bytes),
            signed_by: LegacyAddress::from_bytes(&signed_by_bytes),
            signature,
        })
    }

    /// Verify the signature against a node's Ed25519 public key.
    ///
    /// The key is the public half of the node's key set, which ZeroTier
    /// derives from `SHA512(seed)` rather than from the seed directly.
    pub fn verify(&self, ed25519_public_key: &[u8; 32]) -> bool {
        let Some(signature) = &self.signature else {
            return false;
        };
        LegacyIdentity::verify(ed25519_public_key, &self.signing_bytes(), signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zerotier::LegacyAddress;
    use crate::zerotier::KEY_SET_LEN;

    fn address(value: u8) -> LegacyAddress {
        LegacyAddress::from_bytes(&[value; 5])
    }

    #[test]
    fn com_round_trips() {
        let com = CertificateOfMembership::new(vec![
            Qualifier::new(1, 1000, 60),
            Qualifier::new(2, 2000, 60),
        ]);
        let bytes = com.serialize();

        let parsed = CertificateOfMembership::deserialize(&bytes).expect("parse");
        assert_eq!(parsed.qualifiers().len(), 2);
        assert_eq!(parsed.qualifiers()[0].id, 1);
        assert_eq!(parsed.qualifiers()[1].value, 2000);
        assert!(!parsed.is_signed());
    }

    #[test]
    fn com_rejects_a_bad_version() {
        let mut bytes = CertificateOfMembership::new(vec![]).serialize();
        bytes[0] = 2;
        assert!(CertificateOfMembership::deserialize(&bytes).is_none());
    }

    #[test]
    fn com_rejects_too_many_qualifiers() {
        let qualifiers = (0..MAX_QUALIFIERS + 1)
            .map(|i| Qualifier::new(i as u64, 0, 0))
            .collect();
        let bytes = CertificateOfMembership::new(qualifiers).serialize();
        assert!(CertificateOfMembership::deserialize(&bytes).is_none());
    }

    #[test]
    fn com_rejects_out_of_order_qualifiers() {
        let com =
            CertificateOfMembership::new(vec![Qualifier::new(5, 0, 0), Qualifier::new(2, 0, 0)]);
        let bytes = com.serialize();
        assert!(CertificateOfMembership::deserialize(&bytes).is_none());
    }

    #[test]
    fn coo_round_trips() {
        let identity = LegacyIdentity::from_bytes(&[7u8; KEY_SET_LEN]);
        let mut coo = CertificateOfOwnership::new(
            0x1234_5678_9abc_def0,
            1_700_000_000,
            0,
            0x1234_5678,
            vec![
                OwnedThing {
                    thing_type: THING_MAC,
                    value: vec![0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
                },
                OwnedThing {
                    thing_type: THING_IP,
                    value: vec![10, 0, 0, 42],
                },
            ],
            address(0xaa),
            address(0xbb),
        );
        coo.sign(&identity);

        let bytes = coo.serialize();
        let parsed = CertificateOfOwnership::deserialize(&bytes).expect("parse");

        assert_eq!(parsed.network_id(), 0x1234_5678_9abc_def0);
        assert_eq!(parsed.id(), 0x1234_5678);
        assert_eq!(parsed.things().len(), 2);
        assert_eq!(parsed.things()[0].thing_type, THING_MAC);
        assert_eq!(parsed.things()[0].value, vec![0x02, 0, 0, 0, 0, 1]);
        assert_eq!(parsed.things()[1].value, vec![10, 0, 0, 42]);
        assert!(parsed.signature().is_some());
    }

    #[test]
    fn coo_signature_verifies() {
        let identity = LegacyIdentity::from_bytes(&[7u8; KEY_SET_LEN]);
        let mut coo = CertificateOfOwnership::new(
            1,
            1_700_000_000,
            0,
            1,
            vec![],
            address(0xaa),
            address(0xbb),
        );
        coo.sign(&identity);

        assert!(coo.verify(&identity.ed25519_public()));
    }

    #[test]
    fn coo_signature_rejects_tampering() {
        let identity = LegacyIdentity::from_bytes(&[7u8; KEY_SET_LEN]);
        let mut coo = CertificateOfOwnership::new(
            1,
            1_700_000_000,
            0,
            1,
            vec![],
            address(0xaa),
            address(0xbb),
        );
        coo.sign(&identity);

        let mut tampered = coo.clone();
        tampered.timestamp = 1_800_000_000;
        assert!(!tampered.verify(&identity.ed25519_public()));
    }

    #[test]
    fn coo_signing_bytes_are_bracketed() {
        let coo = CertificateOfOwnership::new(1, 2, 3, 0xaa, vec![], address(0xaa), address(0xbb));
        let bytes = coo.signing_bytes();
        assert_eq!(
            u64::from_be_bytes(bytes[..8].try_into().unwrap()),
            COO_SIGNING_SENTINEL
        );
        assert_eq!(
            u64::from_be_bytes(bytes[bytes.len() - 8..].try_into().unwrap()),
            COO_SIGNING_SENTINEL
        );
    }
}
