use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};

fn main() -> Result<(), oqs::Error> {
    // Signature (SPHINCS+)
    let signer = oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa65Ipd)?;
    let (sig_pk, sig_sk) = signer.keypair()?;

    let sig_pk_b64 = encode_b64(sig_pk.as_ref());
    let sig_sk_b64 = encode_b64(sig_sk.as_ref());

    println!("Signature Public Key: {}", &sig_pk_b64);
    println!("Signature Secret Key: {}", &sig_sk_b64);

    // Simulate a payload
    let payload = b"Hello, World!";

    let signature = signer.sign(payload, &sig_sk)?;

    let signature_b64 = encode_b64(signature.as_ref());

    println!("Signature: {}", &signature_b64);

    signer.verify(payload, &signature, &sig_pk)?;

    println!("Signature verified!");

    let modfied_payload = b"Hello, new World!";
    signer.verify(modfied_payload, &signature, &sig_pk)?;

    // JWT-like token type
    // {HEADER}.{PAYLOAD}.{SIGNATURE}

    Ok(())
}

fn encode_b64(data: &[u8]) -> String {
    general_purpose::STANDARD_NO_PAD.encode(data)
}

fn decode_b64(data: &str) -> Vec<u8> {
    general_purpose::STANDARD_NO_PAD.decode(data).unwrap()
}

#[derive(Debug, Clone, Copy)]
struct CompactUUID(uuid::Uuid);

impl CompactUUID {
    fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    fn to_string(&self) -> String {
        self.0.simple().to_string().replace("-", "")
    }

    /// Parse a string into an API key
    pub fn from_string(input: impl Into<String>) -> Result<Self, String> {
        let input: String = input.into();
        // UUID dash is replaced with empty string, so we need to insert it back
        // ex: cd427fdabb04495688aa97422a3f0320
        //     cd427fda-bb04-4956-88aa-97422a3f0320
        let uuid_a = input.get(0..8).ok_or("Invalid UUID (incomplete part A)")?;
        let uuid_b = input.get(8..12).ok_or("Invalid UUID (incomplete part B)")?;
        let uuid_c = input
            .get(12..16)
            .ok_or("Invalid UUID (incomplete part C)")?;
        let uuid_d = input
            .get(16..20)
            .ok_or("Invalid UUID (incomplete part D)")?;
        let uuid_e = input
            .get(20..32)
            .ok_or("Invalid UUID (incomplete part E)")?;
        let rfmt_s = format!("{}-{}-{}-{}-{}", uuid_a, uuid_b, uuid_c, uuid_d, uuid_e);

        let inner = uuid::Uuid::parse_str(&rfmt_s).map_err(|_| "Invalid UUID")?;
        Ok(CompactUUID(inner))
    }
}

impl Serialize for CompactUUID {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CompactUUID {
    fn deserialize<D>(deserializer: D) -> Result<CompactUUID, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        CompactUUID::from_string(s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Header {
    kalg: oqs::kem::Algorithm,
    salg: oqs::sig::Algorithm,
    // The signature location saved on the server, this is random token or something
    loc: CompactUUID,
}

impl Header {
    fn new(kalg: oqs::kem::Algorithm, salg: oqs::sig::Algorithm) -> Self {
        Self {
            kalg,
            salg,
            loc: CompactUUID::new(),
        }
    }

    fn get_loc(&self) -> CompactUUID {
        self.loc
    }
}
