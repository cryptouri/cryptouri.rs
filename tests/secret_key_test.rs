macro_rules! secret_key_test {
    ($name:ident, $keytype:ident, $uri:expr, $dasherized:expr, $bytes:expr) => {
        mod $name {
            use cryptouri::secret_key::$keytype;
            use cryptouri::{CryptoUri, Encodable};
            use std::convert::TryFrom;

            #[test]
            fn parse_uri() {
                let key = CryptoUri::parse_uri($uri).unwrap();
                assert_eq!(key.secret_key().unwrap().$name().unwrap().as_ref(), $bytes);
            }

            #[test]
            fn parse_dasherized() {
                let key = CryptoUri::parse_dasherized($dasherized).unwrap();
                assert_eq!(key.secret_key().unwrap().$name().unwrap().as_ref(), $bytes);
            }

            #[test]
            fn serialize_uri() {
                let key = $keytype::try_from($bytes.as_ref()).unwrap();
                assert_eq!(&key.to_uri_string(), $uri);
            }

            #[test]
            fn serialize_dasherized() {
                let key = $keytype::try_from($bytes.as_ref()).unwrap();
                assert_eq!(&key.to_dasherized_string(), $dasherized);
            }
        }
    };
}

// AES-128-GCM secret key test
//
// Uses key from NIST AES-GCM test vector: gcmEncryptExtIV128.rsp (Count = 0)
// http://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmtestvectors.zip
secret_key_test!(
    aes128gcm_key,
    Aes128GcmKey,
    "crypto:sec:key:aes128gcm:z965e4e2ascfhaf0w6rjzt5f2u9vnfgp",
    "crypto-sec-key-aes128gcm-z965e4e2ascfhaf0w6rjzt5f2u8fa92h",
    &[17, 117, 76, 215, 42, 236, 48, 155, 245, 47, 118, 135, 33, 46, 137, 87]
);

// AES-256-GCM secret key test
//
// Uses key from NIST AES-GCM test vector: gcmEncryptExtIV256.rsp (Count = 0)
// http://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmtestvectors.zip
secret_key_test!(
    aes256gcm_key,
    Aes256GcmKey,
    "crypto:sec:key:aes256gcm:k5k9qk3h678d5hwnfusvyf2qagd4393ulrjmlrl6shulyjf9qk6qh0amxk",
    "crypto-sec-key-aes256gcm-k5k9qk3h678d5hwnfusvyf2qagd4393ulrjmlrl6shulyjf9qk6q4tmp64",
    &[
        181, 44, 80, 90, 55, 215, 142, 218, 93, 211, 79, 32, 194, 37, 64, 234, 27, 88, 150, 60,
        248, 229, 191, 143, 250, 133, 249, 242, 73, 37, 5, 180
    ]
);

// Ed25519 secret key test
//
// Uses secret scalar from RFC 8032 test vector: "TEST 1" secret key
// https://tools.ietf.org/html/rfc8032#section-7.1
secret_key_test!(
    ed25519_key,
    Ed25519SecretKey,
    "crypto:sec:key:ed25519:n4smr800l4dxpw5yft6f9mpvc3zyn3tf0vexjxts8wkqx89w0asq7zn3zk",
    "crypto-sec-key-ed25519-n4smr800l4dxpw5yft6f9mpvc3zyn3tf0vexjxts8wkqx89w0asqg38w5j",
    &[
        157, 97, 177, 157, 239, 253, 90, 96, 186, 132, 74, 244, 146, 236, 44, 196, 68, 73, 197,
        105, 123, 50, 105, 25, 112, 59, 172, 3, 28, 174, 127, 96
    ]
);

// HKDF-SHA-256 secret key test
secret_key_test!(
    hkdfsha256_key,
    HkdfSha256Key,
    "crypto:sec:key:hkdfsha256:pv9skzctpv9skzctpv9skzctpv9skzctpv9skzctpv9skzctpv9srmexrr",
    "crypto-sec-key-hkdfsha256-pv9skzctpv9skzctpv9skzctpv9skzctpv9skzctpv9skzctpv9s5czenw",
    &[
        0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb,
        0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb
    ]
);

/// Tests for serializing a combined HKDF-SHA-256+AES-256-GCM key
mod hkdfsha256_aes256gcm_key {
    use cryptouri::{
        secret_key::{Algorithm, HkdfSha256Key},
        Encodable,
    };

    const KEY_BYTES: &[u8] = &[
        0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb,
        0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb,
    ];

    /// Test for serializing `hkdfsha256+aes256gcm`
    #[test]
    fn serialize_uri() {
        let key = HkdfSha256Key::new(KEY_BYTES, Algorithm::Aes256Gcm).unwrap();

        assert_eq!(
            key.to_uri_string(),
            "crypto:sec:key:hkdfsha256+aes256gcm:pv9skzctpv9skzctpv9skzctpv9skzctpv9skzctpv9skzctpv9sxm0sk0"
        );
    }

    /// Test for serializing `hkdfsha256_aes256gcm`
    #[test]
    fn serialize_dasherized() {
        let key = HkdfSha256Key::new(KEY_BYTES, Algorithm::Aes256Gcm).unwrap();

        assert_eq!(
            key.to_dasherized_string(),
            "crypto-sec-key-hkdfsha256_aes256gcm-pv9skzctpv9skzctpv9skzctpv9skzctpv9skzctpv9skzctpv9sjrz6qp"
        );
    }
}
