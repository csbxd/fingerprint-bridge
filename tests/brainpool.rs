#![cfg(feature = "patched-tls")]

use btls::bn::{BigNum, BigNumContext};
use btls::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use btls::ecdsa::EcdsaSig;
use btls::nid::Nid;
use btls::pkey::PKey;

struct Vector {
    nid: i32,
    private: &'static str,
    public: &'static str,
    peer: &'static str,
    shared: &'static str,
}

// Independent values from RFC 8734 Appendix A, not this implementation.
// These scalar/point tests validate the three RFC 5639 curves without
// advertising their separate TLS named-group identifiers.
const VECTORS: &[Vector] = &[
    Vector {
        nid: 927,
        private: "81DB1EE100150FF2EA338D708271BE38300CB54241D79950F77B063039804F1D",
        public: concat!(
            "04",
            "44106E913F92BC02A1705D9953A8414DB95E1AAA49E81D9E85F929A8E3100BE5",
            "8AB4846F11CACCB73CE49CBDD120F5A900A69FD32C272223F789EF10EB089BDC"
        ),
        peer: concat!(
            "04",
            "8D2D688C6CF93E1160AD04CC4429117DC2C41825E1E9FCA0ADDD34E6F1B39F7B",
            "990C57520812BE512641E47034832106BC7D3E8DD0E4C7F1136D7006547CEC6A"
        ),
        shared: concat!(
            "04",
            "89AFC39D41D3B327814B80940B042590F96556EC91E6AE7939BCE31F3A18BF2B",
            "49C27868F4ECA2179BFD7D59B1E3BF34C1DBDE61AE12931648F43E59632504DE"
        ),
    },
    Vector {
        nid: 931,
        private: concat!(
            "1E20F5E048A5886F1F157C74E91BDE2B98C8B52D58E5003D57053FC4B0BD6",
            "5D6F15EB5D1EE1610DF870795143627D042"
        ),
        public: concat!(
            "04",
            "68B665DD91C195800650CDD363C625F4E742E8134667B767B1B47679358",
            "8F885AB698C852D4A6E77A252D6380FCAF068",
            "55BC91A39C9EC01DEE36017B7D673A931236D2F1F5C83942D049E3FA206",
            "07493E0D038FF2FD30C2AB67D15C85F7FAA59"
        ),
        peer: concat!(
            "04",
            "4D44326F269A597A5B58BBA565DA5556ED7FD9A8A9EB76C25F46DB69D19",
            "DC8CE6AD18E404B15738B2086DF37E71D1EB4",
            "62D692136DE56CBE93BF5FA3188EF58BC8A3A0EC6C1E151A21038A42E91",
            "85329B5B275903D192F8D4E1F32FE9CC78C48"
        ),
        shared: concat!(
            "04",
            "0BD9D3A7EA0B3D519D09D8E48D0785FB744A6B355E6304BC51C229FBBCE2",
            "39BBADF6403715C35D4FB2A5444F575D4F42",
            "0DF213417EBE4D8E40A5F76F66C56470C489A3478D146DECF6DF0D94BAE9",
            "E598157290F8756066975F1DB34B2324B7BD"
        ),
    },
    Vector {
        nid: 933,
        private: concat!(
            "16302FF0DBBB5A8D733DAB7141C1B45ACBC8715939677F6A56850A38BD87B",
            "D59B09E80279609FF333EB9D4C061231FB26F92EEB04982A5F1D1764CAD5766542",
            "2"
        ),
        public: concat!(
            "04",
            "0A420517E406AAC0ACDCE90FCD71487718D3B953EFD7FBEC5F7F27E28C6",
            "149999397E91E029E06457DB2D3E640668B392C2A7E737A7F0BF04436D11640FD0",
            "9FD",
            "72E6882E8DB28AAD36237CD25D580DB23783961C8DC52DFA2EC138AD472",
            "A0FCEF3887CF62B623B2A87DE5C588301EA3E5FC269B373B60724F5E82A6AD147F",
            "DE7"
        ),
        peer: concat!(
            "04",
            "9D45F66DE5D67E2E6DB6E93A59CE0BB48106097FF78A081DE781CDB31FC",
            "E8CCBAAEA8DD4320C4119F1E9CD437A2EAB3731FA9668AB268D871DEDA55A54731",
            "99F",
            "2FDC313095BCDD5FB3A91636F07A959C8E86B5636A1E930E8396049CB48",
            "1961D365CC11453A06C719835475B12CB52FC3C383BCE35E27EF194512B7187628",
            "5FA"
        ),
        shared: concat!(
            "04",
            "A7927098655F1F9976FA50A9D566865DC530331846381C87256BAF322624",
            "4B76D36403C024D7BBF0AA0803EAFF405D3D24F11A9B5C0BEF679FE1454B21C4CD",
            "1F",
            "7DB71C3DEF63212841C463E881BDCF055523BD368240E6C3143BD8DEF8B3",
            "B3223B95E0F53082FF5E412F4222537A43DF1C6D25729DDB51620A832BE6A26680",
            "A2"
        ),
    },
];

#[test]
fn brainpool_matches_rfc8734_public_points_and_shared_secrets() {
    for v in VECTORS {
        let group = EcGroup::from_curve_name(Nid::from_raw(v.nid)).unwrap();
        let private = BigNum::from_hex_str(v.private).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let mut public = EcPoint::new(&group).unwrap();
        public.mul_generator(&group, &private, &mut ctx).unwrap();
        assert_eq!(
            public
                .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
                .unwrap(),
            hex::decode(v.public).unwrap()
        );
        let peer = EcPoint::from_bytes(&group, &hex::decode(v.peer).unwrap(), &mut ctx).unwrap();
        let mut shared = EcPoint::new(&group).unwrap();
        shared.mul(&group, &peer, &private, &mut ctx).unwrap();
        assert_eq!(
            shared
                .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
                .unwrap(),
            hex::decode(v.shared).unwrap()
        );
    }
}

#[test]
fn brainpool_der_roundtrips_and_ecdsa_rejects_changed_digest() {
    for v in VECTORS {
        let group = EcGroup::from_curve_name(Nid::from_raw(v.nid)).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let private = BigNum::from_hex_str(v.private).unwrap();
        let public =
            EcPoint::from_bytes(&group, &hex::decode(v.public).unwrap(), &mut ctx).unwrap();
        let key = EcKey::from_private_components(&group, &private, &public).unwrap();
        key.check_key().unwrap();
        let pkey = PKey::from_ec_key(key).unwrap();
        let restored = PKey::private_key_from_der(&pkey.private_key_to_der().unwrap()).unwrap();
        let public = PKey::public_key_from_der(&pkey.public_key_to_der().unwrap()).unwrap();
        assert_eq!(
            restored.ec_key().unwrap().group().curve_name(),
            Some(Nid::from_raw(v.nid))
        );
        assert_eq!(
            public.ec_key().unwrap().group().curve_name(),
            Some(Nid::from_raw(v.nid))
        );
        let mut digest = vec![0x42; v.private.len() / 2];
        let signature = EcdsaSig::sign(&digest, &restored.ec_key().unwrap()).unwrap();
        assert!(signature
            .verify(&digest, &public.ec_key().unwrap())
            .unwrap());
        digest[0] ^= 1;
        assert!(!signature
            .verify(&digest, &public.ec_key().unwrap())
            .unwrap());
    }
}

#[test]
fn brainpool_rejects_off_curve_and_truncated_public_keys() {
    for v in VECTORS {
        let group = EcGroup::from_curve_name(Nid::from_raw(v.nid)).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let mut encoded = hex::decode(v.public).unwrap();
        assert!(EcPoint::from_bytes(&group, &encoded[..encoded.len() - 1], &mut ctx).is_err());
        encoded[1..].fill(0);
        assert!(EcPoint::from_bytes(&group, &encoded, &mut ctx).is_err());
    }
}

fn der(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    if contents.len() < 128 {
        output.push(contents.len() as u8);
    } else {
        let length = contents.len().to_be_bytes();
        let significant = &length[length.iter().position(|b| *b != 0).unwrap()..];
        output.push(0x80 | significant.len() as u8);
        output.extend_from_slice(significant);
    }
    output.extend_from_slice(contents);
    output
}

fn spki(parameters: &[u8], point: &[u8]) -> Vec<u8> {
    // id-ecPublicKey, then its AlgorithmIdentifier parameters.
    let mut algorithm = der(6, &hex::decode("2a8648ce3d0201").unwrap());
    algorithm.extend_from_slice(parameters);
    let mut body = der(0x30, &algorithm);
    let mut public = vec![0]; // BIT STRING unused-bit count
    public.extend_from_slice(point);
    body.extend_from_slice(&der(3, &public));
    der(0x30, &body)
}

#[test]
fn brainpool_spki_rejects_wrong_parameters_and_invalid_points() {
    for v in VECTORS {
        let (oid_tail, explicit) = match v.nid {
            927 => (7, include_str!("fixtures/brainpool-p256-parameters.hex")),
            931 => (11, include_str!("fixtures/brainpool-p384-parameters.hex")),
            933 => (13, include_str!("fixtures/brainpool-p512-parameters.hex")),
            _ => unreachable!(),
        };
        let mut oid = hex::decode("2b2403030208010100").unwrap();
        *oid.last_mut().unwrap() = oid_tail;
        let parameters = der(6, &oid);
        let point = hex::decode(v.public).unwrap();
        // Validate the independently encoded positive control first.
        let parsed = PKey::public_key_from_der(&spki(&parameters, &point)).unwrap();
        assert_eq!(
            parsed.ec_key().unwrap().group().curve_name(),
            Some(Nid::from_raw(v.nid))
        );
        for tail in [oid_tail + 1, 0x7f] {
            *oid.last_mut().unwrap() = tail;
            // The t1 twisted curve has its own OID and is not the r1 curve;
            // an unknown OID must not fall back to a same-size NIST curve.
            assert!(PKey::public_key_from_der(&spki(&der(6, &oid), &point)).is_err());
        }
        for invalid_parameters in [vec![], vec![5, 0], hex::decode(explicit.trim()).unwrap()] {
            // Fixtures contain genuine OpenSSL-generated explicit domain
            // parameters. TLS SPKIs still require the exact named-curve OID.
            assert!(PKey::public_key_from_der(&spki(&invalid_parameters, &point)).is_err());
        }
        assert!(PKey::public_key_from_der(&spki(&parameters, &[0])).is_err()); // infinity
        assert!(PKey::public_key_from_der(&spki(&parameters, &point[..point.len() - 1])).is_err());
        let mut off_curve = point.clone();
        off_curve[1..].fill(0);
        assert!(PKey::public_key_from_der(&spki(&parameters, &off_curve)).is_err());
    }
}
