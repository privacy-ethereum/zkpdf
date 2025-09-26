use num_bigint::BigUint;
use num_traits::FromPrimitive;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use simple_asn1::{from_der, oid, ASN1Block, ASN1Class};

use crate::types::{Pkcs7Error, Pkcs7Result, SignatureAlgorithm};

pub struct VerifierParams {
    pub modulus: Vec<u8>,
    pub exponent: BigUint,
    pub signature: Vec<u8>,
    pub signed_attr_digest: Option<Vec<u8>>,
    pub algorithm: SignatureAlgorithm,
    pub signed_data_message_digest: Option<Vec<u8>>,
}

pub fn parse_signed_data(der_bytes: &[u8]) -> Pkcs7Result<VerifierParams> {
    let blocks = from_der(der_bytes)?;

    let content_info = extract_content_info(&blocks)?;
    let signed_children = extract_signed_children(content_info)?;
    let signature_data = get_signature_data(signed_children.clone())?;

    let (modulus_bytes, exponent_big) =
        extract_pubkey_components(&signed_children, &signature_data.signer_serial)?;

    Ok(VerifierParams {
        modulus: modulus_bytes,
        exponent: exponent_big,
        signature: signature_data.signature,
        signed_attr_digest: signature_data.digest_bytes,
        algorithm: signature_data.signed_algo,
        signed_data_message_digest: signature_data.expected_message_digest,
    })
}

struct SignatureData {
    signature: Vec<u8>,
    signer_serial: BigUint,
    digest_bytes: Option<Vec<u8>>,
    signed_algo: SignatureAlgorithm,
    expected_message_digest: Option<Vec<u8>>,
}

fn get_signature_data(signed_data_seq: Vec<ASN1Block>) -> Pkcs7Result<SignatureData> {
    let signer_info_items = extract_signer_info(&signed_data_seq)?;
    let (signer_serial, digest_oid) = extract_issuer_and_digest_algorithm(signer_info_items)?;
    let signed_attrs_der = extract_signed_attributes_der(signer_info_items)?;
    let has_signed_attrs = signed_attrs_der.is_some();
    let embedded_digest = extract_signed_content_digest(&signed_data_seq)?;
    let (digest_bytes, signed_algo, expected_message_digest) = match signed_attrs_der.as_ref() {
        Some(der) => {
            let (digest, algo) = compute_signed_attributes_digest(der, &digest_oid)?;
            let signed_attrs = from_der(der)?;
            let message_digest = extract_message_digest(&signed_attrs)?;
            (Some(digest), algo, Some(message_digest))
        }
        None => {
            let digest = embedded_digest
                .clone()
                .ok_or_else(|| Pkcs7Error::structure("Signed content digest missing"))?;
            let algo = digest_algorithm_from_oid(&digest_oid)?;
            let signed_digest = match algo {
                SignatureAlgorithm::Sha1WithRsaEncryption => {
                    let mut hasher = Sha1::new();
                    hasher.update(&digest);
                    hasher.finalize().to_vec()
                }
                SignatureAlgorithm::Sha256WithRsaEncryption => {
                    let mut hasher = Sha256::new();
                    hasher.update(&digest);
                    hasher.finalize().to_vec()
                }
                SignatureAlgorithm::Sha384WithRsaEncryption => {
                    let mut hasher = Sha384::new();
                    hasher.update(&digest);
                    hasher.finalize().to_vec()
                }
                SignatureAlgorithm::Sha512WithRsaEncryption => {
                    let mut hasher = Sha512::new();
                    hasher.update(&digest);
                    hasher.finalize().to_vec()
                }
                _ => return Err(Pkcs7Error::UnsupportedDigestOid(digest_oid.clone())),
            };

            (Some(signed_digest), algo, Some(digest))
        }
    };
    let signature = extract_signature(signer_info_items, has_signed_attrs)?;

    Ok(SignatureData {
        signature,
        signer_serial,
        digest_bytes,
        signed_algo,
        expected_message_digest,
    })
}

fn extract_signer_info(signed_data_seq: &Vec<ASN1Block>) -> Pkcs7Result<&Vec<ASN1Block>> {
    match signed_data_seq.last() {
        Some(ASN1Block::Set(_, items)) => match items.first() {
            Some(ASN1Block::Sequence(_, signer_info)) => Ok(signer_info),
            _ => Err(Pkcs7Error::structure(
                "Expected SignerInfo SEQUENCE in SignerInfo SET",
            )),
        },
        _ => Err(Pkcs7Error::structure(
            "Expected SignerInfo SET in SignedData",
        )),
    }
}

fn extract_issuer_and_digest_algorithm(
    signer_info: &Vec<ASN1Block>,
) -> Pkcs7Result<(BigUint, simple_asn1::OID)> {
    let (_, signer_serial) = match &signer_info[1] {
        ASN1Block::Sequence(_, parts) if parts.len() == 2 => {
            let serial = match &parts[1] {
                ASN1Block::Integer(_, big_int) => {
                    BigUint::from_bytes_be(&big_int.to_signed_bytes_be())
                }
                other => {
                    return Err(Pkcs7Error::structure(format!(
                        "Expected serialNumber INTEGER, got {:?}",
                        other
                    )))
                }
            };
            (parts[0].clone(), serial)
        }
        other => {
            return Err(Pkcs7Error::structure(format!(
                "Expected issuerAndSerialNumber SEQUENCE, got {:?}",
                other
            )))
        }
    };

    let digest_oid = if let ASN1Block::Sequence(_, items) = &signer_info[2] {
        if let ASN1Block::ObjectIdentifier(_, oid) = &items[0] {
            oid.clone()
        } else {
            return Err(Pkcs7Error::structure(
                "Invalid digestAlgorithm in SignerInfo",
            ));
        }
    } else {
        return Err(Pkcs7Error::structure("Digest algorithm missing"));
    };

    Ok((signer_serial, digest_oid))
}

fn extract_signed_attributes_der(signer_info: &Vec<ASN1Block>) -> Pkcs7Result<Option<Vec<u8>>> {
    for block in signer_info {
        if let ASN1Block::Unknown(ASN1Class::ContextSpecific, true, _len, tag_no, content) = block {
            if tag_no == &BigUint::from(0u8) {
                let mut out = Vec::with_capacity(content.len() + 4);
                out.push(0x31); // SET tag

                let len = content.len();
                if len < 128 {
                    out.push(len as u8);
                } else if len <= 0xFF {
                    out.push(0x81);
                    out.push(len as u8);
                } else {
                    out.push(0x82);
                    out.push((len >> 8) as u8);
                    out.push((len & 0xFF) as u8);
                }

                out.extend_from_slice(content);
                return Ok(Some(out));
            }
        }
    }
    Ok(None)
}

fn compute_signed_attributes_digest(
    signed_attrs_der: &[u8],
    digest_oid: &simple_asn1::OID,
) -> Pkcs7Result<(Vec<u8>, SignatureAlgorithm)> {
    let algorithm = digest_algorithm_from_oid(digest_oid)?;
    let digest = match algorithm {
        SignatureAlgorithm::Sha1WithRsaEncryption => {
            let mut hasher = Sha1::new();
            hasher.update(signed_attrs_der);
            hasher.finalize().to_vec()
        }
        SignatureAlgorithm::Sha256WithRsaEncryption => {
            let mut hasher = Sha256::new();
            hasher.update(signed_attrs_der);
            hasher.finalize().to_vec()
        }
        SignatureAlgorithm::Sha384WithRsaEncryption => {
            let mut hasher = Sha384::new();
            hasher.update(signed_attrs_der);
            hasher.finalize().to_vec()
        }
        SignatureAlgorithm::Sha512WithRsaEncryption => {
            let mut hasher = Sha512::new();
            hasher.update(signed_attrs_der);
            hasher.finalize().to_vec()
        }
        _ => return Err(Pkcs7Error::UnsupportedDigestOid(digest_oid.clone())),
    };

    Ok((digest, algorithm))
}

fn extract_signature(signer_info: &Vec<ASN1Block>, has_signed_attrs: bool) -> Pkcs7Result<Vec<u8>> {
    let sig_index = if has_signed_attrs { 5 } else { 4 };
    if let Some(ASN1Block::OctetString(_, s)) = signer_info.get(sig_index) {
        Ok(s.clone())
    } else {
        Err(Pkcs7Error::structure(
            "EncryptedDigest (signature) not found",
        ))
    }
}

fn digest_algorithm_from_oid(digest_oid: &simple_asn1::OID) -> Pkcs7Result<SignatureAlgorithm> {
    if digest_oid == &oid!(1, 3, 14, 3, 2, 26) {
        Ok(SignatureAlgorithm::Sha1WithRsaEncryption)
    } else if digest_oid == &oid!(2, 16, 840, 1, 101, 3, 4, 2, 1) {
        Ok(SignatureAlgorithm::Sha256WithRsaEncryption)
    } else if digest_oid == &oid!(2, 16, 840, 1, 101, 3, 4, 2, 2) {
        Ok(SignatureAlgorithm::Sha384WithRsaEncryption)
    } else if digest_oid == &oid!(2, 16, 840, 1, 101, 3, 4, 2, 3) {
        Ok(SignatureAlgorithm::Sha512WithRsaEncryption)
    } else {
        Err(Pkcs7Error::UnsupportedDigestOid(digest_oid.clone()))
    }
}

fn extract_signed_content_digest(signed_data_seq: &Vec<ASN1Block>) -> Pkcs7Result<Option<Vec<u8>>> {
    for block in signed_data_seq {
        if let ASN1Block::Sequence(_, items) = block {
            if let Some(ASN1Block::ObjectIdentifier(_, oid_val)) = items.get(0) {
                if *oid_val == oid!(1, 2, 840, 113549, 1, 7, 1) {
                    if let Some(content_block) = items.get(1) {
                        match content_block {
                            ASN1Block::Explicit(ASN1Class::ContextSpecific, _, _, inner) => {
                                if let ASN1Block::OctetString(_, bytes) = inner.as_ref() {
                                    return Ok(Some(bytes.clone()));
                                }
                            }
                            ASN1Block::Unknown(ASN1Class::ContextSpecific, _, _, _, data) => {
                                let parsed = from_der(data).map_err(Pkcs7Error::Der)?;
                                if let Some(ASN1Block::OctetString(_, bytes)) = parsed.get(0) {
                                    return Ok(Some(bytes.clone()));
                                }
                            }
                            ASN1Block::OctetString(_, bytes) => {
                                return Ok(Some(bytes.clone()));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    Ok(None)
}

fn extract_content_info(blocks: &[ASN1Block]) -> Pkcs7Result<&[ASN1Block]> {
    if let Some(ASN1Block::Sequence(_, children)) = blocks.get(0) {
        if let ASN1Block::ObjectIdentifier(_, oid_val) = &children[0] {
            if *oid_val == oid!(1, 2, 840, 113549, 1, 7, 2) {
                Ok(children)
            } else {
                Err(Pkcs7Error::structure("Not a SignedData contentType"))
            }
        } else {
            Err(Pkcs7Error::structure("Missing contentType OID"))
        }
    } else {
        Err(Pkcs7Error::structure("Top-level not a SEQUENCE"))
    }
}

pub fn extract_signed_children(children: &[ASN1Block]) -> Pkcs7Result<Vec<ASN1Block>> {
    let block = children
        .get(1)
        .ok_or_else(|| Pkcs7Error::structure("Missing SignedData content"))?;

    match block {
        ASN1Block::Explicit(ASN1Class::ContextSpecific, _, _, inner) => {
            if let ASN1Block::Sequence(_, seq_children) = &**inner {
                Ok(seq_children.clone())
            } else {
                Err(Pkcs7Error::structure("Explicit SignedData not a SEQUENCE"))
            }
        }
        ASN1Block::Unknown(ASN1Class::ContextSpecific, _, _, _, data) => {
            let parsed = from_der(data).map_err(Pkcs7Error::Der)?;
            if let ASN1Block::Sequence(_, seq_children) = &parsed[0] {
                Ok(seq_children.clone())
            } else {
                Err(Pkcs7Error::structure("Inner SignedData not a SEQUENCE"))
            }
        }
        ASN1Block::Sequence(_, seq_children) => Ok(seq_children.clone()),
        other => Err(Pkcs7Error::structure(format!(
            "Unexpected SignedData format: {:?}",
            other
        ))),
    }
}

pub fn extract_pubkey_components(
    signed_data_seq: &Vec<ASN1Block>,
    signed_serial_number: &BigUint,
) -> Pkcs7Result<(Vec<u8>, BigUint)> {
    let certificates = find_certificates(signed_data_seq)?;
    let tbs_fields = get_correct_tbs(&certificates, signed_serial_number)?;
    let spki_fields = find_subject_public_key_info(&tbs_fields)?;
    let public_key_bitstring = extract_public_key_bitstring(spki_fields)?;
    let rsa_sequence = parse_rsa_public_key(&public_key_bitstring)?;
    let modulus = extract_modulus(&rsa_sequence)?;
    let exponent = extract_exponent(&rsa_sequence)?;

    Ok((modulus, exponent))
}

fn find_certificates(signed_data_seq: &Vec<ASN1Block>) -> Pkcs7Result<Vec<ASN1Block>> {
    let certs_block = signed_data_seq.iter().find(|block| match block {
        ASN1Block::Explicit(ASN1Class::ContextSpecific, _, tag, _) => {
            tag == &simple_asn1::BigUint::from_usize(0).unwrap()
        }
        ASN1Block::Unknown(ASN1Class::ContextSpecific, _, _, tag, _) => {
            tag == &simple_asn1::BigUint::from_usize(0).unwrap()
        }
        _ => false,
    });

    match certs_block {
        Some(cert_block) => match cert_block {
            ASN1Block::Unknown(ASN1Class::ContextSpecific, _, _, tag, data)
                if tag == &BigUint::from(0u8) =>
            {
                let parsed_inner = from_der(data).map_err(Pkcs7Error::Der)?;
                match parsed_inner.as_slice() {
                    [ASN1Block::Set(_, items)] => Ok(items.clone()),
                    [ASN1Block::Sequence(_, items)] => Ok(items.clone()),
                    seqs if seqs.iter().all(|b| matches!(b, ASN1Block::Sequence(_, _))) => {
                        Ok(seqs.to_vec())
                    }
                    other => Err(Pkcs7Error::structure(format!(
                        "Unexpected structure inside implicit certificate block: {:?}",
                        other
                    ))),
                }
            }
            ASN1Block::Explicit(ASN1Class::ContextSpecific, _, tag, inner)
                if tag == &BigUint::from(0u8) =>
            {
                match inner.as_ref() {
                    ASN1Block::Set(_, certs) => Ok(certs.clone()),
                    ASN1Block::Sequence(tag, fields) => {
                        Ok(vec![ASN1Block::Sequence(*tag, fields.clone())])
                    }
                    other => Err(Pkcs7Error::structure(format!(
                        "Expected SET or SEQUENCE inside Explicit certificate block, got {:?}",
                        other
                    ))),
                }
            }
            ASN1Block::Set(_, items)
                if items.iter().all(|i| matches!(i, ASN1Block::Sequence(_, _))) =>
            {
                Ok(items.clone())
            }
            other => Err(Pkcs7Error::structure(format!(
                "Unexpected certificates block type: {:?}",
                other
            ))),
        },
        None => Ok(Vec::new()),
    }
}

fn get_correct_tbs(
    certificates: &Vec<ASN1Block>,
    signed_serial_number: &BigUint,
) -> Pkcs7Result<Vec<ASN1Block>> {
    for certificate in certificates {
        let cert_fields = if let ASN1Block::Sequence(_, fields) = certificate {
            fields
        } else {
            return Err(Pkcs7Error::structure("Certificate not a SEQUENCE"));
        };

        let tbs_fields = match &cert_fields[0] {
            ASN1Block::Explicit(ASN1Class::ContextSpecific, _, _, _) => cert_fields.clone(),
            ASN1Block::Sequence(_, seq) => seq.clone(),
            _ => return Err(Pkcs7Error::structure("tbsCertificate not found")),
        };

        let serial_number = if let ASN1Block::Integer(_, big_int) = &tbs_fields[1] {
            BigUint::from_bytes_be(&big_int.to_signed_bytes_be())
        } else {
            return Err(Pkcs7Error::structure("Serial number not found"));
        };

        // Check if the serial number matches the one we are looking for
        if serial_number == *signed_serial_number {
            return Ok(tbs_fields);
        }
    }
    Err(Pkcs7Error::structure("No matching certificate found"))
}

fn find_subject_public_key_info(tbs_fields: &Vec<ASN1Block>) -> Pkcs7Result<&Vec<ASN1Block>> {
    tbs_fields
        .iter()
        .find_map(|b| {
            if let ASN1Block::Sequence(_, sf) = b {
                if let ASN1Block::Sequence(_, alg) = &sf[0] {
                    if let Some(ASN1Block::ObjectIdentifier(_, o)) = alg.get(0) {
                        if *o == oid!(1, 2, 840, 113549, 1, 1, 1) {
                            return Some(sf);
                        }
                    }
                }
            }
            None
        })
        .ok_or_else(|| Pkcs7Error::structure("subjectPublicKeyInfo not found"))
}

fn extract_public_key_bitstring(spki_fields: &Vec<ASN1Block>) -> Pkcs7Result<Vec<u8>> {
    if let ASN1Block::BitString(_, _, d) = &spki_fields[1] {
        Ok(d.clone())
    } else {
        Err(Pkcs7Error::structure("Expected BIT STRING for public key"))
    }
}

fn parse_rsa_public_key(bitstring: &[u8]) -> Pkcs7Result<Vec<ASN1Block>> {
    let rsa_blocks = from_der(bitstring)?;
    if let ASN1Block::Sequence(_, items) = &rsa_blocks[0] {
        Ok(items.clone())
    } else {
        Err(Pkcs7Error::structure("RSAPublicKey not a SEQUENCE"))
    }
}

fn extract_exponent(rsa_sequence: &Vec<ASN1Block>) -> Pkcs7Result<BigUint> {
    if let ASN1Block::Integer(_, e) = &rsa_sequence[1] {
        Ok(BigUint::from_bytes_be(&e.to_signed_bytes_be()))
    } else {
        Err(Pkcs7Error::structure("Exponent not found"))
    }
}

fn extract_modulus(rsa_sequence: &Vec<ASN1Block>) -> Pkcs7Result<Vec<u8>> {
    if let ASN1Block::Integer(_, m) = &rsa_sequence[0] {
        Ok(m.to_signed_bytes_be())
    } else {
        Err(Pkcs7Error::structure("Modulus not found"))
    }
}

/// find and return the messageDigest OCTET STRING bytes.
fn extract_message_digest(attrs: &[ASN1Block]) -> Pkcs7Result<Vec<u8>> {
    let candidates: &[ASN1Block] = if attrs.len() == 1 {
        if let ASN1Block::Set(_, inner) = &attrs[0] {
            inner.as_slice()
        } else {
            attrs
        }
    } else {
        attrs
    };

    for attr in candidates {
        if let ASN1Block::Sequence(_, items) = attr {
            if let ASN1Block::ObjectIdentifier(_, oid) = &items[0] {
                if *oid == oid!(1, 2, 840, 113549, 1, 9, 4) {
                    if let ASN1Block::Set(_, inner_vals) = &items[1] {
                        if let ASN1Block::OctetString(_, data) = &inner_vals[0] {
                            return Ok(data.clone());
                        } else {
                            return Err(Pkcs7Error::structure(
                                "messageDigest value not an OctetString",
                            ));
                        }
                    } else {
                        return Err(Pkcs7Error::structure("messageDigest missing inner Set"));
                    }
                }
            }
        }
    }
    Err(Pkcs7Error::MissingMessageDigest)
}
