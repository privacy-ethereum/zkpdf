use std::error::Error;

use num_bigint::BigUint;
use num_traits::FromPrimitive;
use sha2::{Digest, Sha256, Sha384, Sha512};
use simple_asn1::{from_der, oid, ASN1Block, ASN1Class};

use crate::SignatureAlgorithm;

pub struct VerifierParams {
    pub modulus: Vec<u8>,
    pub exponent: BigUint,
    pub signature: Vec<u8>,
    pub signed_attr_digest: Vec<u8>,
    pub algorithm: SignatureAlgorithm,
    pub signed_data_message_digest: Vec<u8>,
}

pub fn parse_signed_data(der_bytes: &[u8]) -> Result<VerifierParams, String> {
    let blocks = from_der(der_bytes).map_err(|e| format!("DER parse error: {}", e))?;

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
    digest_bytes: Vec<u8>,
    signed_algo: SignatureAlgorithm,
    expected_message_digest: Vec<u8>,
}

fn get_signature_data(signed_data_seq: Vec<ASN1Block>) -> Result<SignatureData, String> {
    let signer_info_items = extract_signer_info(&signed_data_seq)?;
    let (signer_serial, digest_oid) = extract_issuer_and_digest_algorithm(&signer_info_items)?;
    let signed_attrs_der = extract_signed_attributes_der(&signer_info_items)?;
    let (digest_bytes, signed_algo) =
        compute_signed_attributes_digest(&signed_attrs_der, &digest_oid)?;
    let signed_attrs =
        from_der(&signed_attrs_der).map_err(|e| format!("signedAttrs parse error: {}", e))?;
    let expected_message_digest = extract_message_digest(&signed_attrs)
        .map_err(|e| format!("Failed to get messageDigest: {}", e))?;
    let signature = extract_signature(&signer_info_items, &digest_bytes)?;

    Ok(SignatureData {
        signature,
        signer_serial,
        digest_bytes,
        signed_algo,
        expected_message_digest,
    })
}

fn extract_signer_info(signed_data_seq: &Vec<ASN1Block>) -> Result<&Vec<ASN1Block>, String> {
    match signed_data_seq.last() {
        Some(ASN1Block::Set(_, items)) => match items.first() {
            Some(ASN1Block::Sequence(_, signer_info)) => Ok(signer_info),
            _ => Err("Expected SignerInfo SEQUENCE in SignerInfo SET".into()),
        },
        _ => Err("Expected SignerInfo SET in SignedData".into()),
    }
}

fn extract_issuer_and_digest_algorithm(
    signer_info: &Vec<ASN1Block>,
) -> Result<(BigUint, simple_asn1::OID), String> {
    // issuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber INTEGER }
    let (_, signer_serial) = match &signer_info[1] {
        ASN1Block::Sequence(_, parts) if parts.len() == 2 => {
            let serial = match &parts[1] {
                ASN1Block::Integer(_, big_int) => {
                    BigUint::from_bytes_be(&big_int.to_signed_bytes_be())
                }
                other => {
                    return Err(format!("Expected serialNumber INTEGER, got {:?}", other).into())
                }
            };
            (parts[0].clone(), serial)
        }
        other => {
            return Err(format!("Expected issuerAndSerialNumber SEQUENCE, got {:?}", other).into())
        }
    };

    let digest_oid = if let ASN1Block::Sequence(_, items) = &signer_info[2] {
        if let ASN1Block::ObjectIdentifier(_, oid) = &items[0] {
            oid.clone()
        } else {
            return Err("Invalid digestAlgorithm in SignerInfo".into());
        }
    } else {
        return Err("Digest algorithm missing".into());
    };

    Ok((signer_serial, digest_oid))
}

fn extract_signed_attributes_der(signer_info: &Vec<ASN1Block>) -> Result<Vec<u8>, String> {
    for block in signer_info {
        if let ASN1Block::Unknown(ASN1Class::ContextSpecific, true, _len, tag_no, content) = block {
            if tag_no == &BigUint::from(0u8) {
                // Build universal SET tag + length
                let mut out = Vec::with_capacity(content.len() + 4);
                out.push(0x31); // SET

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
                return Ok(out);
            }
        }
    }
    Err("signedAttrs [0] not found".into())
}

fn compute_signed_attributes_digest(
    signed_attrs_der: &[u8],
    digest_oid: &simple_asn1::OID,
) -> Result<(Vec<u8>, SignatureAlgorithm), String> {
    match digest_oid {
        oid if oid == oid!(2, 16, 840, 1, 101, 3, 4, 2, 1) => {
            // SHA-256
            let mut h = Sha256::new();
            h.update(signed_attrs_der);
            Ok((
                h.finalize().to_vec(),
                SignatureAlgorithm::Sha256WithRsaEncryption,
            ))
        }
        oid if oid == oid!(2, 16, 840, 1, 101, 3, 4, 2, 2) => {
            // SHA-384
            let mut h = Sha384::new();
            h.update(signed_attrs_der);
            Ok((
                h.finalize().to_vec(),
                SignatureAlgorithm::Sha384WithRsaEncryption,
            ))
        }
        oid if oid == oid!(2, 16, 840, 1, 101, 3, 4, 2, 3) => {
            // SHA-512
            let mut h = Sha512::new();
            h.update(signed_attrs_der);
            Ok((
                h.finalize().to_vec(),
                SignatureAlgorithm::Sha512WithRsaEncryption,
            ))
        }
        oid if oid == oid!(1, 3, 14, 3, 2, 26) => {
            // SHA-1
            let mut h = sha1::Sha1::new();
            h.update(signed_attrs_der);
            Ok((
                h.finalize().to_vec(),
                SignatureAlgorithm::Sha1WithRsaEncryption,
            ))
        }
        _ => Err("Unsupported digest OID".into()),
    }
}

fn extract_signature(
    signer_info: &Vec<ASN1Block>,
    digest_bytes: &Vec<u8>,
) -> Result<Vec<u8>, String> {
    let sig_index = if digest_bytes.is_empty() { 4 } else { 5 };
    if let ASN1Block::OctetString(_, s) = &signer_info[sig_index] {
        Ok(s.clone())
    } else {
        Err("EncryptedDigest (signature) not found".into())
    }
}

fn extract_content_info(blocks: &[ASN1Block]) -> Result<&[ASN1Block], String> {
    if let Some(ASN1Block::Sequence(_, children)) = blocks.get(0) {
        if let ASN1Block::ObjectIdentifier(_, oid_val) = &children[0] {
            if *oid_val == oid!(1, 2, 840, 113549, 1, 7, 2) {
                Ok(children)
            } else {
                Err("Not a SignedData contentType".into())
            }
        } else {
            Err("Missing contentType OID".into())
        }
    } else {
        Err("Top-level not a SEQUENCE".into())
    }
}

pub fn extract_signed_children(children: &[ASN1Block]) -> Result<Vec<ASN1Block>, String> {
    let block = children
        .get(1)
        .ok_or_else(|| "Missing SignedData content".to_string())?;

    match block {
        ASN1Block::Explicit(ASN1Class::ContextSpecific, _, _, inner) => {
            if let ASN1Block::Sequence(_, seq_children) = &**inner {
                Ok(seq_children.clone())
            } else {
                Err("Explicit SignedData not a SEQUENCE".into())
            }
        }
        ASN1Block::Unknown(ASN1Class::ContextSpecific, _, _, _, data) => {
            let parsed =
                from_der(data).map_err(|e| format!("Inner SignedData parse error: {}", e))?;
            if let ASN1Block::Sequence(_, seq_children) = &parsed[0] {
                Ok(seq_children.clone())
            } else {
                Err("Inner SignedData not a SEQUENCE".into())
            }
        }
        ASN1Block::Sequence(_, seq_children) => Ok(seq_children.clone()),
        other => Err(format!("Unexpected SignedData format: {:?}", other)),
    }
}

pub fn extract_pubkey_components(
    signed_data_seq: &Vec<ASN1Block>,
    signed_serial_number: &BigUint,
) -> Result<(Vec<u8>, BigUint), String> {
    let certificates = find_certificates(signed_data_seq)?;
    let tbs_fields = get_correct_tbs(&certificates, signed_serial_number)
        .map_err(|e| format!("Failed to get correct tbsCertificate: {}", e))?;
    let spki_fields = find_subject_public_key_info(&tbs_fields)?;
    let public_key_bitstring = extract_public_key_bitstring(&spki_fields)?;
    let rsa_sequence = parse_rsa_public_key(&public_key_bitstring)?;
    let modulus = extract_modulus(&rsa_sequence)?;
    let exponent = extract_exponent(&rsa_sequence)?;

    Ok((modulus, exponent))
}

fn find_certificates(signed_data_seq: &Vec<ASN1Block>) -> Result<Vec<ASN1Block>, String> {
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
                let parsed_inner =
                    from_der(data).map_err(|e| format!("Cert wrapper parse error: {}", e))?;
                match parsed_inner.as_slice() {
                    [ASN1Block::Set(_, items)] => Ok(items.clone()),
                    [ASN1Block::Sequence(_, items)] => Ok(items.clone()),
                    seqs if seqs.iter().all(|b| matches!(b, ASN1Block::Sequence(_, _))) => {
                        Ok(seqs.to_vec())
                    }
                    other => Err(format!(
                        "Unexpected structure inside implicit certificate block: {:?}",
                        other
                    )
                    .into()),
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
                    other => Err(format!(
                        "Expected SET or SEQUENCE inside Explicit certificate block, got {:?}",
                        other
                    )
                    .into()),
                }
            }
            ASN1Block::Set(_, items)
                if items.iter().all(|i| matches!(i, ASN1Block::Sequence(_, _))) =>
            {
                Ok(items.clone())
            }
            other => Err(format!("Unexpected certificates block type: {:?}", other).into()),
        },
        None => Ok(Vec::new()),
    }
}

fn get_correct_tbs(
    certificates: &Vec<ASN1Block>,
    signed_serial_number: &BigUint,
) -> Result<Vec<ASN1Block>, Box<dyn Error>> {
    for certificate in certificates {
        let cert_fields = if let ASN1Block::Sequence(_, fields) = certificate {
            fields
        } else {
            return Err("Certificate not a SEQUENCE".into());
        };

        let tbs_fields = match &cert_fields[0] {
            ASN1Block::Explicit(ASN1Class::ContextSpecific, _, _, _) => cert_fields.clone(),
            ASN1Block::Sequence(_, seq) => seq.clone(),
            _ => return Err("tbsCertificate not found".into()),
        };

        let serial_number = if let ASN1Block::Integer(_, big_int) = &tbs_fields[1] {
            BigUint::from_bytes_be(&big_int.to_signed_bytes_be())
        } else {
            return Err("Serial number not found".into());
        };

        // Check if the serial number matches the one we are looking for
        if serial_number == *signed_serial_number {
            return Ok(tbs_fields);
        }
    }
    Err("No matching certificate found".into())
}

fn find_subject_public_key_info(tbs_fields: &Vec<ASN1Block>) -> Result<&Vec<ASN1Block>, String> {
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
        .ok_or_else(|| "subjectPublicKeyInfo not found".to_string())
}

fn extract_public_key_bitstring(spki_fields: &Vec<ASN1Block>) -> Result<Vec<u8>, String> {
    if let ASN1Block::BitString(_, _, d) = &spki_fields[1] {
        Ok(d.clone())
    } else {
        Err("Expected BIT STRING for public key".into())
    }
}

fn parse_rsa_public_key(bitstring: &[u8]) -> Result<Vec<ASN1Block>, String> {
    let rsa_blocks = from_der(bitstring).map_err(|e| format!("RSAPublicKey parse error: {}", e))?;
    if let ASN1Block::Sequence(_, items) = &rsa_blocks[0] {
        Ok(items.clone())
    } else {
        Err("RSAPublicKey not a SEQUENCE".into())
    }
}

fn extract_exponent(rsa_sequence: &Vec<ASN1Block>) -> Result<BigUint, String> {
    if let ASN1Block::Integer(_, e) = &rsa_sequence[1] {
        Ok(BigUint::from_bytes_be(&e.to_signed_bytes_be()))
    } else {
        Err("Exponent not found".into())
    }
}

fn extract_modulus(rsa_sequence: &Vec<ASN1Block>) -> Result<Vec<u8>, String> {
    if let ASN1Block::Integer(_, m) = &rsa_sequence[0] {
        Ok(m.to_signed_bytes_be())
    } else {
        Err("Modulus not found".into())
    }
}

/// find and return the messageDigest OCTET STRING bytes.
fn extract_message_digest(attrs: &[ASN1Block]) -> Result<Vec<u8>, String> {
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
                            return Err("messageDigest value not an OctetString".into());
                        }
                    } else {
                        return Err("messageDigest missing inner Set".into());
                    }
                }
            }
        }
    }
    Err("messageDigest attribute (OID 1.2.840.113549.1.9.4) not found".into())
}
