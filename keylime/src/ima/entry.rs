// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Keylime Authors

// Parser for IMA ASCII entries.
//
// Implements the templates (modes) and types as defined in:
// https://elixir.bootlin.com/linux/latest/source/security/integrity/ima/ima_template.c
// https://www.kernel.org/doc/html/v5.12/security/IMA-templates.html

use crate::algorithms::HashAlgorithm;
use crate::endian;
use openssl::hash::MessageDigest;
use std::convert::{TryFrom, TryInto};
use std::io::{Error, ErrorKind, Result, Write};

pub trait Encode {
    /// Encodes this type and writes the output to `writer`.
    fn encode(&self, writer: &mut dyn Write) -> Result<()>;
}

pub trait EncodeLegacy {
    /// Encodes this type in legacy mode and writes the output to `writer`.
    fn encode_legacy(&self, writer: &mut dyn Write) -> Result<()>;
}

/// Wrapper around a IMA digest value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Digest {
    pub algorithm: HashAlgorithm,
    value: Vec<u8>,
}

impl Digest {
    /// Creates a new `Digest` with `algorithm` and `value`.
    pub fn new(algorithm: HashAlgorithm, value: &[u8]) -> Result<Self> {
        let digest: MessageDigest = algorithm.into();
        if value.len() != digest.size() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid digest value",
            ));
        }
        let mut v = Vec::with_capacity(digest.size());
        v.extend_from_slice(value);
        Ok(Self {
            algorithm,
            value: v,
        })
    }

    /// Retrieves the value held in this `Digest`.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Returns a pre-defined digest value used to indicate the start
    /// of the IMA measurement list.
    pub fn start(algorithm: HashAlgorithm) -> Self {
        let digest: MessageDigest = algorithm.into();
        Self {
            algorithm,
            value: vec![0x00u8; digest.size()],
        }
    }

    /// Returns a pre-defined digest value used to indicate the ToMToU
    /// error in the IMA measurement list.
    pub fn ff(algorithm: HashAlgorithm) -> Self {
        let digest: MessageDigest = algorithm.into();
        Self {
            algorithm,
            value: vec![0xffu8; digest.size()],
        }
    }
}

impl TryFrom<&str> for Digest {
    type Error = std::io::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        let tokens: Vec<&str> = value.splitn(2, ':').collect();
        if tokens.len() == 1 {
            Ok(Digest {
                algorithm: HashAlgorithm::Sha1,
                value: hex::decode(tokens[0]).map_err(|_| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        "invalid hex encoding",
                    )
                })?,
            })
        } else {
            Ok(Digest {
                algorithm: tokens[0].try_into().map_err(|_| {
                    Error::new(ErrorKind::InvalidInput, "invalid algorithm")
                })?,
                value: hex::decode(tokens[1]).map_err(|_| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        "invalid hex encoding",
                    )
                })?,
            })
        }
    }
}

impl Encode for Digest {
    fn encode(&self, writer: &mut dyn Write) -> Result<()> {
        if self.algorithm == HashAlgorithm::Sha1 {
            writer.write_all(&endian::local_endianness_32(
                self.value.len() as u32,
            ))?;
            writer.write_all(&self.value)?;
        } else {
            let algorithm = format!("{}", self.algorithm);
            let total_len = algorithm.len() + 2 + self.value.len();
            writer
                .write_all(&endian::local_endianness_32(total_len as u32))?;
            writer.write_all(algorithm.as_bytes())?;
            writer.write_all(&[58u8, 0u8])?;
            writer.write_all(&self.value)?;
        }
        Ok(())
    }
}

impl EncodeLegacy for Digest {
    fn encode_legacy(&self, writer: &mut dyn Write) -> Result<()> {
        writer.write_all(&self.value)?;
        Ok(())
    }
}

struct Name {
    name: String,
}

impl TryFrom<&str> for Name {
    type Error = std::io::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            name: value.to_string(),
        })
    }
}

const TCG_EVENT_NAME_LEN_MAX: usize = 255;

impl Encode for Name {
    fn encode(&self, writer: &mut dyn Write) -> Result<()> {
        let bytes = self.name.as_bytes();
        writer.write_all(&endian::local_endianness_32(
            (bytes.len() + 1) as u32,
        ))?;
        writer.write_all(bytes)?;
        writer.write_all(&[0u8])?; // NUL
        Ok(())
    }
}

impl EncodeLegacy for Name {
    fn encode_legacy(&self, writer: &mut dyn Write) -> Result<()> {
        let bytes = self.name.as_bytes();
        writer.write_all(bytes)?;
        writer.write_all(&vec![0u8; TCG_EVENT_NAME_LEN_MAX - bytes.len()])?;
        Ok(())
    }
}

struct Signature {
    value: Vec<u8>,
}

impl TryFrom<&str> for Signature {
    type Error = std::io::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        let value = hex::decode(value).map_err(|_| {
            Error::new(ErrorKind::InvalidInput, "invalid hex encoding")
        })?;
        // basic checks on signature
        if value.len() < 9 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid signature",
            ));
        }
        let sig_size = u16::from_be_bytes(value[7..9].try_into().unwrap()); //#[allow_ci]
        if (sig_size as usize) + 9 != value.len() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid signature",
            ));
        }
        Ok(Self { value })
    }
}

impl Encode for Signature {
    fn encode(&self, writer: &mut dyn Write) -> Result<()> {
        writer.write_all(&endian::local_endianness_32(
            self.value.len() as u32
        ))?;
        writer.write_all(&self.value)?;
        Ok(())
    }
}

struct Buffer {
    value: Vec<u8>,
}

impl TryFrom<&str> for Buffer {
    type Error = std::io::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            value: hex::decode(value).map_err(|_| {
                Error::new(ErrorKind::InvalidInput, "invalid hex encoding")
            })?,
        })
    }
}

impl Encode for Buffer {
    fn encode(&self, writer: &mut dyn Write) -> Result<()> {
        writer.write_all(&endian::local_endianness_32(
            self.value.len() as u32
        ))?;
        writer.write_all(&self.value)?;
        Ok(())
    }
}

pub trait EventData: Encode {
    fn path(&self) -> &str;
}

struct Ima {
    digest: Digest,
    path: Name,
}

impl TryFrom<&str> for Ima {
    type Error = std::io::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        let tokens: Vec<&str> = value.splitn(2, ' ').collect();
        if tokens.len() != 2 {
            return Err(Error::new(ErrorKind::InvalidInput, value));
        }
        Ok(Self {
            digest: Digest::try_from(tokens[0])?,
            path: Name::try_from(tokens[1])?,
        })
    }
}

impl EventData for Ima {
    fn path(&self) -> &str {
        &self.path.name
    }
}

impl Encode for Ima {
    fn encode(&self, writer: &mut dyn Write) -> Result<()> {
        self.digest.encode_legacy(writer)?;
        self.path.encode_legacy(writer)?;
        Ok(())
    }
}

struct ImaNg {
    digest: Digest,
    path: Name,
}

impl TryFrom<&str> for ImaNg {
    type Error = std::io::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        let tokens: Vec<&str> = value.splitn(2, ' ').collect();
        if tokens.len() != 2 {
            return Err(Error::new(ErrorKind::InvalidInput, value));
        }

        Ok(Self {
            digest: Digest::try_from(tokens[0])?,
            path: Name::try_from(tokens[1])?,
        })
    }
}

impl EventData for ImaNg {
    fn path(&self) -> &str {
        &self.path.name
    }
}

impl Encode for ImaNg {
    fn encode(&self, writer: &mut dyn Write) -> Result<()> {
        self.digest.encode(writer)?;
        self.path.encode(writer)?;
        Ok(())
    }
}

struct ImaSig {
    digest: Digest,
    path: Name,
    signature: Option<Signature>,
}

impl EventData for ImaSig {
    fn path(&self) -> &str {
        &self.path.name
    }
}

impl TryFrom<&str> for ImaSig {
    type Error = std::io::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        // extract signature first
        let (value, signature) = value
            .rsplit_once(' ')
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, value))?;

        // parse d-ng|n-ng as in ima-ng
        let tokens: Vec<&str> = value.splitn(2, ' ').collect();
        if tokens.len() != 2 {
            return Err(Error::new(ErrorKind::InvalidInput, value));
        }

        let digest = Digest::try_from(tokens[0])?;
        let path = Name::try_from(tokens[1])?;
        let signature = if !signature.is_empty() {
            Some(Signature::try_from(signature)?)
        } else {
            None
        };

        Ok(Self {
            digest,
            path,
            signature,
        })
    }
}

impl Encode for ImaSig {
    fn encode(&self, writer: &mut dyn Write) -> Result<()> {
        self.digest.encode(writer)?;
        self.path.encode(writer)?;
        if let Some(signature) = &self.signature {
            signature.encode(writer)?;
        } else {
            writer.write_all(&endian::local_endianness_32(0u32))?;
        }
        Ok(())
    }
}

struct ImaBuf {
    digest: Digest,
    name: Name,
    data: Buffer,
}

impl TryFrom<&str> for ImaBuf {
    type Error = std::io::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        let tokens: Vec<&str> = value.splitn(3, ' ').collect();
        if tokens.len() != 3 {
            return Err(Error::new(ErrorKind::InvalidInput, value));
        }
        Ok(Self {
            digest: Digest::try_from(tokens[0])?,
            name: Name::try_from(tokens[1])?,
            data: Buffer::try_from(tokens[2])?,
        })
    }
}

impl EventData for ImaBuf {
    fn path(&self) -> &str {
        &self.name.name
    }
}

impl Encode for ImaBuf {
    fn encode(&self, writer: &mut dyn Write) -> Result<()> {
        self.digest.encode(writer)?;
        self.name.encode(writer)?;
        self.data.encode(writer)?;
        Ok(())
    }
}

/// Represents a single entry in the IMA measurement list.
pub struct Entry {
    pub template_hash: Digest,
    pub event_data: Box<dyn EventData>,
}

impl TryFrom<&str> for Entry {
    type Error = std::io::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        let tokens: Vec<&str> = value.splitn(4, ' ').collect();
        if tokens.len() != 4 {
            return Err(Error::new(ErrorKind::InvalidInput, value));
        }

        let template_hash = Digest {
            algorithm: HashAlgorithm::Sha1,
            value: hex::decode(tokens[1]).map_err(|_| {
                Error::new(ErrorKind::InvalidInput, "invalid hex encoding")
            })?,
        };
        let mode = tokens[2];
        let event = tokens[3];

        match mode {
            "ima" => Ok(Self {
                template_hash,
                event_data: Box::new(Ima::try_from(event)?),
            }),
            "ima-ng" => Ok(Self {
                template_hash,
                event_data: Box::new(ImaNg::try_from(event)?),
            }),
            "ima-sig" => Ok(Self {
                template_hash,
                event_data: Box::new(ImaSig::try_from(event)?),
            }),
            "ima-buf" => Ok(Self {
                template_hash,
                event_data: Box::new(ImaBuf::try_from(event)?),
            }),
            template => Err(Error::new(
                ErrorKind::Other,
                format!("unrecognized template \"{template}\"",),
            )),
        }
    }
}

// Unit Testing
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ima() {
        let entry: Entry = "10 d7026dc672344d3ee372217bdbc7395947788671 ima 6f66d1d8e2fffcc12dfcb78c04b81fe5b8bbae4e /usr/bin/kmod"
            .try_into().expect("unable to parse ima template");
        assert_eq!(entry.event_data.path(), "/usr/bin/kmod");
        let mut buf = vec![];
        entry
            .event_data
            .encode(&mut buf)
            .expect("unable to encode event data");
        assert_eq!(
            &buf,
            &hex::decode("6f66d1d8e2fffcc12dfcb78c04b81fe5b8bbae4e2f7573722f62696e2f6b6d6f640000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap(), //#[allow_ci]
        );
    }

    #[test]
    fn test_parse_ima_ng() {
        let entry: Entry = "10 7936eb315fb4e74b99e7d461bc5c96049e1ee092 ima-ng sha1:bc026ae66d81713e4e852465e980784dc96651f8 /usr/lib/systemd/systemd"
            .try_into().expect("unable to parse ima-ng template");
        assert_eq!(entry.event_data.path(), "/usr/lib/systemd/systemd");
        let mut buf = vec![];
        entry
            .event_data
            .encode(&mut buf)
            .expect("unable to encode event data");
        assert_eq!(
            &buf,
            &hex::decode("14000000bc026ae66d81713e4e852465e980784dc96651f8190000002f7573722f6c69622f73797374656d642f73797374656d6400").unwrap(), //#[allow_ci]
        );
    }

    #[test]
    fn test_parse_ima_sig() {
        let entry: Entry = "10 06e804489a77ddab51b9ef27e17053c0e5d503bd ima-sig sha1:1cb84b12db45d7da8de58ba6744187db84082f0e /usr/bin/zmore 030202531f402500483046022100bff9c02dc7b270c83cc94bfec10eecd42831de2cdcb04f024369a14623bc3a91022100cc4d015ae932fb98d6846645ed7d1bb1afd4621ec9089bc087126f191886dd31"
            .try_into().expect("unable to parse ima-sig template");
        assert_eq!(entry.event_data.path(), "/usr/bin/zmore");
        let mut buf = vec![];
        entry
            .event_data
            .encode(&mut buf)
            .expect("unable to encode event data");
        assert_eq!(
            &buf,
            &hex::decode("140000001cb84b12db45d7da8de58ba6744187db84082f0e0f0000002f7573722f62696e2f7a6d6f72650051000000030202531f402500483046022100bff9c02dc7b270c83cc94bfec10eecd42831de2cdcb04f024369a14623bc3a91022100cc4d015ae932fb98d6846645ed7d1bb1afd4621ec9089bc087126f191886dd31").unwrap(), //#[allow_ci]
        );
    }

    #[test]
    fn test_parse_ima_sig_missing() {
        let entry: Entry = "10 5426cf3031a43f5bfca183d79950698a95a728f6 ima-sig sha256:f1125b940480d20ad841d26d5ea253edc0704b5ec1548c891edf212cb1a9365e /lib/modules/5.4.48-openpower1/kernel/drivers/usb/common/usb-common.ko "
            .try_into().expect("unable to parse ima-sig template without signature");
        assert_eq!(entry.event_data.path(), "/lib/modules/5.4.48-openpower1/kernel/drivers/usb/common/usb-common.ko");
        let mut buf = vec![];
        entry
            .event_data
            .encode(&mut buf)
            .expect("unable to encode event data");
        assert_eq!(
            &buf,
            &hex::decode("280000007368613235363a00f1125b940480d20ad841d26d5ea253edc0704b5ec1548c891edf212cb1a9365e470000002f6c69622f6d6f64756c65732f352e342e34382d6f70656e706f776572312f6b65726e656c2f647269766572732f7573622f636f6d6d6f6e2f7573622d636f6d6d6f6e2e6b6f0000000000").unwrap(), //#[allow_ci]
        );
    }

    #[test]
    fn test_parse_ima_buf() {
        let entry: Entry = "10 b7862dbbf1383ac6c7cca7f02d981a081aacb1f1 ima-buf sha1:6e0e6fc8a188ef4f059638949adca4d221946906 device_resume 6e616d653d544553543b757569643d43525950542d5645524954592d39656633326535623635623034343234613561386562343436636630653731332d544553543b63617061636974793d303b6d616a6f723d3235333b6d696e6f723d303b6d696e6f725f636f756e743d313b6e756d5f746172676574733d313b6163746976655f7461626c655f686173683d346565383065333365353635643336333430356634303238393436653837623365396563306335383661666639656630656436663561653762656237326431333b"
            .try_into().expect("unable to parse ima-buf template");
        assert_eq!(entry.event_data.path(), "device_resume");
        let mut buf = vec![];
        entry
            .event_data
            .encode(&mut buf)
            .expect("unable to encode event data");
        assert_eq!(
            &buf,
            &hex::decode("140000006e0e6fc8a188ef4f059638949adca4d2219469060e0000006465766963655f726573756d6500ce0000006e616d653d544553543b757569643d43525950542d5645524954592d39656633326535623635623034343234613561386562343436636630653731332d544553543b63617061636974793d303b6d616a6f723d3235333b6d696e6f723d303b6d696e6f725f636f756e743d313b6e756d5f746172676574733d313b6163746976655f7461626c655f686173683d346565383065333365353635643336333430356634303238393436653837623365396563306335383661666639656630656436663561653762656237326431333b").unwrap(), //#[allow_ci]
        );
    }
}
