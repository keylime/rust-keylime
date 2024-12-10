// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Keylime Authors
use openssl::{
    asn1::Asn1Time,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    x509::{extension, X509Extension, X509Name, X509},
};
use thiserror::Error;

static LOCAL_IPS: &[&str] = &["127.0.0.1", "::1"];
static LOCAL_DNS_NAMES: &[&str] = &["localhost", "localhost.domain"];

#[derive(Error, Debug)]
pub enum CertificateBuilderError {
    /// Error getting ASN.1 Time from days from now
    #[error("failed to get ASN.1 Time for {days} day(s) from now")]
    ASN1TimeDaysFromNowError {
        days: u32,
        source: openssl::error::ErrorStack,
    },

    /// X509 certificate builder error
    #[error("X509 certificate builder error: {message}")]
    BuilderError {
        message: String,
        source: openssl::error::ErrorStack,
    },

    /// Failed to get public key from the private key
    #[error("failed to get public key from the private key")]
    PubkeyFromPrivError { source: crate::crypto::CryptoError },

    /// Common name not set on CertificateBuilder
    #[error("Common Name not set on CertificateBuilder. Set the common name with the common_name() method from the CertificateBuilder object")]
    MissingCommonNameError,

    /// Private key not set on CertificateBuilder
    #[error("Private key not set on CertificateBuilder. Set the private key with the private_key() method from the CertificateBuilder object")]
    MissingPrivateKeyError,

    /// Error creating X509 Name
    #[error("Error creating X509 Name: {message}")]
    NameBuilderError {
        message: String,
        source: openssl::error::ErrorStack,
    },
}

#[derive(Default)]
pub struct CertificateBuilder<'a> {
    common_name: Option<&'a str>,
    dns_names: Option<Vec<&'a str>>,
    extensions: Option<Vec<X509Extension>>,
    hash_algorithm: Option<MessageDigest>,
    ips: Option<Vec<&'a str>>,
    not_after: Option<u32>,
    not_before: Option<u32>,
    private_key: Option<&'a PKey<Private>>,
    version: Option<i32>,
}

impl<'a> CertificateBuilder<'a> {
    /// Create a new CertificateBuilder object
    pub fn new() -> CertificateBuilder<'a> {
        CertificateBuilder::default()
    }

    /// Set the CertificateBuilder Common Name to use when generating the certificate
    ///
    /// # Arguments:
    ///
    /// * cn (&str): The subject Common Name
    pub fn common_name(
        &'a mut self,
        cn: &'a str,
    ) -> &'a mut CertificateBuilder<'a> {
        self.common_name = Some(cn);
        self
    }

    /// Set the hash algorithm to be used when signing the certificate
    ///
    /// # Arguments:
    ///
    /// * hash_algorithm (MessageDigest): The hash algorithm to be used when signing the certificate
    pub fn hash_algorithm(
        &'a mut self,
        hash_algorithm: MessageDigest,
    ) -> &'a mut CertificateBuilder<'a> {
        self.hash_algorithm = Some(hash_algorithm);
        self
    }

    /// Set the certificate start of validity, in days from now
    ///
    /// # Arguments:
    ///
    /// * days_from_now (u32): The number of days from now when the built certificate will become
    ///   valid
    pub fn not_before(
        &'a mut self,
        days_from_now: u32,
    ) -> &'a mut CertificateBuilder<'a> {
        self.not_before = Some(days_from_now);
        self
    }

    /// Set the certificate expiration date, in days from now
    ///
    /// # Arguments:
    ///
    /// * days_from_now (u32): The number of days from now when the built certificate will expire
    pub fn not_after(
        &'a mut self,
        days_from_now: u32,
    ) -> &'a mut CertificateBuilder<'a> {
        self.not_after = Some(days_from_now);
        self
    }

    /// Set the certificate X.509 standard version.
    ///
    /// # Arguments:
    ///
    /// * version (i32): The version number. Note that the version is zero-indexed, meaning passing
    ///   the value `2` corresponds to the version 3 of the X.509 standard
    ///
    /// If not called, the version 3 of the X.509 standard will be used
    pub fn version(
        &'a mut self,
        version: i32,
    ) -> &'a mut CertificateBuilder<'a> {
        self.version = Some(version);
        self
    }

    /// Set the private key associated with the certificate
    ///
    /// # Arguments:
    ///
    /// * private_key (PKey<Private>): The private key to be associated with the certificate
    pub fn private_key(
        &'a mut self,
        private_key: &'a PKey<Private>,
    ) -> &'a mut CertificateBuilder<'a> {
        self.private_key = Some(private_key);
        self
    }

    /// Set DNS names to add to the Subject Alternative Name
    ///
    /// # Arguments:
    ///
    /// * dns_names (Vec<&str>): A Vec<&str> containing DNS names to add to the certificate Subject
    ///   Alternative Name
    pub fn add_dns_names(
        &'a mut self,
        dns_names: Vec<&'a str>,
    ) -> &'a mut CertificateBuilder<'a> {
        match &mut self.dns_names {
            None => {
                self.dns_names = Some(dns_names);
            }
            Some(v) => {
                for name in dns_names {
                    v.push(name);
                }
            }
        }
        self
    }

    /// Set additional IPs to add to the Subject Alternative Name
    ///
    /// # Arguments:
    ///
    /// * ips: (Vec<&str>): A Vec<&str> containing IPs to add to the certificate Subject
    ///   Alternative Name
    pub fn add_ips(
        &'a mut self,
        ips: Vec<&'a str>,
    ) -> &'a mut CertificateBuilder<'a> {
        match &mut self.ips {
            None => {
                self.ips = Some(ips);
            }
            Some(v) => {
                for ip in ips {
                    v.push(ip);
                }
            }
        }
        self
    }

    /// Set additional extensions to include in the certificate
    ///
    /// # Arguments:
    ///
    /// * extensions (Vec<X509Extension>): A Vec<X509Extension> containing the additional
    ///   extensions to include in the certificate
    pub fn add_extensions(
        &'a mut self,
        extensions: Vec<X509Extension>,
    ) -> &'a mut CertificateBuilder<'a> {
        match &mut self.extensions {
            None => {
                self.extensions = Some(extensions);
            }
            Some(v) => {
                for extension in extensions {
                    v.push(extension);
                }
            }
        }
        self
    }

    /// Generate the certificate using the previously set options
    pub fn build(&'a mut self) -> Result<X509, CertificateBuilderError> {
        let mut name_builder = X509Name::builder().map_err(|source| {
            CertificateBuilderError::NameBuilderError {
                message: "failed to create X509 Name object".into(),
                source,
            }
        })?;

        let mut builder = X509::builder().map_err(|source| {
            CertificateBuilderError::BuilderError {
                message: "failed to create X509 certificate builder object"
                    .into(),
                source,
            }
        })?;

        match self.common_name {
            Some(cn) => {
                name_builder
                    .append_entry_by_nid(Nid::COMMONNAME, cn)
                    .map_err(|source| {
                        CertificateBuilderError::NameBuilderError {
                            message:
                                "failed to set Common Name in Name builder"
                                    .into(),
                            source,
                        }
                    })?;
            }
            None => {
                return Err(CertificateBuilderError::MissingCommonNameError);
            }
        }

        let name = name_builder.build();
        builder.set_subject_name(&name).map_err(|source| {
            CertificateBuilderError::BuilderError {
                message: "failed to set X509 certificate subject name".into(),
                source,
            }
        })?;

        // Self-signed certificate, the issuer is the same as the subject
        builder.set_issuer_name(&name).map_err(|source| {
            CertificateBuilderError::BuilderError {
                message: "failed to set X509 issuer name".into(),
                source,
            }
        })?;

        // If the not_before is not set, use the default value of 0 to make the certificate valid
        // from now
        let not_before = self.not_before.unwrap_or(0);
        let valid_from =
            Asn1Time::days_from_now(not_before).map_err(|source| {
                CertificateBuilderError::ASN1TimeDaysFromNowError {
                    days: not_before,
                    source,
                }
            })?;
        builder.set_not_before(&valid_from).map_err(|source| {
            CertificateBuilderError::BuilderError {
                message: "failed to set X509 certificate Not Before date"
                    .into(),
                source,
            }
        })?;

        // If the not_after is not set, use the default value of 365 days
        let not_after = self.not_after.unwrap_or(365);
        let valid_to =
            Asn1Time::days_from_now(not_after).map_err(|source| {
                CertificateBuilderError::ASN1TimeDaysFromNowError {
                    days: not_after,
                    source,
                }
            })?;
        builder.set_not_after(&valid_to).map_err(|source| {
            CertificateBuilderError::BuilderError {
                message: "failed to set X509 certificate Not After date"
                    .into(),
                source,
            }
        })?;

        // If the version is not set, use the default value 2, which corresponds to X.509 version 3
        let v = self.version.unwrap_or(2);
        builder.set_version(v).map_err(|source| {
            CertificateBuilderError::BuilderError {
                message: "failed to set X509 certificate version".into(),
                source,
            }
        })?;

        match self.private_key {
            Some(p) => {
                let pubkey = crate::crypto::pkey_pub_from_priv(p).map_err(
                    |source| CertificateBuilderError::PubkeyFromPrivError {
                        source,
                    },
                )?;

                builder.set_pubkey(&pubkey).map_err(|source| {
                    CertificateBuilderError::BuilderError {
                        message: "failed to set X509 certificate public key"
                            .into(),
                        source,
                    }
                })?;

                let h =
                    self.hash_algorithm.unwrap_or(MessageDigest::sha256());
                builder
                    .sign(p, h)
                    .map_err(|source| CertificateBuilderError::BuilderError {
                        message: "failed to set X509 certificate builder signing private key and hashing algorithm".into(),
                        source,
                    })?;
            }
            None => {
                return Err(CertificateBuilderError::MissingPrivateKeyError);
            }
        }

        // Build Subject Alternative Name
        let mut san = &mut extension::SubjectAlternativeName::new();
        for dns_name in LOCAL_DNS_NAMES.iter() {
            san = san.dns(dns_name);
        }

        if let Some(dns_names) = &self.dns_names {
            for dns_name in
                dns_names.iter().filter(|&n| !LOCAL_DNS_NAMES.contains(n))
            {
                san = san.dns(dns_name);
            }
        }

        for local_ip in LOCAL_IPS.iter() {
            san = san.ip(local_ip);
        }

        if let Some(additional_ips) = &self.ips {
            for ip in
                additional_ips.iter().filter(|&i| !LOCAL_IPS.contains(i))
            {
                san = san.ip(ip);
            }
        }

        let x509 = san.build(&builder.x509v3_context(None, None)).map_err(
            |source| CertificateBuilderError::BuilderError {
                message: "failed to build Subject Alternative Name".into(),
                source,
            },
        )?;
        builder.append_extension(x509).map_err(|source| {
            CertificateBuilderError::BuilderError {
                message:
                    "failed to append X509 certificate Subject Alternative Name extension"
                        .into(),
                source,
            }
        })?;

        Ok(builder.build())
    }
}

// Unit Testing
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::*;

    fn test_generate_certificate(
        privkey: PKey<Private>,
        pubkey: PKey<Public>,
    ) {
        // Minimal certificate
        let r = CertificateBuilder::new()
            .private_key(&privkey)
            .common_name("uuidA")
            .build();
        assert!(r.is_ok());
        let cert = r.unwrap(); //#[allow_ci]
        let cert_pubkey_pem =
            cert.public_key().unwrap().public_key_to_pem().unwrap(); //#[allow_ci]
        let pubkey_pem = pubkey.public_key_to_pem().unwrap(); //#[allow_ci]
        assert_eq!(cert_pubkey_pem, pubkey_pem);

        // Setting hash algorithm
        let r = CertificateBuilder::new()
            .private_key(&privkey)
            .common_name("uuidA")
            .hash_algorithm(MessageDigest::sha512())
            .build();
        assert!(r.is_ok());
        let cert = r.unwrap(); //#[allow_ci]
        let sig_alg = cert
            .signature_algorithm()
            .object()
            .nid()
            .signature_algorithms()
            .unwrap(); //#[allow_ci]
        assert_eq!(sig_alg.digest, openssl::nid::Nid::SHA512);

        // Setting certificate validity not_before
        let two_days_from_now = Asn1Time::days_from_now(2).unwrap(); //#[allow_ci]
        let r = CertificateBuilder::new()
            .not_before(2)
            .private_key(&privkey)
            .common_name("uuidA")
            .build();
        assert!(r.is_ok());
        let cert = r.unwrap(); //#[allow_ci]
                               // There is a very small chance that this will fail when the value for the full second
                               // changes between the time the certificate is generated and now
        assert!(cert.not_before() == two_days_from_now);

        // Setting certificate validity not_after
        let ten_days_from_now = Asn1Time::days_from_now(10).unwrap(); //#[allow_ci]
        let r = CertificateBuilder::new()
            .private_key(&privkey)
            .common_name("uuidA")
            .not_after(10)
            .build();
        assert!(r.is_ok());
        let cert = r.unwrap(); //#[allow_ci]
                               // There is a very small chance that this will fail when the value for the full second
                               // changes between the time the certificate is generated and now
        assert!(cert.not_after() == ten_days_from_now);

        // Setting certificate version explicitly
        let r = CertificateBuilder::new()
            .private_key(&privkey)
            .common_name("uuidA")
            .version(2)
            .build();
        assert!(r.is_ok());
        let cert = r.unwrap(); //#[allow_ci]
        assert_eq!(cert.version(), 2);

        // Adding extra DNS names
        let r = CertificateBuilder::new()
            .private_key(&privkey)
            .common_name("uuidA")
            .add_dns_names(vec!["hostname", "hostname2"])
            .build();
        assert!(r.is_ok());
        let cert = r.unwrap(); //#[allow_ci]
        let san: Vec<String> = cert
            .subject_alt_names()
            .unwrap() //#[allow_ci]
            .into_iter()
            .filter_map(|n| n.dnsname().map(|n| n.to_owned()))
            .collect();
        assert!(san.contains(&"hostname".to_string()));
        assert!(san.contains(&"hostname2".to_string()));

        // Adding extra IPv4 addresses
        let r = CertificateBuilder::new()
            .private_key(&privkey)
            .common_name("uuidA")
            .add_ips(vec!["192.168.0.1", "172.30.1.15"])
            .build();
        assert!(r.is_ok());
        let cert = r.unwrap(); //#[allow_ci]
        let san: Vec<Vec<u8>> = cert
            .subject_alt_names()
            .unwrap() //#[allow_ci]
            .into_iter()
            .filter_map(|i| i.ipaddress().map(|i| i.to_owned()))
            .collect();
        assert!(san.contains(
            &"192.168.0.1"
                .parse::<std::net::Ipv4Addr>()
                .unwrap() //#[allow_ci]
                .octets()
                .as_ref()
                .to_owned()
        ));
        assert!(san.contains(
            &"172.30.1.15"
                .parse::<std::net::Ipv4Addr>()
                .unwrap() //#[allow_ci]
                .octets()
                .as_ref()
                .to_owned()
        ));

        // Adding extra IPv6 addresses
        let r = CertificateBuilder::new()
            .private_key(&privkey)
            .common_name("uuidA")
            .add_ips(vec!["::2:3", "::4:5"])
            .build();
        assert!(r.is_ok());
        let cert = r.unwrap(); //#[allow_ci]
        let san: Vec<Vec<u8>> = cert
            .subject_alt_names()
            .unwrap() //#[allow_ci]
            .into_iter()
            .filter_map(|n| n.ipaddress().map(|n| n.to_owned()))
            .collect();
        assert!(san.contains(
            &"::2:3"
                .parse::<std::net::Ipv6Addr>()
                .unwrap() //#[allow_ci]
                .octets()
                .as_ref()
                .to_owned()
        ));
        assert!(san.contains(
            &"::4:5"
                .parse::<std::net::Ipv6Addr>()
                .unwrap() //#[allow_ci]
                .octets()
                .as_ref()
                .to_owned()
        ));

        // Adding extra extensions
        let bc = x509::extension::BasicConstraints::new()
            .ca()
            .critical()
            .build()
            .unwrap(); //#[allow_ci]
        let r = CertificateBuilder::new()
            .private_key(&privkey)
            .common_name("uuidA")
            .add_extensions(vec![bc])
            .build();
        assert!(r.is_ok());
    }

    #[test]
    fn test_generate_rsa_certificate() {
        let (pubkey, privkey) = rsa_generate_pair(2048).unwrap(); //#[allow_ci]
        test_generate_certificate(privkey, pubkey);
    }

    #[test]
    #[ignore]
    fn test_generate_long_rsa_certificate() {
        for length in [3072, 4096] {
            let (pubkey, privkey) = rsa_generate_pair(length).unwrap(); //#[allow_ci]
            test_generate_certificate(privkey, pubkey);
        }
    }

    #[test]
    fn test_generate_ecc_certificate() {
        use openssl::ec::EcGroup;

        for group in [
            EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap(), //#[allow_ci]
            EcGroup::from_curve_name(Nid::SECP256K1).unwrap(), //#[allow_ci]
            EcGroup::from_curve_name(Nid::SECP384R1).unwrap(), //#[allow_ci],
            EcGroup::from_curve_name(Nid::SECP521R1).unwrap(), //#[allow_ci]
        ] {
            let (pubkey, privkey) = ecc_generate_pair(&group).unwrap(); //#[allow_ci]

            test_generate_certificate(privkey, pubkey);
        }
    }
}
