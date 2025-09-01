use anyhow::{Context, Result};
use std::{
    fs::{self, File},
    io::Read,
    time::Duration,
};

pub struct ClientArgs {
    pub ca_certificate: String,
    pub certificate: String,
    pub key: String,
    pub insecure: Option<bool>,
    pub timeout: u64,
    /// Accept invalid TLS hostnames (INSECURE - for testing only)
    pub accept_invalid_hostnames: bool,
}

pub fn get_https_client(args: &ClientArgs) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .connection_verbose(true)
        .timeout(Duration::from_millis(args.timeout));

    if args.insecure.unwrap_or(false) {
        builder = builder.danger_accept_invalid_certs(true);
    } else {
        // Get CA certificate from file
        let mut buf = Vec::new();
        File::open(args.ca_certificate.clone())
            .context(format!(
                "Failed to open '{}' file",
                args.ca_certificate
            ))?
            .read_to_end(&mut buf)
            .context(format!(
                "Failed to read '{}' to the end",
                args.ca_certificate
            ))?;
        let ca_cert =
            reqwest::Certificate::from_pem(&buf).context(format!(
                "Failed to parse certificate from PEM file '{}'",
                args.ca_certificate
            ))?;

        // Get client key and certificate from files
        let cert = fs::read(args.certificate.clone()).context(format!(
            "Failed to read client certificate from file '{}'",
            args.certificate
        ))?;
        let key = fs::read(args.key.clone()).context(format!(
            "Failed to read key from file '{}'",
            args.key
        ))?;
        let identity = reqwest::Identity::from_pkcs8_pem(&cert, &key)
            .context(format!(
            "Failed to add client identity from certificate '{}' and key '{}'",
            args.certificate,
            args.key
        ))?;

        builder = builder
            .add_root_certificate(ca_cert)
            .identity(identity)
            .danger_accept_invalid_hostnames(args.accept_invalid_hostnames);
    }
    builder.build().context("Failed to create HTTPS client")
}
