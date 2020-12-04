#[macro_use]
use log::*;

use crate::common::config_get;
use crate::crypto;
use crate::error;
use crate::error::{Error, Result};
use crate::secure_mount;

use std::path::Path;

use serde_json::Value;

/// Handles revocation messages via 0mq
/// See:
/// - URL: https://github.com/keylime/keylime/blob/master/keylime/revocation_notifier.py
///   Function: await_notifications
pub(crate) async fn run_revocation_service() -> Result<()> {
    let mount = secure_mount::mount()?;
    let revocation_cert_path =
        format!("{}/unzipped/RevocationNotifier-cert.crt", mount);

    // Connect to the service via 0mq
    let context = zmq::Context::new();
    let mysock = context.socket(zmq::SUB)?;

    mysock.set_subscribe(b"")?;

    let revocation_ip =
        config_get("/etc/keylime.conf", "general", "receive_revocation_ip")?;
    let revocation_port = config_get(
        "/etc/keylime.conf",
        "general",
        "receive_revocation_port",
    )?;
    let endpoint = format!("{}:{}", revocation_ip, revocation_port);

    mysock.connect(endpoint.as_str())?;

    // Unlike the python agent we do not attempt lazy loading. We either
    // have the certificate, or we don't. If we don't have a key or can't load
    // the key we return a Configuration error as the service will not work.
    let cert_key = if Path::new(&revocation_cert_path).exists() {
        info!(
            "Loading the revocation certificate from {}",
            revocation_cert_path
        );
        match crypto::rsa_import_pubkey(revocation_cert_path) {
            Ok(v) => v,
            Err(e) => {
                return Err(error::Error::Configuration(String::from(
                    "Can not load pubkey",
                )))
            }
        }
    } else {
        error!("Path for the 0mq socket socket doesn't exist");
        return Err(error::Error::Configuration(String::from(
            "Path for the 0mq socket socket doesn't exist",
        )));
    };

    info!("Waiting for revocation messages on 0mq {}", endpoint);

    // Main revocation service loop. If a message is malformed or
    // can not be verified the loop continues.
    loop {
        let mut rawbody = match mysock.recv_string(0) {
            Ok(v) => match v {
                Ok(v) => v,
                _ => {
                    warn!("Unable to read message from 0mq");
                    continue;
                }
            },
            Err(e) => {
                warn!("Unable to read message from 0mq");
                continue;
            }
        };

        let body: Value = serde_json::from_str(rawbody.as_str())?;

        // Ensure we have a signature, otherwise continue the loop
        let signature = match body["signature"].as_str() {
            Some(v) => v,
            _ => {
                warn!("No signature on revocation message from server");
                continue;
            }
        };

        // Ensure we have a msg, otherwise continue the loop
        let message = match body["msg"].as_str() {
            Some(v) => v,
            _ => {
                warn!("No msg on revocation message from server");
                continue;
            }
        };

        // Verify the message and signature with our key
        let mut verified =
            crypto::rsa_verify(cert_key.clone(), message, signature);

        match verified {
            Ok(true) => {
                let msg = body["msg"].as_str();
                let msg_payload: Value =
                    serde_json::from_str(match msg.as_deref() {
                        Some(v) => v,
                        _ => {
                            warn!("Unable to decode json in msg");
                            continue;
                        }
                    })?;
                debug!(
                    "Revocation signature validated for revocation: {}",
                    msg_payload
                );
                // TODO: Implement callback
                //callback(msg_payload)
            }
            _ => {
                error!("Invalid revocation message siganture {}", body);
            }
        }
    }
    Ok(())
}
