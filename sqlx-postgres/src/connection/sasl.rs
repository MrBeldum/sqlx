use crate::connection::stream::PgStream;
use crate::error::Error;
use crate::message::{Authentication, AuthenticationSasl, SaslInitialResponse, SaslResponse};
use crate::rt;
use crate::PgConnectOptions;
use hmac::{Hmac, Mac};
use hmac::{HmacReset, KeyInit};
use sha2::{Digest, Sha256};
use stringprep::saslprep;

use base64::prelude::{Engine as _, BASE64_STANDARD};
use rand::RngExt;

const GS2_HEADER: &str = "n,,";
const CHANNEL_ATTR: &str = "c";
const USERNAME_ATTR: &str = "n";
const CLIENT_PROOF_ATTR: &str = "p";
const NONCE_ATTR: &str = "r";

// Maximum SCRAM iteration count accepted from the server, matching
// `postgres-protocol` 0.6.12's `MAX_ITERATION_COUNT`. A malicious or
// compromised server can otherwise force unbounded PBKDF2 work with a huge
// `i=` value, keeping the client busy for a very long time.
const MAX_SCRAM_ITERATION_COUNT: u32 = 100_000;

pub(crate) async fn authenticate(
    stream: &mut PgStream,
    options: &PgConnectOptions,
    data: AuthenticationSasl,
) -> Result<(), Error> {
    let mut has_sasl = false;
    let mut has_sasl_plus = false;
    let mut unknown = Vec::new();

    for mechanism in data.mechanisms() {
        match mechanism {
            "SCRAM-SHA-256" => {
                has_sasl = true;
            }

            "SCRAM-SHA-256-PLUS" => {
                has_sasl_plus = true;
            }

            _ => {
                unknown.push(mechanism.to_owned());
            }
        }
    }

    if !has_sasl_plus && !has_sasl {
        return Err(err_protocol!(
            "unsupported SASL authentication mechanisms: {}",
            unknown.join(", ")
        ));
    }

    // channel-binding = "c=" base64
    let mut channel_binding = format!("{CHANNEL_ATTR}=");
    BASE64_STANDARD.encode_string(GS2_HEADER, &mut channel_binding);

    // "n=" saslname ;; Usernames are prepared using SASLprep.
    let username = format!("{}={}", USERNAME_ATTR, options.username);
    let username = match saslprep(&username) {
        Ok(v) => v,
        Err(error) => {
            return Err(Error::Configuration(
                format!("Failed to saslprep username: {:?}", error).into(),
            ))
        }
    };

    // nonce = "r=" c-nonce [s-nonce] ;; Second part provided by server.
    let client_nonce = gen_nonce();
    let nonce = format!("{NONCE_ATTR}={client_nonce}");

    // client-first-message-bare = [reserved-mext ","] username "," nonce ["," extensions]
    let client_first_message_bare = format!("{username},{nonce}");

    let client_first_message = format!("{GS2_HEADER}{client_first_message_bare}");

    stream
        .send(SaslInitialResponse {
            response: &client_first_message,
            plus: false,
        })
        .await?;

    let cont = match stream.recv_expect().await? {
        Authentication::SaslContinue(data) => data,

        auth => {
            return Err(err_protocol!(
                "expected SASLContinue but received {:?}",
                auth
            ));
        }
    };

    // Validate the server-first message before spending any PBKDF2 work.
    validate_server_first_message(&client_nonce, &cont.nonce, cont.iterations)?;

    // Normalize(password):
    let password = options.password.as_deref().unwrap_or_default();
    let password = match saslprep(password) {
        Ok(v) => v,
        Err(error) => {
            return Err(Error::Configuration(
                format!("Failed to saslprep password: {:?}", error).into(),
            ))
        }
    };

    // SaltedPassword := Hi(Normalize(password), salt, i)
    let salted_password = hi(&password, &cont.salt, cont.iterations).await?;

    // ClientKey := HMAC(SaltedPassword, "Client Key")
    let mut mac = Hmac::<Sha256>::new_from_slice(&salted_password).map_err(Error::protocol)?;
    mac.update(b"Client Key");

    let client_key = mac.finalize().into_bytes();

    // StoredKey := H(ClientKey)
    let stored_key = Sha256::digest(client_key);

    // client-final-message-without-proof
    let client_final_message_wo_proof = format!(
        "{channel_binding},r={nonce}",
        channel_binding = channel_binding,
        nonce = &cont.nonce
    );

    // AuthMessage := client-first-message-bare + "," + server-first-message + "," + client-final-message-without-proof
    let auth_message = format!(
        "{client_first_message_bare},{server_first_message},{client_final_message_wo_proof}",
        client_first_message_bare = client_first_message_bare,
        server_first_message = cont.message,
        client_final_message_wo_proof = client_final_message_wo_proof
    );

    // ClientSignature := HMAC(StoredKey, AuthMessage)
    let mut mac = Hmac::<Sha256>::new_from_slice(&stored_key).map_err(Error::protocol)?;
    mac.update(auth_message.as_bytes());

    let client_signature = mac.finalize().into_bytes();

    // ClientProof := ClientKey XOR ClientSignature
    let client_proof: Vec<u8> = client_key
        .iter()
        .zip(client_signature.iter())
        .map(|(&a, &b)| a ^ b)
        .collect();

    // ServerKey := HMAC(SaltedPassword, "Server Key")
    let mut mac = Hmac::<Sha256>::new_from_slice(&salted_password).map_err(Error::protocol)?;
    mac.update(b"Server Key");

    let server_key = mac.finalize().into_bytes();

    // ServerSignature := HMAC(ServerKey, AuthMessage)
    let mut mac = Hmac::<Sha256>::new_from_slice(&server_key).map_err(Error::protocol)?;
    mac.update(auth_message.as_bytes());

    // client-final-message = client-final-message-without-proof "," proof
    let mut client_final_message = format!("{client_final_message_wo_proof},{CLIENT_PROOF_ATTR}=");
    BASE64_STANDARD.encode_string(client_proof, &mut client_final_message);

    stream.send(SaslResponse(&client_final_message)).await?;

    let data = match stream.recv_expect().await? {
        Authentication::SaslFinal(data) => data,

        auth => {
            return Err(err_protocol!("expected SASLFinal but received {:?}", auth));
        }
    };

    // authentication is only considered valid if this verification passes
    mac.verify_slice(&data.verifier).map_err(Error::protocol)?;

    Ok(())
}

// Validate the SCRAM server-first message before doing any PBKDF2 work.
//
// RFC 5802 describes the server nonce as the client nonce followed by
// server-chosen characters; a server that replays the client nonce, shortens
// it, or otherwise drops the client-nonce prefix is rejected. The iteration
// count is bounded so a hostile server cannot force unbounded work.
fn validate_server_first_message(
    client_nonce: &str,
    server_nonce: &str,
    iterations: u32,
) -> Result<(), Error> {
    if !server_nonce.starts_with(client_nonce) || server_nonce.len() <= client_nonce.len() {
        return Err(err_protocol!(
            "server nonce does not contain the client nonce"
        ));
    }

    if iterations > MAX_SCRAM_ITERATION_COUNT {
        return Err(err_protocol!(
            "server iteration count ({iterations}) exceeds the maximum of {MAX_SCRAM_ITERATION_COUNT}"
        ));
    }

    Ok(())
}

// nonce is a sequence of random printable bytes
fn gen_nonce() -> String {
    let mut rng = rand::rng();
    let count = rng.random_range(64..128);

    // printable = %x21-2B / %x2D-7E
    // ;; Printable ASCII except ",".
    // ;; Note that any "printable" is also
    // ;; a valid "value".
    let nonce: String = std::iter::repeat(())
        .map(|()| {
            let mut c = rng.random_range(0x21u8..0x7F);

            while c == 0x2C {
                c = rng.random_range(0x21u8..0x7F);
            }

            c
        })
        .take(count)
        .map(|c| c as char)
        .collect();

    nonce
}

// Hi(str, salt, i):
async fn hi<'a>(s: &'a str, salt: &'a [u8], iter_count: u32) -> Result<[u8; 32], Error> {
    let mut mac = HmacReset::<Sha256>::new_from_slice(s.as_bytes()).map_err(Error::protocol)?;

    mac.update(salt);
    mac.update(&1u32.to_be_bytes());

    let mut u = mac.finalize_reset().into_bytes();
    let mut hi = u;

    for i in 1..iter_count {
        mac.update(u.as_slice());
        u = mac.finalize_reset().into_bytes();
        hi = hi.iter().zip(u.iter()).map(|(&a, &b)| a ^ b).collect();

        // For large iteration counts, this process can take a long time and block the event loop.
        // It was measured as taking ~50ms for 4096 iterations (the default) on a developer machine.
        // If we want to yield every 10-100us (as generally advised for tokio), then we can yield
        // every 5 iterations which should be every ~50us.
        if i % 5 == 0 {
            rt::yield_now().await;
        }
    }

    Ok(hi.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regression tests for transact-rs/sqlx#4451: the SCRAM-SHA-256 client
    // must bound the server iteration count and must verify that the server
    // nonce extends the client nonce (RFC 5802).

    #[test]
    fn rejects_unbounded_iteration_count() {
        // i=u32::MAX from a hostile server must not be accepted.
        assert!(
            validate_server_first_message("clientnonce", "clientnonceSERVER", u32::MAX).is_err()
        );
    }

    #[test]
    fn iteration_count_boundary() {
        // 100,000 matches `postgres-protocol`'s MAX_ITERATION_COUNT precedent.
        assert!(validate_server_first_message("c", "cS", 100_000).is_ok());
        assert!(validate_server_first_message("c", "cS", 100_001).is_err());
    }

    #[test]
    fn rejects_server_nonce_without_client_prefix() {
        assert!(validate_server_first_message("clientnonce", "attacker-chosen", 4096).is_err());
    }

    #[test]
    fn rejects_server_nonce_replaying_client_nonce() {
        // RFC 5802: the server must append its own characters; a bare replay
        // of the client nonce is not acceptable.
        assert!(validate_server_first_message("clientnonce", "clientnonce", 4096).is_err());
    }

    #[test]
    fn accepts_valid_server_first_message() {
        assert!(validate_server_first_message("clientnonce", "clientnonceSERVER", 4096).is_ok());
    }
}
