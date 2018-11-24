/// This module contains optional APIs for implementing QUIC TLS.
use client::{ClientConfig, ClientSession, ClientSessionImpl};
use msgs::base::Payload;
use msgs::enums::{ExtensionType, ContentType, ProtocolVersion, AlertDescription};
use msgs::handshake::{ClientExtension, ServerExtension, UnknownExtension};
use msgs::message::{Message, MessagePayload};
use server::{ServerConfig, ServerSession, ServerSessionImpl};
use error::TLSError;
use key_schedule::{SecretKind, Protocol};
use session::SessionCommon;

use std::sync::Arc;
use webpki;

/// Secrets used to encrypt/decrypt traffic
pub struct Secrets {
    /// Secret used to encrypt packets transmitted by the client
    pub client: Vec<u8>,
    /// Secret used to encrypt packets transmitted by the server
    pub server: Vec<u8>,
}

/// Generic methods for QUIC sessions
pub trait QuicExt {
    /// Return the TLS-encoded transport parameters for the session's peer.
    fn get_quic_transport_parameters(&self) -> Option<&[u8]>;

    /// Consume unencrypted TLS handshake data.
    ///
    /// Handshake data obtained from separate encryption levels should be supplied in separate calls.
    fn read_hs(&mut self, plaintext: &[u8]) -> Result<(), TLSError>;

    /// Emit unencrypted TLS handshake data.
    ///
    /// This should be called until it writes nothing, checking for the changes in encryption level (i.e. availability
    /// of new secrets) after each call.
    fn write_hs(&mut self, buf: &mut Vec<u8>);

    /// Emit the TLS description code of a fatal alert, if one has arisen.
    ///
    /// Check after `read_hs` returns `Err(_)`.
    fn take_alert(&mut self) -> Option<AlertDescription>;

    /// Get the secrets used to encrypt/decrypt handshake traffic, if available
    fn get_handshake_secrets(&self) -> Option<Secrets>;

    /// Get the secrets used to encrypt/decrypt 1-RTT traffic, if available
    fn get_1rtt_secrets(&self) -> Option<Secrets>;

    /// Get 1-RTT secrets for use following a key update.
    ///
    /// This should only be called after `get_1rtt_secrets` has returned `Some(_)`.
    ///
    /// # Panics
    /// - If called before the handshake completes.
    fn update_1rtt_secrets(&mut self) -> Secrets;
}

impl QuicExt for ClientSession {
    fn get_quic_transport_parameters(&self) -> Option<&[u8]> {
        self.imp.common.quic.params.as_ref().map(|v| v.as_ref())
    }

    fn read_hs(&mut self, plaintext: &[u8]) -> Result<(), TLSError> {
        self.imp.common
            .handshake_joiner
            .take_message(Message {
                typ: ContentType::Handshake,
                version: ProtocolVersion::TLSv1_3,
                payload: MessagePayload::new_opaque(plaintext.into()),
            });
        self.imp.process_new_handshake_messages()?;
        Ok(())
    }

    fn write_hs(&mut self, buf: &mut Vec<u8>) {
        self.imp.common.sendable_tls.write_to(buf).unwrap();
    }

    fn take_alert(&mut self) -> Option<AlertDescription> { self.imp.common.quic.alert.take() }

    fn get_handshake_secrets(&self) -> Option<Secrets> { get_handshake_secrets(&self.imp.common) }

    fn get_1rtt_secrets(&self) -> Option<Secrets> { get_1rtt_secrets(&self.imp.common) }

    fn update_1rtt_secrets(&mut self) -> Secrets { update_1rtt_secrets(&mut self.imp.common) }
}

impl QuicExt for ServerSession {
    fn get_quic_transport_parameters(&self) -> Option<&[u8]> {
        self.imp.common.quic.params.as_ref().map(|v| v.as_ref())
    }

    fn read_hs(&mut self, plaintext: &[u8]) -> Result<(), TLSError> {
        self.imp.common
            .handshake_joiner
            .take_message(Message {
                typ: ContentType::Handshake,
                version: ProtocolVersion::TLSv1_3,
                payload: MessagePayload::new_opaque(plaintext.into()),
            });
        self.imp.process_new_handshake_messages()?;
        Ok(())
    }

    fn write_hs(&mut self, buf: &mut Vec<u8>) {
        self.imp.common.sendable_tls.write_to(buf).unwrap();
    }

    fn take_alert(&mut self) -> Option<AlertDescription> { self.imp.common.quic.alert.take() }

    fn get_handshake_secrets(&self) -> Option<Secrets> { get_handshake_secrets(&self.imp.common) }

    fn get_1rtt_secrets(&self) -> Option<Secrets> { get_1rtt_secrets(&self.imp.common) }

    fn update_1rtt_secrets(&mut self) -> Secrets { update_1rtt_secrets(&mut self.imp.common) }
}

fn get_handshake_secrets(this: &SessionCommon) -> Option<Secrets> {
    let key_schedule = this.key_schedule.as_ref()?;
    let handshake_hash = this.hs_transcript.get_current_hash();
    let client = key_schedule.derive(SecretKind::ClientHandshakeTrafficSecret, &handshake_hash);
    let server = key_schedule.derive(SecretKind::ServerHandshakeTrafficSecret, &handshake_hash);
    Some(Secrets { client, server })
}

fn get_1rtt_secrets(this: &SessionCommon) -> Option<Secrets> {
    if !this.traffic { return None; }
    let key_schedule = this.key_schedule.as_ref().unwrap();
    Some(Secrets {
        client: key_schedule.current_client_traffic_secret.clone(),
        server: key_schedule.current_server_traffic_secret.clone(),
    })
}

fn update_1rtt_secrets(this: &mut SessionCommon) -> Secrets {
    {
        let key_schedule = this.key_schedule.as_mut().unwrap();
        key_schedule.current_client_traffic_secret = key_schedule.derive_next(SecretKind::ClientApplicationTrafficSecret);
        key_schedule.current_server_traffic_secret = key_schedule.derive_next(SecretKind::ServerApplicationTrafficSecret);
    }
    get_1rtt_secrets(this).expect("handshake incomplete")
}

/// Methods specific to QUIC client sessions
pub trait ClientQuicExt {
    /// Make a new QUIC ClientSession. This differs from `ClientSession::new()`
    /// in that it takes an extra argument, `params`, which contains the
    /// TLS-encoded transport parameters to send.
    fn new_quic(config: &Arc<ClientConfig>, hostname: webpki::DNSNameRef, params: Vec<u8>)
                -> ClientSession {
        assert!(config.versions.iter().all(|x| x.get_u16() >= ProtocolVersion::TLSv1_3.get_u16()), "QUIC requires TLS version >= 1.3");
        let mut imp = ClientSessionImpl::new(config);
        imp.common.protocol = Protocol::Quic;
        imp.start_handshake(hostname.into(), vec![
            ClientExtension::Unknown(UnknownExtension {
                typ: ExtensionType::TransportParameters,
                payload: Payload::new(params),
            })
        ]);
        ClientSession { imp }
    }
}

impl ClientQuicExt for ClientSession {}

/// Methods specific to QUIC server sessions
pub trait ServerQuicExt {
    /// Make a new QUIC ServerSession. This differs from `ServerSession::new()`
    /// in that it takes an extra argument, `params`, which contains the
    /// TLS-encoded transport parameters to send.
    fn new_quic(config: &Arc<ServerConfig>, params: Vec<u8>) -> ServerSession {
        assert!(config.versions.iter().all(|x| x.get_u16() >= ProtocolVersion::TLSv1_3.get_u16()), "QUIC requires TLS version >= 1.3");
        let mut imp = ServerSessionImpl::new(config, vec![
                ServerExtension::Unknown(UnknownExtension {
                    typ: ExtensionType::TransportParameters,
                    payload: Payload::new(params),
                }),
        ]);
        imp.common.protocol = Protocol::Quic;
        ServerSession { imp }
    }
}

impl ServerQuicExt for ServerSession {}
