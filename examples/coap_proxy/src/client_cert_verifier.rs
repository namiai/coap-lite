use crate::banlist_checker::BanListChecker;
use crate::certificate::extract_cn_from_presented_certificates;
use std::error::Error;
use std::sync::Arc;
use tokio_rustls::rustls::internal::msgs::base::PayloadU16;
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::rustls::TLSError;
use tokio_rustls::rustls::{
    Certificate, ClientCertVerified, ClientCertVerifier, OwnedTrustAnchor,
};
use tokio_rustls::webpki;
use tokio_rustls::webpki::DNSName;

/// Which signature verification mechanisms we support.  No particular
/// order.
static SUPPORTED_SIG_ALGS: &[&webpki::SignatureAlgorithm] = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::ED25519,
    &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PKCS1_3072_8192_SHA384,
];

/// Allows any authenticated client that has the valid, not-banned certificate
///
pub struct AllowAuthenticatedClientsWithNotBannedCertificates<T>
where
    T: BanListChecker,
{
    roots: RootCertStore,
    banlist_checker: T,
}

impl<T> AllowAuthenticatedClientsWithNotBannedCertificates<T>
where
    T: BanListChecker + 'static,
{
    pub fn new(
        roots: RootCertStore,
        banlist_checker: T,
    ) -> Arc<dyn ClientCertVerifier> {
        Arc::new(AllowAuthenticatedClientsWithNotBannedCertificates {
            roots,
            banlist_checker,
        })
    }
}

impl<T> ClientCertVerifier
    for AllowAuthenticatedClientsWithNotBannedCertificates<T>
where
    T: BanListChecker,
{
    fn client_auth_root_subjects(
        &self,
        _: Option<&DNSName>,
    ) -> Option<Vec<PayloadU16>> {
        Some(self.roots.get_subjects())
    }

    fn verify_client_cert(
        &self,
        presented_certs: &[Certificate],
        _: Option<&DNSName>,
    ) -> Result<ClientCertVerified, TLSError> {
        let (cert, chain, trustroots) = prepare(&self.roots, presented_certs)?;
        let now = try_now()?;
        cert.verify_is_valid_tls_client_cert(
            SUPPORTED_SIG_ALGS,
            &webpki::TLSClientTrustAnchors(&trustroots),
            &chain,
            now,
        )
        .map_err(TLSError::WebPKIError)
        .map(|_| ClientCertVerified::assertion())?;

        let cn = extract_cn_from_presented_certificates(&presented_certs)
            .map_err(|e| {
                TLSError::General(
                    ClientCertificateAuthenticationError::BanCheckFailed(
                        e.to_string(),
                    )
                    .to_string(),
                )
            })?;

        let cn_is_banned =
            self.banlist_checker.cn_is_banned(&cn).map_err(|e| {
                TLSError::General(
                    ClientCertificateAuthenticationError::BanCheckFailed(
                        e.to_string(),
                    )
                    .to_string(),
                )
            })?;
        if cn_is_banned {
            info!("Rejecting access for the client with banned certificate, common name is {}", cn);
            Err(TLSError::General(
                ClientCertificateAuthenticationError::CommonNameIsBanned
                    .to_string(),
            ))
        } else {
            Ok(ClientCertVerified::assertion())
        }
    }
}

type CertChainAndRoots<'a, 'b> = (
    webpki::EndEntityCert<'a>,
    Vec<&'a [u8]>,
    Vec<webpki::TrustAnchor<'b>>,
);

#[derive(Debug)]
pub enum ClientCertificateAuthenticationError {
    CommonNameIsBanned,
    BanCheckFailed(String),
}

impl std::fmt::Display for ClientCertificateAuthenticationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientCertificateAuthenticationError::CommonNameIsBanned => {
                write!(f, "Common name is banned")
            }
            ClientCertificateAuthenticationError::BanCheckFailed(e) => write!(
                f,
                "Common name check failed due to the following error: {}",
                e
            ),
        }
    }
}

impl Error for ClientCertificateAuthenticationError {}

fn try_now() -> Result<webpki::Time, TLSError> {
    webpki::Time::try_from(std::time::SystemTime::now())
        .map_err(|_| TLSError::FailedToGetCurrentTime)
}

fn prepare<'a, 'b>(
    roots: &'b RootCertStore,
    presented_certs: &'a [Certificate],
) -> Result<CertChainAndRoots<'a, 'b>, TLSError> {
    if presented_certs.is_empty() {
        return Err(TLSError::NoCertificatesPresented);
    }

    // EE cert must appear first.
    let cert = webpki::EndEntityCert::from(&presented_certs[0].0)
        .map_err(TLSError::WebPKIError)?;

    let chain: Vec<&'a [u8]> = presented_certs
        .iter()
        .skip(1)
        .map(|cert| cert.0.as_ref())
        .collect();

    let trustroots: Vec<webpki::TrustAnchor> = roots
        .roots
        .iter()
        .map(OwnedTrustAnchor::to_trust_anchor)
        .collect();

    Ok((cert, chain, trustroots))
}
