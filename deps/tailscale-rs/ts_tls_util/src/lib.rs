#![doc = include_str!("../README.md")]

use std::sync::{Arc, LazyLock};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;
pub use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::CertificateDer;
pub use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use url::Url;

#[cfg(feature = "insecure")]
mod insecure;

#[cfg(feature = "insecure")]
pub use insecure::connect_insecure;

static ROOT_CERT_STORE: LazyLock<Arc<RootCertStore>> = LazyLock::new(|| {
    Arc::new(RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    })
});

// ThinkTerm (private CA): every verified tailnet TLS path uses the same roots.
fn roots() -> std::io::Result<Arc<RootCertStore>> {
    let Some(path) = std::env::var_os("TS_TLS_EXTRA_CA_FILE") else {
        return Ok(ROOT_CERT_STORE.clone());
    };
    let pem = std::fs::read(path)?;
    let mut roots = (**ROOT_CERT_STORE).clone();
    let original_len = roots.len();
    for cert in CertificateDer::pem_slice_iter(&pem) {
        roots
            .add(cert.map_err(std::io::Error::other)?)
            .map_err(std::io::Error::other)?;
    }
    if roots.len() == original_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TS_TLS_EXTRA_CA_FILE contains no certificates",
        ));
    }
    Ok(Arc::new(roots))
}

/// Establishes a TLS stream with a server over an existing connection.
///
/// See module-level documentation for information on root certificates.
pub async fn connect<Io>(server_name: ServerName<'_>, io: Io) -> std::io::Result<TlsStream<Io>>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    connect_alpn::<Io>(server_name, io, []).await
}

/// Establishes a TLS stream with a server over an existing connection, with an optional set of
/// ALPN protocols to negotiate.
///
/// See module-level documentation for information on root certificates.
pub async fn connect_alpn<Io>(
    server_name: ServerName<'_>,
    io: Io,
    alpn: impl IntoIterator<Item = Vec<u8>>,
) -> tokio::io::Result<TlsStream<Io>>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    // TODO(npry): custom tls cert verifier to support commonname overrides and self-signed certs
    let mut rustls_config = ClientConfig::builder()
        .with_root_certificates(roots()?)
        .with_no_client_auth();

    rustls_config
        .alpn_protocols
        .extend(alpn.into_iter().map(|x| x.to_owned()));

    let connector = TlsConnector::from(Arc::new(rustls_config));

    let stream = connector.connect(server_name.to_owned(), io).await?;

    Ok(stream)
}

/// If possible, converts the host portion of the given [`Url`] to a [`ServerName`] for establishing
/// TLS streams.
pub fn server_name(url: &Url) -> Option<ServerName<'_>> {
    ServerName::try_from(url.host_str()?).ok()
}
