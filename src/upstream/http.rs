use std::future::{Future, poll_fn};
use std::io;
use std::pin::pin;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::task::Poll;
use std::time::Instant;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{
    ClientConfig, RootCertStore,
    crypto::ring,
    pki_types::{CertificateDer, ServerName, pem::PemObject},
};

use super::{Cancellation, MAX_FRAME, VERSION};

pub(super) struct Http {
    runtime: tokio::runtime::Runtime,
    uri: Uri,
    route: SocketAddr,
    tls: Option<(TlsConnector, ServerName<'static>)>,
    session: Option<HeaderValue>,
    version: Option<&'static str>,
    authorization: Option<HeaderValue>,
}

pub(super) fn endpoint(url: &str, ip: Option<&str>) -> io::Result<(Uri, SocketAddr)> {
    let uri: Uri = url.parse().map_err(io::Error::other)?;
    let authority = uri.authority().ok_or_else(invalid)?;
    if authority.as_str().contains('@') || uri.query().is_some() || uri.path().len() > 512 {
        return Err(invalid());
    }
    let (address, port) = match uri.scheme_str() {
        Some("http") if uri.host() == Some("127.0.0.1") && ip.is_none() => (
            Ipv4Addr::LOCALHOST.into(),
            uri.port_u16().ok_or_else(invalid)?,
        ),
        Some("https") => {
            let host = uri.host().ok_or_else(invalid)?.trim_matches(['[', ']']);
            ServerName::try_from(host).map_err(io::Error::other)?;
            let address: IpAddr = ip.unwrap_or(host).parse().map_err(|_| {
                io::Error::other("HTTPS upstreams require an explicit numeric connect_ip")
            })?;
            (address, uri.port_u16().unwrap_or(443))
        }
        _ => {
            return Err(io::Error::other(
                "Use loopback HTTP or a verified HTTPS upstream",
            ));
        }
    };
    if address.is_unspecified() || address.is_multicast() || port == 0 {
        return Err(invalid());
    }
    Ok((uri, SocketAddr::new(address, port)))
}

impl Http {
    pub fn new(
        uri: Uri,
        route: SocketAddr,
        token: Option<String>,
        ca: Option<Vec<u8>>,
    ) -> io::Result<Self> {
        let tls = match uri.scheme_str() {
            Some("https") => {
                let host = uri.host().ok_or_else(invalid)?.trim_matches(['[', ']']);
                let server_name =
                    ServerName::try_from(host.to_owned()).map_err(io::Error::other)?;
                let certificates = match ca {
                    Some(ca) => ca,
                    None => read_system_roots()?,
                };
                let mut roots = RootCertStore::empty();
                let certs = CertificateDer::pem_slice_iter(&certificates)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(io::Error::other)?;
                if roots.add_parsable_certificates(certs).0 == 0 {
                    return Err(io::Error::other("No usable trust roots for upstream TLS"));
                }
                let config =
                    ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
                        .with_safe_default_protocol_versions()
                        .map_err(io::Error::other)?
                        .with_root_certificates(roots)
                        .with_no_client_auth();
                Some((TlsConnector::from(Arc::new(config)), server_name))
            }
            _ if token.is_none() && ca.is_none() => None,
            _ => return Err(io::Error::other("Upstream credentials require HTTPS")),
        };
        let authorization = token
            .map(|token| {
                let mut value =
                    HeaderValue::from_str(&format!("Bearer {token}")).map_err(io::Error::other)?;
                value.set_sensitive(true);
                Ok::<_, io::Error>(value)
            })
            .transpose()?;
        Ok(Self {
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?,
            uri,
            route,
            tls,
            session: None,
            version: None,
            authorization,
        })
    }

    pub fn negotiate(&mut self, version: &'static str) {
        self.version = Some(version);
    }

    pub fn exchange(
        &mut self,
        message: &Value,
        id: Option<u32>,
        deadline: Instant,
        cancellation: Option<&Cancellation>,
    ) -> io::Result<Option<Value>> {
        self.request(Method::POST, serde_json::to_vec(message)?, id, deadline, cancellation)
    }

    pub fn close(&mut self, deadline: Instant) {
        if self.session.is_some() {
            let _ = self.request(Method::DELETE, Vec::new(), None, deadline, None);
            self.session = None;
        }
    }

    fn request(
        &mut self,
        method: Method,
        bytes: Vec<u8>,
        id: Option<u32>,
        deadline: Instant,
        cancellation: Option<&Cancellation>,
    ) -> io::Result<Option<Value>> {
        if bytes.len() > MAX_FRAME {
            return Err(invalid());
        }
        let authority = self.uri.authority().ok_or_else(invalid)?;
        let mut request = Request::builder()
            .method(method.clone())
            .uri(self.uri.path())
            .header(header::HOST, authority.as_str())
            .header(header::CONNECTION, "close")
            .header(header::ACCEPT, "application/json, text/event-stream");
        if method == Method::POST {
            request = request.header(header::CONTENT_TYPE, "application/json");
        }
        if let Some(version) = self.version {
            request = request.header("MCP-Protocol-Version", version);
        }
        if let Some(session) = &self.session {
            request = request.header("Mcp-Session-Id", session);
        }
        if let Some(auth) = &self.authorization {
            request = request.header(header::AUTHORIZATION, auth);
        }
        let request = request
            .body(Full::new(Bytes::from(bytes)))
            .map_err(io::Error::other)?;
        let result = self.runtime.block_on(async {
            let exchange = tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), async {
                let stream = TcpStream::connect(self.route).await?;
                let (mut sender, connection) = if let Some((tls, host)) = &self.tls {
                    connect(tls.connect(host.clone(), stream).await?).await?
                } else {
                    connect(stream).await?
                };
                let connection = AbortOnDrop(connection.abort_handle());
                let answer = async {
                    let mut response = sender
                        .send_request(request)
                        .await
                        .map_err(io::Error::other)?;
                    if method == Method::DELETE
                        && (response.status().is_success()
                            || response.status() == StatusCode::METHOD_NOT_ALLOWED)
                    {
                        return Ok((None, None));
                    }
                    if id.is_none()
                        && matches!(
                            response.status(),
                            StatusCode::OK | StatusCode::ACCEPTED | StatusCode::NO_CONTENT
                        )
                    {
                        return Ok((None, None));
                    }
                    if response.status() != StatusCode::OK {
                        return Err(invalid());
                    }
                    let session = response.headers().get("Mcp-Session-Id").cloned();
                    if session.as_ref().is_some_and(|value| {
                        value.is_empty()
                            || value.len() > 128
                            || !value.as_bytes().iter().all(|b| (0x21..=0x7e).contains(b))
                    }) {
                        return Err(invalid());
                    }
                    let content_type = response
                        .headers()
                        .get(header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.split(';').next())
                        .unwrap_or_default();
                    let sse = match content_type {
                        "application/json" => false,
                        "text/event-stream" => true,
                        _ => return Err(invalid()),
                    };
                    let mut data = Vec::new();
                    let mut total = 0;
                    while let Some(frame) = response.body_mut().frame().await {
                        if let Ok(chunk) = frame.map_err(io::Error::other)?.into_data() {
                            total += chunk.len();
                            if total > MAX_FRAME {
                                return Err(invalid());
                            }
                            data.extend_from_slice(&chunk);
                            if sse && let Some(value) = event_result(&mut data, id)? {
                                self.check_reflection(&value)?;
                                return Ok((Some(value), session));
                            }
                        }
                    }
                    if sse {
                        return Err(invalid());
                    }
                    let value = serde_json::from_slice(&data)?;
                    self.check_reflection(&value)?;
                    Ok((Some(value), session))
                }
                .await;
                drop(connection);
                answer
            });
            let outcome = if let Some(token) = cancellation {
                let mut cancelled = pin!(token.wait());
                let mut exchange = pin!(exchange);
                poll_fn(|cx| {
                    if cancelled.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Ok(Err(io::ErrorKind::Interrupted.into())));
                    }
                    exchange.as_mut().poll(cx)
                })
                .await
            } else {
                exchange.await
            };
            outcome.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
        });
        let (response, session) = result?;
        if id == Some(1) {
            self.session = session;
        }
        Ok(response)
    }
    fn check_reflection(&self, response: &Value) -> io::Result<()> {
        let token = self
            .authorization
            .as_ref()
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "));
        if token.is_some_and(|token| response.to_string().contains(token)) {
            return Err(io::Error::other("Upstream reflected its credential"));
        }
        Ok(())
    }
}

struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn connect(
    stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
) -> io::Result<(
    http1::SendRequest<Full<Bytes>>,
    tokio::task::JoinHandle<Result<(), hyper::Error>>,
)> {
    let (sender, connection) = http1::Builder::new()
        .max_headers(32)
        .max_buf_size(16_384)
        .handshake(TokioIo::new(stream))
        .await
        .map_err(io::Error::other)?;
    Ok((sender, tokio::spawn(connection)))
}

fn read_system_roots() -> io::Result<Vec<u8>> {
    use std::io::Read;
    for path in [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/cert.pem",
    ] {
        if let Ok(file) = std::fs::File::open(path) {
            let mut data = Vec::new();
            file.take(1_048_577).read_to_end(&mut data)?;
            if data.len() <= 1_048_576 {
                return Ok(data);
            }
        }
    }
    Err(io::Error::other("System TLS trust bundle is unavailable"))
}

fn event_result(buffer: &mut Vec<u8>, id: Option<u32>) -> io::Result<Option<Value>> {
    let mut consumed = 0;
    while let Some(end) = buffer[consumed..]
        .windows(2)
        .position(|bytes| bytes == b"\n\n" || bytes == b"\n\r")
    {
        let end = consumed + end;
        let delimiter = if buffer[end + 1] == b'\r' {
            if buffer.get(end + 2) != Some(&b'\n') {
                break;
            }
            3
        } else {
            2
        };
        let event = std::str::from_utf8(&buffer[consumed..end]).map_err(io::Error::other)?;
        let data = event
            .split('\n')
            .map(|line| line.strip_suffix('\r').unwrap_or(line))
            .filter_map(|line| line.strip_prefix("data:"))
            .map(|line| line.strip_prefix(' ').unwrap_or(line))
            .collect::<Vec<_>>()
            .join("\n");
        if !data.is_empty() {
            let message: Value = serde_json::from_str(&data)?;
            if id.is_some_and(|id| message["id"] == id) {
                return Ok(Some(message));
            }
        }
        consumed = end + delimiter;
    }
    buffer.drain(..consumed);
    Ok(None)
}

fn invalid() -> io::Error {
    io::Error::other("Invalid upstream HTTP response")
}

pub(super) fn version(raw: &Value) -> Option<&'static str> {
    [VERSION, "2025-06-18", "2025-03-26"]
        .into_iter()
        .find(|version| raw.as_str() == Some(version))
}
