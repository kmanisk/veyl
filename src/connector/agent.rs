//! Foreground device probe. No background polling, shell, or filesystem authority.
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, StatusCode, client::conn::http1};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use std::{
    io::{self, Read},
    time::Duration,
};

async fn post(port: u16, token: &str, route: &str, value: Value) -> Result<Value, String> {
    let socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|_| "Connector unavailable")?;
    let (mut tx, connection) = http1::handshake(TokioIo::new(socket))
        .await
        .map_err(|_| "Connection failed")?;
    let task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = async {
        let req = Request::post(route)
            .header("host", format!("127.0.0.1:{port}"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(value.to_string())))
            .map_err(|_| "Invalid request")?;
        let res = tx.send_request(req).await.map_err(|_| "Request failed")?;
        if res.status() != StatusCode::OK {
            return Err(format!("Connector rejected request ({})", res.status()));
        }
        let body = Limited::new(res.into_body(), super::MAX)
            .collect()
            .await
            .map_err(|_| "Invalid response body")?;
        serde_json::from_slice(&body.to_bytes()).map_err(|_| "Invalid response JSON".into())
    }
    .await;
    task.abort();
    response
}

pub async fn heartbeat(port: u16) -> Result<(), String> {
    if port == 0 {
        return Err("Explicit nonzero port required".into());
    }
    let mut input = String::new();
    io::stdin()
        .take(67)
        .read_to_string(&mut input)
        .map_err(|_| "Credential input failed")?;
    let token = input.trim_end_matches(['\r', '\n']);
    if !mcp_gateway::core::credential::token_shape(token) {
        return Err("Expected device token on stdin".into());
    }
    tokio::time::timeout(Duration::from_secs(10),async {
        let sequence=post(port,token,"/device/sequence",json!({"api_version":super::API})).await?;
        if sequence["api_version"].as_u64()!=Some(super::API){return Err("Incompatible connector".into());}
        let seq=sequence["last_sequence"].as_u64().and_then(|n|n.checked_add(1)).ok_or("Invalid sequence")?;
        let os=std::env::consts::OS;
        let response=post(port,token,"/device/heartbeat",json!({"api_version":super::API,"sequence":seq,"os":os,"runtime_version":env!("CARGO_PKG_VERSION")})).await?;
        if response["accepted"]!=true||response["api_version"].as_u64()!=Some(super::API){return Err("Invalid acknowledgment".into());}
        println!("{}",json!({"accepted":true,"api_version":super::API,"sequence":seq,"os":os,"runtime_version":env!("CARGO_PKG_VERSION")}));
        Ok(())
    }).await.map_err(|_|"Device request timed out")?
}
