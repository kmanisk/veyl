//! Local OAuth operator through the existing one-use dashboard pairing and
//! paired-session CSRF API. No long-lived operator token in argv or output.
mod onboarding;
pub(crate) mod managed;
pub(crate) use managed::run as managed_login;
use crate::http::{dashboard::issue_pairing, operator::{PolicyFile,verify_approvals}};
use bytes::Bytes;
use http_body_util::{BodyExt,Full,Limited};
use hyper::{Request,StatusCode,client::conn::http1,header};
use hyper_util::rt::TokioIo;
use mcp_gateway::http_common::oauth_http::consent_input;
use serde_json::{Value,json};
use std::{ffi::OsString,io::{self,Read},net::{Ipv4Addr,SocketAddrV4},path::Path,time::Duration};
use tokio::net::TcpStream;

const HELP: &str = "Usage: veyl oauth list|inspect|approve|deny|revoke|mode --listen 127.0.0.1:PORT --config ABSOLUTE_POLICY\nLocal preview only. Non-list operations read a JSON object from stdin (max 8192 bytes).\ninspect: request[, mode]; approve/deny: request, client_id, redirect_uri, resource, local_client, confirm:true[, mode]; revoke: client_id, confirm:true; mode: client_id, mode, confirm:true.\nInspect first, review the exact binding, then explicitly confirm. Uses one-use local dashboard pairing.";

struct Session {
    cookie: String,
    csrf: String,
}

async fn request(addr: SocketAddrV4, endpoint: &str, payload: Value, session: Option<&Session>) -> Result<(Value,Option<String>),String> {
    tokio::time::timeout(Duration::from_secs(8),async {
        let mut req=Request::builder().method("POST").uri(format!("/dashboard/api/{endpoint}"))
            .header(header::HOST,addr.to_string())
            .header(header::ORIGIN,format!("http://{addr}"))
            .header(header::CONTENT_TYPE,"application/json")
            .header(header::CONNECTION,"close");
        if let Some(session)=session {
            req=req.header(header::COOKIE,&session.cookie).header("X-CSRF-Token",&session.csrf);
        }
        let req=req.body(Full::new(Bytes::from(payload.to_string()))).map_err(|_|"Invalid request")?;
        let stream=TcpStream::connect(addr).await.map_err(|_|"Cannot reach local dashboard")?;
        let (mut sender,conn)=http1::Builder::new().max_buf_size(32768)
            .handshake(TokioIo::new(stream)).await.map_err(|_|"Local HTTP handshake failed")?;
        let task=tokio::spawn(conn);
        let result=async {
            let response=sender.send_request(req).await.map_err(|_|"Dashboard request failed")?;
            if response.status()!=StatusCode::OK {
                return Err(format!("Dashboard returned {}",response.status()));
            }
            let cookie=response.headers().get(header::SET_COOKIE).and_then(|v|v.to_str().ok())
                .and_then(|v|v.split(';').next()).and_then(|v|v.strip_prefix("mcp_dash_session="))
                .filter(|v|v.len()==48 && v.bytes().all(|b|b.is_ascii_hexdigit()))
                .map(|v|format!("mcp_dash_session={v}"));
            let bytes=Limited::new(response.into_body(),2*1024*1024).collect().await.map_err(|_|"Invalid dashboard response")?.to_bytes();
            let value=serde_json::from_slice(&bytes).map_err(|_|"Invalid dashboard JSON")?;
            Ok((value,cookie))
        }.await;
        task.abort();
        result
    }).await.map_err(|_|"Dashboard request timed out; inspect state before retrying".to_owned())?
}

pub(crate) fn run(args: &[OsString]) -> Result<(),String> {
    if args==["--help"] {println!("{HELP}\n\n{}\nWorkspace editing and job approval require scope_fingerprint from inspect.",onboarding::HELP);return Ok(());}
    let action=args.first().and_then(|v|v.to_str()).ok_or(HELP)?;
    if matches!(action,"setup"|"run") {return onboarding::run(args);}
    if !matches!(action,"list"|"inspect"|"approve"|"deny"|"revoke"|"mode") || rustix::process::geteuid().is_root() {
        return Err(HELP.into());
    }
    let mut options=args[1..].iter();
    let mut addr=None;
    let mut config=None;
    while let Some(key)=options.next() {
        match key.to_str() {
            Some("--listen") if addr.is_none()=> {
                addr=Some(options.next().and_then(|v|v.to_str()).and_then(|v|v.parse::<SocketAddrV4>().ok()).ok_or(HELP)?);
            }
            Some("--config") if config.is_none()=>config=Some(Path::new(options.next().ok_or(HELP)?)),
            _=>return Err(HELP.into()),
        }
    }
    let addr=addr.filter(|v|*v.ip()==Ipv4Addr::LOCALHOST && v.port()!=0).ok_or(HELP)?;
    let config=config.filter(|p|p.is_absolute()).ok_or(HELP)?;
    let mut bytes=Vec::new();
    if action=="list" {bytes.extend_from_slice(b"{}");}
    else {
        io::stdin().take(8193).read_to_end(&mut bytes).map_err(|_|"Cannot read OAuth request JSON")?;
    }
    let payload=consent_input(action,&bytes).map_err(|_|"Invalid OAuth request JSON")?;
    // Require explicit preview policy, never silently fall back to the
    // installed service. The caller supplies the actual ephemeral port.
    let token={
        let policy=PolicyFile::lock(config,true)?;
        let settings=policy.snapshot()?;
        verify_approvals(&settings)?;
        if settings.tailnet.is_some() || settings.admin_listen.is_none_or(|v|v.port()!=0) {
            return Err("OAuth CLI requires an isolated preview policy".into());
        }
        issue_pairing(&policy)?
    };
    let rt=tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_|"Cannot start local CLI runtime")?;
    let (value,cookie)=rt.block_on(request(addr,"pair",json!({"pairing_token":token}),None))?;
    let session=Session {
        cookie:cookie.ok_or("Missing paired session")?,
        csrf:value["csrf"].as_str().filter(|v|v.len()==48 && v.bytes().all(|b|b.is_ascii_hexdigit())).ok_or("Invalid session proof")?.to_owned(),
    };
    let result=rt.block_on(request(addr,"oauth",payload,Some(&session)));
    let logout=rt.block_on(request(addr,"logout",json!({}),Some(&session)));
    let (response,_)=result?;
    println!("{}",serde_json::to_string_pretty(&response).map_err(|_|"Invalid response")?);
    if logout.is_err() {
        return Err("OAuth operation succeeded, but dashboard logout failed; do not repeat the operation".into());
    }
    Ok(())
}
