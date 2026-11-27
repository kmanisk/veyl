//! Dedicated, foreground-owned OAuth ingress. No persistent Serve mutation.
//! Tailscaled removes a Foreground session when its IPN bus connection closes.
use super::{API, SOCKET, entries, local_request, node_allows_funnel, state_object};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, StatusCode, body::Incoming, client::conn::http1, header};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use std::{net::{Ipv4Addr, SocketAddrV4}, path::{Path, PathBuf}, time::Duration};
use tokio::{net::UnixStream, task::JoinHandle};

const WATCH: &str = "/localapi/v0/watch-ipn-bus?mask=18";
const STATUS: &str = "/localapi/v0/status?peers=false";
const TIMEOUT: Duration = Duration::from_secs(4);

pub(crate) struct Plan {
    socket: PathBuf,
    origin: String,
    host: String,
    port: u16,
}

fn hostname(status: &Value) -> Result<String, String> {
    let name = status["Self"]["DNSName"].as_str().unwrap_or_default().trim_end_matches('.');
    if status["BackendState"] != "Running" || !name.ends_with(".ts.net") || name.split('.').count()<4
        || name.len()>253 || name.split('.').any(|label| label.is_empty() || label.len()>63
            || label.starts_with('-') || label.ends_with('-') || !label.bytes().all(|b|b.is_ascii_lowercase()||b.is_ascii_digit()||b==b'-'))
        || !status["CertDomains"].as_array().is_some_and(|v|v.iter().any(|d|d==name))
    {
        return Err("Tailscale must be running with MagicDNS and HTTPS enabled (run 'tailscale up' and enable MagicDNS and HTTPS certificates in Tailscale admin DNS settings)".into());
    }
    Ok(name.to_owned())
}

fn free_port(state: &Value, port: u16) -> Result<(), String> {
    if !state.is_object() {return Err("Invalid Serve state".into());}
    let check=|scope:&Value|->Result<(),String>{
        if !scope.is_object(){return Err("Invalid foreground Serve state".into());}
        let same=|key:&str|key.rsplit_once(':').and_then(|(_,p)|p.parse::<u16>().ok())==Some(port);
        if entries(scope,"TCP")?.any(|(k,_)|k.parse::<u16>()==Ok(port))
            || entries(scope,"Web")?.any(|(k,_)|same(k))
            || entries(scope,"AllowFunnel")?.any(|(k,_)|same(k))
        {return Err(format!("HTTPS port {port} is already occupied"));}
        Ok(())
    };
    check(state)?;
    for (_,foreground) in entries(state,"Foreground")? {check(foreground)?;}
    Ok(())
}

impl Plan {
    pub fn detect(socket:Option<PathBuf>, requested:Option<u16>)->Result<Self,String>{
        if requested.is_some_and(|p|!matches!(p,8443|10000)){
            return Err("Use dedicated Funnel port 8443 or 10000".into());
        }
        let socket=socket.unwrap_or_else(||PathBuf::from(SOCKET));
        if !socket.is_absolute() || !socket.symlink_metadata().is_ok_and(|m|std::os::unix::fs::FileTypeExt::is_socket(&m.file_type())){
            return Err("Tailscaled socket unavailable (start the tailscaled service and confirm /run/tailscale/tailscaled.sock is accessible)".into());
        }
        let rt=tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_|"LocalAPI runtime unavailable")?;
        rt.block_on(async {
            let (status,_)=local_request(&socket,Method::GET,STATUS,None,vec![]).await?;
            let host=hostname(&status)?;
            let (state,_)=local_request(&socket,Method::GET,API,None,vec![]).await?;
            let state=state_object(state)?;
            let port=[8443,10000].into_iter().find(|p|requested.is_none_or(|r|r==*p) && node_allows_funnel(&status,*p) && free_port(&state,*p).is_ok())
                .ok_or("No authorized, unoccupied dedicated Funnel port; existing routes were preserved (ensure your tailnet ACL grants funnel permission and ports 8443 or 10000 are free)")?;
            Ok(Self{socket,origin:format!("https://{host}:{port}"),host,port})
        })
    }
    pub fn origin(&self)->&str {&self.origin}
    fn config(&self, target:SocketAddrV4)->Result<Value,String>{
        if *target.ip()!=Ipv4Addr::LOCALHOST || target.port()==0 {return Err("Expected bound IPv4 loopback MCP listener".into());}
        let authority=format!("{}:{}",self.host,self.port);
        // Tailscale strips non-root mounts; dedicate the entire HTTPS
        // port to the MCP-only listener, which has the exact route allowlist.
        Ok(json!({"TCP":{self.port.to_string():{"HTTPS":true}},
            "Web":{authority.clone():{"Handlers":{"/":{"Proxy":format!("http://{target}")}}}},
            "AllowFunnel":{authority:true}}))
    }
    pub async fn up(&self,target:SocketAddrV4)->Result<Lease,String>{
        let expected=self.config(target)?;
        let (status,_)=local_request(&self.socket,Method::GET,STATUS,None,vec![]).await?;
        if hostname(&status)?!=self.host || !node_allows_funnel(&status,self.port){
            return Err("Tailscale node or Funnel permission changed".into());
        }
        let mut lease=Lease::connect(&self.socket).await?;
        let (state,etag)=local_request(&self.socket,Method::GET,API,None,vec![]).await?;
        let mut next=state_object(state)?;
        free_port(&next,self.port)?;
        if etag.is_empty()||etag=="*" || next["Foreground"].get(&lease.id).is_some(){
            return Err("Conditional Serve version or fresh foreground session unavailable".into());
        }
        next["Foreground"][&lease.id]=expected.clone();
        local_request(&self.socket,Method::POST,API,Some(&etag),serde_json::to_vec(&next).map_err(|_|"Invalid Serve config")?).await?;
        let (mut actual,_)=local_request(&self.socket,Method::GET,API,None,vec![]).await?;
        if actual["Foreground"][&lease.id]!=expected {
            return Err("Foreground route publication could not be verified".into());
        }
        actual["Foreground"].as_object_mut().ok_or("Invalid foreground state")?.remove(&lease.id);
        free_port(&actual,self.port)?;
        lease.expected=Some(expected);
        Ok(lease)
    }
}

struct Driver(JoinHandle<Result<(),hyper::Error>>);
impl Drop for Driver {fn drop(&mut self){self.0.abort();}}

pub(crate) struct Lease {
    socket:PathBuf,
    id:String,
    body:Incoming,
    driver:Driver,
    expected:Option<Value>,
}
impl Lease {
    async fn connect(socket:&Path)->Result<Self,String>{
        tokio::time::timeout(TIMEOUT,async{
            let stream=UnixStream::connect(socket).await.map_err(|_|"Tailscaled unavailable")?;
            let (mut sender,connection)=http1::Builder::new().max_buf_size(32768).handshake(TokioIo::new(stream)).await.map_err(|_|"IPN bus handshake failed")?;
            let driver=Driver(tokio::spawn(connection));
            let request=Request::builder().method(Method::GET).uri(WATCH)
                .header(header::HOST,"local-tailscaled.sock").body(Full::new(Bytes::new())).map_err(|_|"IPN request failed")?;
            let reply=sender.send_request(request).await.map_err(|_|"IPN bus unavailable")?;
            if reply.status()!=StatusCode::OK{return Err("IPN bus denied".into());}
            let mut body=reply.into_body();
            let mut bytes=Vec::new();
            let id=loop {
                let frame=body.frame().await.ok_or("IPN session closed")?.map_err(|_|"IPN session read failed")?;
                let Ok(data)=frame.into_data() else {continue;};
                if bytes.len()+data.len()>131072 {return Err("IPN initial event too large".into());}
                bytes.extend_from_slice(&data);
                let mut values=serde_json::Deserializer::from_slice(&bytes).into_iter::<Value>();
                match values.next(){
                    Some(Ok(value))=>{
                        if value["State"]!=6 {return Err("IPN session is not running".into());}
                        break value["SessionID"].as_str().filter(|s|!s.is_empty()&&s.len()<=128&&s.bytes().all(|b|b.is_ascii_alphanumeric()||matches!(b,b'-'|b'_')))
                            .ok_or("Invalid IPN session ID")?.to_owned();
                    }
                    Some(Err(e)) if e.is_eof()=>{},
                    None=>{},
                    _=>return Err("Invalid IPN session event".into()),
                }
            };
            Ok(Self{socket:socket.to_owned(),id,body,driver,expected:None})
        }).await.map_err(|_|"IPN session timed out")?
    }
    /// Return only when the lease connection is lost. Never parse or log
    /// subsequent notifications (they can contain unrelated host metadata).
    pub async fn ended(&mut self) {
        while let Some(Ok(_))=self.body.frame().await {}
    }
    /// Close the owning session and check only its own foreground key.
    /// Never reset Serve or delete another session.
    pub async fn down(self)->Result<(),String>{
        let Self{socket,id,body,driver,expected}=self;
        drop(body);
        driver.0.abort();
        drop(driver);
        if expected.is_none(){return Ok(());}
        for _ in 0..10 {
            let (state,_)=local_request(&socket,Method::GET,API,None,vec![]).await?;
            let state=state_object(state)?;
            if state["Foreground"].get(&id).is_none(){return Ok(());}
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err("Foreground route removal not verified; inspect tailscale status".into())
    }
}
