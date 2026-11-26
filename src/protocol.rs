//! Minimal legacy MCP 2025-11-25 JSON-RPC dispatch.
//!
//! All file operations are delegated to `file_access`; no transport code or
//! filesystem policy is duplicated in this module.

#[cfg(any(all(test, target_os = "linux"), target_os = "android"))]
use serde_json::json;
use serde_json::{Map, Value};

#[cfg(target_os = "linux")]
use crate::{file_access::FileAccess, tools::registry::read_file};
use mcp_gateway::core::{tools::tool_text,workspace::WorkspaceTool};
#[cfg(target_os = "linux")]
use mcp_gateway::core::tools::Tool;

#[cfg(all(test, target_os = "linux"))]
use mcp_gateway::core::protocol::MCP_VERSION;
use mcp_gateway::core::protocol::Session;

#[derive(Clone)]
pub struct Protocol {
    #[cfg(target_os = "linux")]
    files: Option<FileAccess>,
    session: Session,
    probe: bool,
    #[cfg(target_os = "android")]
    workspace: Option<mcp_gateway::platform::private_workspace::PrivateWorkspace>,
}

impl Protocol {
    #[cfg(target_os = "linux")]
    pub fn new(files: FileAccess) -> Self {
        Self {
            files: Some(files),
            session: Session::new("mcp-gateway", env!("CARGO_PKG_VERSION")),
            probe: false,
            #[cfg(target_os = "android")]
            workspace: None,
        }
    }

    pub fn platform_probe(root: Option<&std::path::Path>) -> Result<Self, &'static str> {
        #[cfg(target_os = "android")]
        let workspace = root
            .map(mcp_gateway::platform::private_workspace::PrivateWorkspace::termux)
            .transpose()?;
        #[cfg(not(target_os = "android"))]
        if root.is_some() {
            return Err("platform probe has no filesystem adapter on this target");
        }
        Ok(Self {
            #[cfg(target_os = "linux")]
            files: None,
            session: Session::new("mcp-gateway", env!("CARGO_PKG_VERSION")),
            probe: true,
            #[cfg(target_os = "android")]
            workspace,
        })
    }

    pub fn parse_error() -> Value {
        Session::parse_error()
    }
    pub fn oversized_message(limit: usize) -> Value {
        Session::oversized_message(limit)
    }

    pub fn dispatch(&mut self, message: Value) -> Option<Value> {
        if self.probe {
            #[cfg(target_os = "android")]
            let workspace = self.workspace.clone();
            #[cfg(target_os = "android")]
            let available = if workspace.is_some() { WorkspaceTool::READ_ONLY.as_slice() } else { &[WorkspaceTool::PlatformInfo] };
            #[cfg(not(target_os = "android"))]
            let available = &[WorkspaceTool::PlatformInfo];
            // Windows/bootstrap mode deliberately has no filesystem or execution tools.
            return self.session.dispatch(
                message,
                || available.iter().map(|t|t.schema()).collect(),
                |name, args| {
                    let tool=WorkspaceTool::parse(name)?;
                    if !available.contains(&tool){return None;}
                    if tool==WorkspaceTool::PlatformInfo {
                        let valid = args.is_none_or(|v| v.as_object().is_some_and(Map::is_empty));
                        return Some(if valid {
                            let mut report = mcp_gateway::platform::report();
                            #[cfg(target_os = "android")]
                            if workspace.is_some() {
                                report["probe"]["tools"] = json!([
                                    "platform_info",
                                    "read_file",
                                    "list_directory",
                                    "file_info"
                                ]);
                            }
                            #[cfg(not(target_os = "android"))]
                            let _ = &mut report;
                            tool_text(false, &report.to_string())
                        } else {
                            tool_text(
                                true,
                                "Unexpected platform_info arguments",
                            )
                        });
                    }
                    #[cfg(target_os = "android")]
                    if let Some(workspace)=workspace.as_ref() {
                        return Some(match tool.path(args).and_then(|p|match tool {
                            WorkspaceTool::ReadFile=>workspace.read(p),
                            WorkspaceTool::FileInfo=>workspace.info(p).map(|v|v.to_string()),
                            WorkspaceTool::ListDirectory=>workspace.list(p).map(|v|v.to_string()),
                            _=>Err("Unsupported operation"),
                        }) {
                            Ok(value)=>tool_text(false,&value),
                            Err(err)=>tool_text(true,err),
                        });
                    }
                    None
                },
            );
        }
        #[cfg(target_os = "linux")]
        return self.dispatch_with_tools(
            message,
            || vec![Tool::ReadFile.schema()],
            |files, name, args| {
                (name == "read_file").then(|| read_file(files.expect("legacy file scope"), args))
            },
        );
        #[cfg(not(target_os = "linux"))]
        unreachable!("non-Linux protocol only supports probe");
    }

    #[cfg(target_os = "linux")]
    pub fn dispatch_with_tools(
        &mut self,
        message: Value,
        list: impl FnOnce() -> Vec<Value>,
        call: impl FnOnce(Option<&FileAccess>, &str, Option<&Value>) -> Option<Value>,
    ) -> Option<Value> {
        let files = self.files.as_ref();
        self.session
            .dispatch(message, list, |name, args| call(files, name, args))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn protocol() -> Protocol {
        Protocol::new(FileAccess::new(&std::env::temp_dir()).unwrap())
    }

    fn initialize_params(version: &str) -> Value {
        json!({
            "protocolVersion": version,
            "clientInfo": {"name": "unit-test", "version": "1"},
            "capabilities": {}
        })
    }

    fn initialized() -> Value {
        json!({"jsonrpc":"2.0","method":"notifications/initialized"})
    }

    fn send(protocol: &mut Protocol, id: u64, method: &str, params: Option<Value>) -> Value {
        let mut request = json!({"jsonrpc":"2.0","id":id,"method":method});
        if let Some(params) = params {
            request["params"] = params;
        }
        protocol.dispatch(request).unwrap()
    }

    fn assert_error(reply: Value, id: Value, code: i32) {
        assert_eq!(reply["jsonrpc"], "2.0");
        assert_eq!(reply["id"], id);
        assert_eq!(reply["error"]["code"], code);
    }

    #[test]
    fn malformed_requests_and_invalid_ids_are_rejected() {
        let mut protocol = protocol();
        for message in [json!(true), json!([]), json!({"jsonrpc":"2.0"})] {
            assert_error(protocol.dispatch(message).unwrap(), Value::Null, -32600);
        }
        for message in [
            json!({"jsonrpc":"1.0","id":1,"method":"ping"}),
            json!({"jsonrpc":"2.0","id":1,"method":42}),
        ] {
            assert_error(protocol.dispatch(message).unwrap(), json!(1), -32600);
        }
        for id in [Value::Null, json!(true), json!({}), json!([]), json!(0.5)] {
            let reply = protocol.dispatch(json!({"jsonrpc":"2.0","id":id,"method":"ping"}));
            assert_error(reply.unwrap(), Value::Null, -32600);
        }
    }

    #[test]
    fn ping_echoes_supported_ids_before_initialization() {
        let mut protocol = protocol();
        for id in [json!("client-1"), json!(-9), json!(u64::MAX)] {
            let reply = protocol
                .dispatch(json!({"jsonrpc":"2.0","id":id,"method":"ping"}))
                .unwrap();
            assert_eq!(reply, json!({"jsonrpc":"2.0","id":id,"result":{}}));
        }
    }

    #[test]
    fn initialization_requires_valid_arguments_and_initialized_notification() {
        let mut protocol = protocol();
        assert!(protocol.dispatch(initialized()).is_none());
        assert!(
            protocol
                .dispatch(json!({
                    "jsonrpc":"2.0","method":"initialize","params":initialize_params(MCP_VERSION)
                }))
                .is_none()
        );
        assert_error(send(&mut protocol, 1, "tools/list", None), json!(1), -32000);

        for (id, field, invalid) in [
            (2, "protocolVersion", json!("")),
            (3, "capabilities", json!([])),
            (4, "clientInfo", json!({"name":"test"})),
        ] {
            let mut params = initialize_params(MCP_VERSION);
            params[field] = invalid;
            assert_error(
                send(&mut protocol, id, "initialize", Some(params)),
                json!(id),
                -32602,
            );
        }

        let params = initialize_params("2025-03-26");
        let reply = send(&mut protocol, 5, "initialize", Some(params.clone()));
        assert_eq!(reply["result"]["protocolVersion"], MCP_VERSION);
        assert_eq!(reply["result"]["capabilities"], json!({"tools":{}}));
        assert_error(
            send(&mut protocol, 6, "initialize", Some(params.clone())),
            json!(6),
            -32600,
        );
        assert_error(
            send(&mut protocol, 7, "notifications/initialized", None),
            json!(7),
            -32601,
        );

        let mut invalid = initialized();
        invalid["params"] = json!([]);
        assert!(protocol.dispatch(invalid).is_none());
        assert_error(send(&mut protocol, 8, "tools/list", None), json!(8), -32000);

        assert!(protocol.dispatch(initialized()).is_none());
        assert!(protocol.dispatch(initialized()).is_none());
        assert_eq!(
            send(&mut protocol, 9, "tools/list", None)["result"]["tools"][0]["name"],
            "read_file"
        );
        assert_error(
            send(&mut protocol, 10, "initialize", Some(params)),
            json!(10),
            -32600,
        );
    }

    #[test]
    fn unknown_requests_get_method_not_found_and_notifications_are_silent() {
        let mut protocol = protocol();
        assert_error(send(&mut protocol, 1, "unknown", None), json!(1), -32601);
        assert!(
            protocol
                .dispatch(json!({"jsonrpc":"2.0","method":"unknown"}))
                .is_none()
        );
        send(
            &mut protocol,
            2,
            "initialize",
            Some(initialize_params(MCP_VERSION)),
        );
        assert!(protocol.dispatch(initialized()).is_none());
        assert_error(send(&mut protocol, 3, "unknown", None), json!(3), -32601);
    }

    #[test]
    fn invalid_rpc_params_and_invalid_tool_arguments_have_distinct_errors() {
        let mut protocol = protocol();
        for (id, params) in [(1, Value::Null), (2, json!([1])), (3, json!("scalar"))] {
            assert_error(
                send(&mut protocol, id, "ping", Some(params)),
                json!(id),
                -32602,
            );
        }
        send(
            &mut protocol,
            4,
            "initialize",
            Some(initialize_params(MCP_VERSION)),
        );
        assert!(protocol.dispatch(initialized()).is_none());
        assert_error(
            send(&mut protocol, 5, "tools/list", Some(json!({"cursor":10}))),
            json!(5),
            -32602,
        );
        assert_error(
            send(
                &mut protocol,
                6,
                "tools/call",
                Some(json!({"name":"unknown"})),
            ),
            json!(6),
            -32602,
        );
        for (id, arguments) in [
            (7, json!([])),
            (8, json!({"path":null})),
            (9, json!({"path":"x","extra":true})),
        ] {
            let params = json!({"name":"read_file","arguments":arguments});
            let reply = send(&mut protocol, id, "tools/call", Some(params));
            assert_eq!(reply["id"], id);
            assert_eq!(reply["result"]["isError"], true);
            assert_eq!(reply["result"]["content"][0]["type"], "text");
        }
    }
}
