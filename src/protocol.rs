//! Minimal legacy MCP 2025-11-25 JSON-RPC dispatch.
//!
//! All file operations are delegated to `file_access`; no transport code or
//! filesystem policy is duplicated in this module.

use serde_json::{Map, Value, json};

use crate::file_access::FileAccess;
use crate::tools::registry::{Tool, read_file};

const MCP_VERSION: &str = "2025-11-25";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Phase {
    New,
    AwaitingInitialized,
    Ready,
}

pub struct Protocol {
    files: FileAccess,
    phase: Phase,
}

impl Protocol {
    pub fn new(files: FileAccess) -> Self {
        Self {
            files,
            phase: Phase::New,
        }
    }

    pub fn parse_error() -> Value {
        error(Value::Null, -32700, "Parse error")
    }

    pub fn oversized_message(limit: usize) -> Value {
        error(
            Value::Null,
            -32600,
            &format!("Message exceeds the {limit}-byte limit"),
        )
    }

    pub fn dispatch(&mut self, message: Value) -> Option<Value> {
        self.dispatch_with_tools(
            message,
            || vec![Tool::ReadFile.schema()],
            |files, name, args| (name == "read_file").then(|| read_file(files, args)),
        )
    }

    pub fn dispatch_with_tools(
        &mut self,
        message: Value,
        list: impl FnOnce() -> Vec<Value>,
        call: impl FnOnce(&FileAccess, &str, Option<&Value>) -> Option<Value>,
    ) -> Option<Value> {
        let Value::Object(mut message) = message else {
            return Some(error(Value::Null, -32600, "Invalid JSON-RPC request"));
        };

        let id = message.remove("id");
        if id
            .as_ref()
            .is_some_and(|id| !(id.is_string() || id.is_i64() || id.is_u64()))
        {
            return Some(error(Value::Null, -32600, "Invalid MCP request id"));
        }

        if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Some(error(
                id.unwrap_or(Value::Null),
                -32600,
                "Invalid JSON-RPC version",
            ));
        }

        let Some(method) = message.get("method").and_then(Value::as_str) else {
            return Some(error(
                id.unwrap_or(Value::Null),
                -32600,
                "JSON-RPC method must be a string",
            ));
        };

        let params = message.get("params");
        let valid_params = params.is_none_or(Value::is_object);
        let Some(id) = id else {
            if method == "notifications/initialized"
                && valid_params
                && self.phase == Phase::AwaitingInitialized
            {
                self.phase = Phase::Ready;
            }
            return None;
        };
        if !valid_params {
            return Some(error(id, -32602, "MCP parameters must be an object"));
        }
        let params = params.and_then(Value::as_object);

        Some(match method {
            "initialize" => self.initialize(id, params),
            "ping" => result(id, json!({})),
            "tools/list" | "tools/call" if self.phase != Phase::Ready => {
                error(id, -32000, "MCP connection has not been initialized")
            }
            "tools/list" => {
                if params
                    .and_then(|p| p.get("cursor"))
                    .is_some_and(|cursor| !cursor.is_string())
                {
                    error(id, -32602, "tools/list cursor must be a string")
                } else {
                    result(id, json!({"tools": list()}))
                }
            }
            "tools/call" => self.call_tool(id, params, call),
            _ => error(id, -32601, "Method not found"),
        })
    }

    fn initialize(&mut self, id: Value, params: Option<&Map<String, Value>>) -> Value {
        if self.phase != Phase::New {
            return error(id, -32600, "MCP initialization has already started");
        }
        let Some(params) = params else {
            return error(id, -32602, "Expected initialize parameters");
        };
        if params
            .get("protocolVersion")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return error(id, -32602, "Expected a nonempty client protocolVersion");
        }
        if !params.get("capabilities").is_some_and(Value::is_object) {
            return error(id, -32602, "Expected client capabilities object");
        }
        let client_info = params.get("clientInfo").and_then(Value::as_object);
        if !client_info.is_some_and(|info| {
            info.get("name").is_some_and(Value::is_string)
                && info.get("version").is_some_and(Value::is_string)
        }) {
            return error(
                id,
                -32602,
                "Expected clientInfo with string name and version",
            );
        }

        self.phase = Phase::AwaitingInitialized;
        // The server offers its sole supported version during negotiation.
        result(
            id,
            json!({
                "protocolVersion": MCP_VERSION,
                "capabilities": { "tools": {} },
                "serverInfo": {
                    "name": "mcp-gateway",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }),
        )
    }

    fn call_tool(
        &self,
        id: Value,
        params: Option<&Map<String, Value>>,
        call: impl FnOnce(&FileAccess, &str, Option<&Value>) -> Option<Value>,
    ) -> Value {
        let Some(params) = params else {
            return error(id, -32602, "Expected tools/call parameters");
        };
        let reply = params
            .get("name")
            .and_then(Value::as_str)
            .and_then(|name| call(&self.files, name, params.get("arguments")));
        match reply {
            Some(body) => result(id, body),
            None => error(id, -32602, "Unknown tool name"),
        }
    }
}

fn result(id: Value, body: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": body })
}

fn error(id: Value, code: i32, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message} })
}

#[cfg(test)]
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
