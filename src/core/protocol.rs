//! Portable MCP session and JSON-RPC dispatcher. No OS, file or transport authority.
use serde_json::{Map, Value, json};
pub const MCP_VERSION: &str = "2025-11-25";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Phase {
    New,
    AwaitingInitialized,
    Ready,
}

#[derive(Clone)]
pub struct Session {
    phase: Phase,
    server_name: &'static str,
    server_version: &'static str,
}
impl Session {
    pub fn new(server_name: &'static str, server_version: &'static str) -> Self {
        Self {
            phase: Phase::New,
            server_name,
            server_version,
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
    pub fn dispatch(
        &mut self,
        message: Value,
        list: impl FnOnce() -> Vec<Value>,
        call: impl FnOnce(&str, Option<&Value>) -> Option<Value>,
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
                    "name": self.server_name,
                    "version": self.server_version
                }
            }),
        )
    }

    fn call_tool(
        &self,
        id: Value,
        params: Option<&Map<String, Value>>,
        call: impl FnOnce(&str, Option<&Value>) -> Option<Value>,
    ) -> Value {
        let Some(params) = params else {
            return error(id, -32602, "Expected tools/call parameters");
        };
        let reply = params
            .get("name")
            .and_then(Value::as_str)
            .and_then(|name| call(name, params.get("arguments")));
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
    #[test]
    fn common_session_owns_lifecycle_not_tool_authority() {
        let mut session = Session::new("connector", "1");
        let mut calls = 0;
        let request =
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"demo"}});
        let response = session
            .dispatch(
                request.clone(),
                || panic!("unexpected listing"),
                |_, _| {
                    calls += 1;
                    Some(json!({}))
                },
            )
            .unwrap();
        assert_eq!(response["error"]["code"], -32000);
        let init = json!({"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":MCP_VERSION,"capabilities":{},"clientInfo":{"name":"test","version":"1"}}});
        let response = session
            .dispatch(init.clone(), Vec::new, |_, _| None)
            .unwrap();
        assert_eq!(response["result"]["serverInfo"]["name"], "connector");
        assert_eq!(
            session.dispatch(init, Vec::new, |_, _| None).unwrap()["error"]["code"],
            -32600
        );
        assert!(
            session
                .dispatch(
                    json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
                    Vec::new,
                    |_, _| None
                )
                .is_none()
        );
        assert_eq!(
            session
                .dispatch(request.clone(), Vec::new, |_, _| None)
                .unwrap()["error"]["code"],
            -32602
        );
        assert_eq!(
            session
                .dispatch(request, Vec::new, |_, _| {
                    calls += 1;
                    Some(json!({"allowed":true}))
                })
                .unwrap()["result"]["allowed"],
            true
        );
        assert_eq!(calls, 1);
    }
}
