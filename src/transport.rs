//! Newline-delimited JSON-RPC over foreground stdio.

use std::io::{self, BufRead, Read, Write};

use serde_json::Value;

use crate::protocol::Protocol;

const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

pub fn run<I: BufRead, O: Write>(
    mut input: I,
    mut output: O,
    mut protocol: Protocol,
) -> io::Result<()> {
    let mut line = Vec::new();

    loop {
        line.clear();
        // Leave room for a CRLF delimiter beyond the maximum payload size.
        let read = (&mut input)
            .take((MAX_MESSAGE_BYTES + 2) as u64)
            .read_until(b'\n', &mut line)?;
        if read == 0 {
            return Ok(());
        }

        let delimited = line.strip_suffix(b"\n");
        let payload = match delimited {
            Some(payload) => payload.strip_suffix(b"\r").unwrap_or(payload),
            None => &line,
        };
        let reply = if payload.len() > MAX_MESSAGE_BYTES {
            if delimited.is_none() {
                input.skip_until(b'\n')?;
            }
            Some(Protocol::oversized_message(MAX_MESSAGE_BYTES))
        } else {
            match serde_json::from_slice::<Value>(payload) {
                Ok(request) => protocol.dispatch(request),
                Err(_) => Some(Protocol::parse_error()),
            }
        };

        if let Some(reply) = reply {
            match write_reply(&mut output, &reply) {
                Err(error) if error.kind() == io::ErrorKind::BrokenPipe => return Ok(()),
                result => result?,
            }
        }
    }
}

fn write_reply(output: &mut impl Write, reply: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut *output, reply)?;
    output.write_all(b"\n")?;
    output.flush()
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Cursor};

    use serde_json::json;

    use super::*;
    use crate::file_access::FileAccess;

    const PING: &[u8] = br#"{"jsonrpc":"2.0","method":"ping","id":1}"#;

    fn protocol() -> Protocol {
        Protocol::new(FileAccess::new(&std::env::temp_dir()).unwrap())
    }

    fn replies(input: impl BufRead) -> Vec<Value> {
        let mut output = Vec::new();
        run(input, &mut output, protocol()).unwrap();
        output
            .lines()
            .map(|line| serde_json::from_str(&line.unwrap()).unwrap())
            .collect()
    }

    #[test]
    fn accepts_maximum_payload_with_lf_or_crlf() {
        for delimiter in [b"\n".as_slice(), b"\r\n"] {
            let mut input = PING.to_vec();
            input.resize(MAX_MESSAGE_BYTES, b' ');
            input.extend_from_slice(delimiter);
            assert_eq!(
                replies(Cursor::new(input)),
                [json!({"jsonrpc":"2.0","id":1,"result":{}})]
            );
        }
    }

    #[test]
    fn rejects_oversized_lines_and_resumes_at_the_next_frame() {
        for (extra, delimiter) in [
            (1, b"\n".as_slice()),
            (1, b"\r\n"),
            (2 * MAX_MESSAGE_BYTES, b"\n"),
        ] {
            let input = io::repeat(b' ')
                .take((MAX_MESSAGE_BYTES + extra) as u64)
                .chain(delimiter)
                .chain(PING)
                .chain(b"\n".as_slice());
            let output = replies(BufReader::with_capacity(4096, input));
            assert_eq!(output.len(), 2);
            assert_eq!(output[0]["error"]["code"], -32600);
            assert!(output[0]["id"].is_null());
            assert_eq!(output[1]["id"], 1);
            assert_eq!(output[1]["result"], json!({}));
        }
    }

    #[test]
    fn oversized_final_line_produces_one_error_and_exits_at_eof() {
        let input = io::repeat(b'x').take((MAX_MESSAGE_BYTES + 1) as u64);
        let output = replies(BufReader::new(input));
        assert_eq!(output.len(), 1);
        assert_eq!(output[0]["error"]["code"], -32600);
    }

    #[test]
    fn malformed_json_and_invalid_utf8_do_not_interrupt_framing() {
        let mut input = b"{bad json}\n{\"method\":\"\xff\"}\n".to_vec();
        input.extend_from_slice(PING);
        let output = replies(Cursor::new(input));
        assert_eq!(output.len(), 3);
        for error in &output[..2] {
            assert_eq!(error["error"]["code"], -32700);
            assert!(error["id"].is_null());
        }
        assert_eq!(output[2]["result"], json!({}));
    }

    #[test]
    fn empty_input_produces_no_output() {
        assert!(replies(Cursor::new(b"")).is_empty());
    }

    struct FailingOutput {
        on_flush: bool,
        kind: io::ErrorKind,
    }

    impl Write for FailingOutput {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.on_flush {
                Ok(bytes.len())
            } else {
                Err(self.kind.into())
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(self.kind.into())
        }
    }

    #[test]
    fn broken_pipe_is_clean_on_write_or_flush() {
        for on_flush in [false, true] {
            let output = FailingOutput {
                on_flush,
                kind: io::ErrorKind::BrokenPipe,
            };
            assert!(run(Cursor::new(PING), output, protocol()).is_ok());
        }
    }

    #[test]
    fn other_output_errors_propagate() {
        let output = FailingOutput {
            on_flush: false,
            kind: io::ErrorKind::PermissionDenied,
        };
        let error = run(Cursor::new(PING), output, protocol()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }
}
