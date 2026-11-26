#![forbid(unsafe_code)]

#[path = "../connector/mod.rs"]
mod connector;

fn main() -> Result<(), String> {
    connector::run()
}
