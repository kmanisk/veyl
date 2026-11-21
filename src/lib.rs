#![forbid(unsafe_code)]

// Reusable service-policy primitives. The Milestone 1 stdio binary remains
// unchanged: no authentication, privileged execution or service is activated.
pub mod security;
