//! Shared, OS-independent gateway primitives. Platform storage, authorization
//! state, process isolation, and transport remain outside this module.
pub mod credential;

pub mod protocol;

pub mod capability;
pub mod lifecycle;
pub mod oauth;
pub mod session;
pub mod timeshift;
pub mod tools;
pub mod workspace;
