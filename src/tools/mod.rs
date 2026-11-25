//! Tool registration and scoped filesystem mutation.

#[cfg(target_os = "linux")]
pub(crate) mod extensions;
#[cfg(target_os = "linux")]
mod filesystem;
#[cfg(target_os = "linux")]
pub(crate) mod git;
pub(crate) mod mutation;
#[cfg(target_os = "linux")]
mod patch;
pub(crate) mod registry;
#[cfg(target_os = "linux")]
mod write;

#[cfg(target_os = "linux")]
pub(crate) use filesystem::MutationRoot;
