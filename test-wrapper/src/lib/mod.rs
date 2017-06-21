/// Contains the library which gets injected. Wrapper functions use a custom macro which
/// automatically loads the original function with the right signature. Communicates with the
/// daemon through a Unix socket specified in the environment variable `TEST_WRAPPER_SOCKET`.

#[macro_use]
extern crate lazy_static;

extern crate libc;
extern crate serde;

#[macro_use]
extern crate serde_derive;
extern crate bincode;
extern crate serde_json;

extern crate errno;

extern crate fnv;

extern crate rand;

mod internal_stat;
#[macro_use]
mod shared;
mod overrides;
mod permissions;
pub use permissions::*;
mod files;
pub use files::*;
mod file_descriptors;
pub use file_descriptors::*;
mod creation;
pub use creation::*;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod xattrs;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use xattrs::*;

#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
mod extattrs;
#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
pub use extattrs::*;
