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

extern crate errno;

extern crate twox_hash;

mod internal_stat;
#[macro_use]
mod shared;
mod xattrs;
pub use xattrs::*;
mod permissions;
pub use permissions::*;
mod files;
pub use files::*;
