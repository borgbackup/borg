#![allow(non_snake_case)]

mod stat_base;
pub use self::stat_base::StatBase;

#[cfg(target_os = "linux")]
#[cfg(target_pointer_width = "64")]
mod linux64;
#[cfg(target_os = "linux")]
#[cfg(target_pointer_width = "64")]
pub use self::linux64::*;

#[cfg(target_os = "linux")]
#[cfg(not(target_pointer_width = "64"))]
mod linux32;
#[cfg(target_os = "linux")]
#[cfg(not(target_pointer_width = "64"))]
pub use self::linux32::*;

#[cfg(not(target_os = "linux"))]
mod other;
#[cfg(not(target_os = "linux"))]
pub use self::other::*;
