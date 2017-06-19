use std::env;
use std::ops::Deref;
use std::ffi::OsString;
use std::sync::{RwLock, RwLockReadGuard};
use std::os::raw::*;

use std::os::unix::ffi::OsStrExt;

use serde_json;

use fnv::FnvHashMap;

fn get_true() -> bool {
    true
}

fn get_one() -> u32 {
    1
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Override {
    pub return_value: Option<c_int>,
    pub set_errno: Option<c_int>,
    #[serde(default = "get_true")]
    pub side_effect: bool,
    #[serde(default = "get_one")]
    pub inverse_probability: u32,
}

lazy_static! {
    static ref LAST_OVERRIDE_ENV: RwLock<Option<OsString>> = RwLock::new(None);
    static ref LAST_OVERRIDES: RwLock<FnvHashMap<String, Override>> = RwLock::new(Default::default());
}

pub fn get_overrides() -> RwLockReadGuard<'static, FnvHashMap<String, Override>> {
    let override_env = env::var_os("TEST_WRAPPER_OVERRIDES");
    {
        let last_override_env = LAST_OVERRIDE_ENV.read().unwrap();
        if &override_env == last_override_env.deref() {
            return LAST_OVERRIDES.read().unwrap();
        }
    }
    {
        debug!("New overrides detected: {:?}", override_env);
        let mut last_override_env = LAST_OVERRIDE_ENV.write().unwrap();
        let mut last_overrides = LAST_OVERRIDES.write().unwrap();
        // Keep both write locks alive to avoid a race condition
        if let Some(ref env) = override_env {
            match serde_json::from_slice(env.as_os_str().as_bytes()) {
                Ok(value) => {
                    *last_overrides = value;
                },
                Err(err) => {
                    error!("Failed to deserialize overrides JSON: {:?}", err);
                    last_overrides.clear();
                }
            }
        } else {
            last_overrides.clear();
        }
        *last_override_env = override_env;
    }
    LAST_OVERRIDES.read().unwrap()
}
