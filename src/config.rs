use regex::Regex;
use serde::{Deserialize};
use config::{Config};
use anyhow::Result;


#[allow(clippy::module_name_repetitions)]
#[derive(Deserialize, Clone, Debug)]
pub struct ProgramConfig {
    pub(crate) listen_interface: String,
    pub(crate) upstream_mac: String,
    pub(crate) send_interfaces: Vec<SendInterface>,
    pub(crate) dhcpv6_process_filter: Vec<String>,
    #[serde(with = "serde_regex")]
    pub(crate) prefixes_regex: Regex
}

#[derive(Deserialize, Clone, Debug)]
pub struct SendInterface {
    pub name: String,
    pub send_delays: Vec<u8>,
    pub prefixes: Vec<Prefix>
}

#[derive(Deserialize, Clone, Debug)]
pub struct Prefix {
    #[serde(with = "serde_regex")]
    pub regex: Regex,
    pub length: u8
}

/// load configuration from environment variables
pub fn load(path: &str) -> Result<ProgramConfig> {
    Ok(Config::builder()
        .add_source(config::File::with_name(path))
        .build()?
        .try_deserialize()?)
}
