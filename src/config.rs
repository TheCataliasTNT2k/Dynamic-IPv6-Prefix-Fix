use anyhow::Result;
use config::Config;
use regex::Regex;
use serde::Deserialize;

#[allow(clippy::module_name_repetitions)]
#[derive(Deserialize, Clone, Debug)]
pub(crate) struct ProgramConfig {
    pub(crate) listen_interface: String,
    pub(crate) upstream_mac: String,
    pub(crate) send_interfaces: Vec<SendInterface>,
    pub(crate) dhcpv6_process_filter: Vec<String>,
    #[serde(with = "serde_regex")]
    pub(crate) prefixes_regex: Regex,
}

#[derive(Deserialize, Clone, Debug)]
pub(crate) struct SendInterface {
    pub(crate) name: String,
    pub(crate) send_delays: Vec<u8>,
    pub(crate) prefixes: Vec<Prefix>,
}

#[derive(Deserialize, Clone, Debug)]
pub(crate) struct Prefix {
    #[serde(with = "serde_regex")]
    pub(crate) regex: Regex,
    pub(crate) length: u8,
}

/// load configuration from environment variables
pub(crate) fn load(path: &str) -> Result<ProgramConfig> {
    Ok(Config::builder()
        .add_source(config::File::with_name(path))
        .build()?
        .try_deserialize()?)
}
