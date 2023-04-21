#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![warn(clippy::dbg_macro, clippy::use_debug)]
#![warn(
    clippy::expect_used,
    clippy::panic,
    clippy::unimplemented,
    clippy::todo,
    clippy::unreachable
)]
#![warn(
    clippy::shadow_unrelated,
    clippy::str_to_string,
    clippy::wildcard_enum_match_arm
)]

use std::env;
use std::process::exit;

use regex::Regex;
use tracing::{error, info, warn};

use crate::config::{load, ProgramConfig};
use crate::utils::{get_interface_channel, listen_to_ras};

mod config;
mod ras;
mod utils;

fn check_config(config: &mut ProgramConfig) {
    if config.dhcpv6_process_filter.is_empty() {
        error!("We do not have a process filter, exiting!");
        exit(3);
    }
    if !Regex::new(
        "[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]"
    ).unwrap().is_match(&config.upstream_mac) {
        error!("'{}' is not a valid mac address (6 parts, 2 chars each)!", config.upstream_mac);
        exit(3);
    }
    for send_interface in &mut config.send_interfaces {
        if send_interface.prefixes.is_empty() {
            warn!("'{}' does not have any prefixes defined, we will not send anything on this interface!", send_interface.name);
        }
        let count = send_interface.send_delays.len();
        send_interface.send_delays.retain(|delay| delay >= &1u8);
        if send_interface.send_delays.len() < count {
            warn!(
                "Removed {} zeros from send_delays for {} interface",
                count - send_interface.send_delays.len(),
                send_interface.name
            );
        }
        send_interface.send_delays.sort_unstable();
        for prefix in &send_interface.prefixes {
            if prefix.length > 128 {
                error!(
                    "Prefix length with regex {} of interface {} is invalid!",
                    prefix.regex, send_interface.name
                );
                exit(3);
            }
        }
    }
    if config.send_interfaces.is_empty() {
        warn!("No interfaces to send RAs, exiting!");
        exit(5);
    }
}

pub fn main() {
    tracing_subscriber::fmt::init();
    info!("Starting version {}...", env!("CARGO_PKG_VERSION"));
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        error!("No config file set, exiting!");
        exit(1);
    }

    let mut config = match load(&args[1]) {
        Ok(v) => v,
        Err(err) => {
            error!("Could not load config! {err}");
            exit(2);
        }
    };
    check_config(&mut config);
    info!("Using filter '{}'", config.dhcpv6_process_filter.join(", "));
    let Some((_, rx)) = get_interface_channel(&config.listen_interface) else {
        error!("Exiting!");
        exit(4);
    };
    info!("Listening on interface '{}'", config.listen_interface);

    listen_to_ras(rx, &config);
}
