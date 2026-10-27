//! Windows background host.

mod adapters;
mod audit;
mod ble;
mod bind;
mod bridge;
mod config;
mod diagnostics;
mod enroll;
mod irk;
mod notify;
mod pairing;
mod paired;
mod pipe;
mod registry;
mod runtime;
mod stop;
mod session;
mod vault;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name="watchd", version, about="Watch Unlock Windows background host")]
struct Cli { #[command(subcommand)] cmd: Cmd }

#[derive(Subcommand)]
enum Cmd {
    /// Run the background monitor; does not install a login component.
    Run,
    /// Ask the running background monitor in this session to stop; its supervisor exits too.
    Stop,
    /// One JSON request over stdin; never put secrets in command arguments.
    Ui,
    /// Live metadata-only BLE scan for the desktop UI.
    ScanJson { #[arg(long,default_value_t=30)] seconds:u64 },
    /// Advertise a bounded Windows pairing window; requires user confirmation.
    Pair { #[arg(long,default_value_t=120)] seconds:u64 },
    /// Import an explicitly selected CurrentUser-DPAPI identity without displaying it.
    ImportDevice { #[arg(long)] identity_file:std::path::PathBuf, #[arg(long)] name:String },
    /// Elevated, one-time binding of a Windows-paired watch's IRK. Started by the UI only.
    BindPaired { #[arg(long)] address:String, #[arg(long)] name:String,
        /// The non-elevated process that asked; its account must match the elevated one.
        #[arg(long)] launcher_pid:Option<u32> },
    /// Validate and store the current Windows account password interactively.
    Enroll,
    /// Send an explicit notification test. Does not unlock Windows.
    NotifyTest,
}

fn main() {
    let result = match Cli::parse().cmd {
        Cmd::Run => runtime::run(),
        Cmd::Stop => stop::request().map(|_| ()).map_err(anyhow::Error::from),
        Cmd::Ui => bridge::run(),
        Cmd::ScanJson {seconds} => adapters::scan_json(seconds),
        Cmd::Pair {seconds} => pairing::run(seconds),
        Cmd::ImportDevice {identity_file,name} => bridge::import_device(&identity_file,&name),
        // The exit code tells the waiting UI request which step stopped; nothing else is printed.
        Cmd::BindPaired {address,name,launcher_pid} => match bind::run(&address,&name,launcher_pid) {
            Ok(()) => Ok(()),
            Err(failure) => std::process::exit(failure.code()),
        },
        Cmd::Enroll => enroll::enroll(),
        Cmd::NotifyTest => notify::notify_test().map_err(anyhow::Error::from),
    };
    if result.is_err() {
        // Raw Windows/network errors may contain identities or user-supplied URLs.
        eprintln!("Operation failed. Check configuration, permissions and hardware availability.");
        std::process::exit(1);
    }
}
