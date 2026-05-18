pub mod advanced;
pub mod ai;
pub mod cli;
pub mod core;
pub mod db;
pub mod detection;
pub mod http;
pub mod insta;
pub mod payload;
pub mod session_hijack;
pub mod report;
pub mod scanner;
pub mod utils;


pub use cli::args::CliArgs;
pub use core::engine::ScanEngine;
pub use detection::analyzer::{Analyzer, Finding, Severity};
pub use http::client::HttpClient;
pub use payload::generator::PayloadGenerator;
pub use report::generator::ReportGenerator;

pub const VERSION: &str = "8.3.1";
pub const NAME: &str = "OXIDE Community Edition";
pub const DESCRIPTION: &str = "Open eXtensible Intelligence & Detection Engine — Community Edition";
