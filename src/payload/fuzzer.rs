
use crate::payload::xss::XssPayloads;
use crate::payload::sql_injection::SqlInjection;
use crate::payload::lfi::Lfi;
use crate::payload::command_injection::CommandInjection;


pub struct Fuzzer;

impl Fuzzer {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_sql_payloads(&self) -> Vec<String> {
        let mut payloads = SqlInjection::get_error_payloads();
        payloads.extend(SqlInjection::get_waf_bypass_payloads());
        payloads.extend(SqlInjection::get_time_payloads());
        payloads.extend(SqlInjection::get_union_payloads());
        payloads.extend(SqlInjection::get_boolean_payloads().iter().map(|(t, _)| t.clone()));
        payloads.extend(SqlInjection::get_stacked_payloads());
        payloads
    }

    pub fn generate_destructive_sql_payloads(&self) -> Vec<String> {
        SqlInjection::get_destructive_payloads()
    }

    pub fn generate_nosql_payloads(&self) -> Vec<String> {
        SqlInjection::get_nosql_payloads()
    }

    pub fn generate_xss_payloads(&self) -> Vec<String> {
        let mut payloads = XssPayloads::get_basic_payloads();
        payloads.extend(XssPayloads::get_event_handlers());
        payloads.extend(XssPayloads::get_waf_bypass_payloads());
        payloads.extend(XssPayloads::get_encoded_payloads());
        payloads
    }

    pub fn generate_ssti_payloads(&self) -> Vec<String> {
        XssPayloads::get_ssti_payloads()
    }

    pub fn generate_lfi_payloads(&self) -> Vec<String> {
        Lfi::get_payloads()
    }

    pub fn generate_cmd_injection_payloads(&self, listener_ip: &str, listener_port: u16) -> Vec<String> {
        let mut payloads = CommandInjection::get_basic_payloads();
        payloads.extend(CommandInjection::get_oob_payloads("collab.oxide.local"));
        payloads.extend(CommandInjection::get_time_based_payloads());
        payloads.extend(CommandInjection::get_reverse_shell_payloads(listener_ip, listener_port));
        payloads.extend(CommandInjection::get_windows_payloads());
        payloads
    }

}
