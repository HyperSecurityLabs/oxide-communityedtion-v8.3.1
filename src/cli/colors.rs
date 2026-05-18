use colored::Colorize;

// Brand truecolor: HyperSecurityOffensiveLabs orange
const BRAND_R: u8 = 255;
const BRAND_G: u8 = 140;
const BRAND_B: u8 = 0;

pub struct Colors;

impl Colors {
    pub fn warning(text: &str) -> String {
        text.bright_yellow().to_string()
    }

    pub fn ok(text: &str) -> String {
        text.bright_green().to_string()
    }

    pub fn brand(text: &str) -> String {
        text.truecolor(BRAND_R, BRAND_G, BRAND_B).bold().to_string()
    }
}

pub fn print_status(status: &str, message: &str) {
    match status {
        "OK"       => println!("{} {}", "[  OK  ]".bright_green(), message),
        "ERROR"    => println!("{} {}", "[ ERR  ]".bright_red().bold(), message),
        "WARN"     => println!("{} {}", "[ WARN ]".bright_yellow(), message),
        "INFO"     => println!("{} {}", "[ INFO ]".bright_cyan(), message),
        "VULN"     => println!("{} {}", "[ VULN ]".truecolor(255, 0, 60).bold(), message),
        "CRITICAL" => println!("{} {}", "[ CRIT ]".truecolor(255, 0, 60).bold(), message),
        _          => println!("[{:^6}] {}", status, message),
    }
}
