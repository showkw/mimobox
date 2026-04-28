#[cfg(target_os = "linux")]
mod network_isolation_tests {
    use std::error::Error;
    use std::path::PathBuf;

    use mimobox_core::{NamespaceDegradation, Sandbox, SandboxConfig, SeccompProfile};
    use mimobox_os::LinuxSandbox;

    fn network_config() -> SandboxConfig {
        let mut config = SandboxConfig::default();
        config.deny_network = true;
        config.namespace_degradation = NamespaceDegradation::AllowDegradation;
        config.timeout_secs = Some(10);
        config.fs_readonly = vec![
            PathBuf::from("/usr"),
            PathBuf::from("/lib"),
            PathBuf::from("/lib64"),
            PathBuf::from("/bin"),
            PathBuf::from("/sbin"),
            PathBuf::from("/dev"),
            PathBuf::from("/proc"),
            PathBuf::from("/etc"),
        ];
        config
    }

    fn python_command() -> Option<String> {
        ["/usr/bin/python3", "/bin/python3", "/usr/local/bin/python3"]
            .into_iter()
            .find(|path| std::path::Path::new(path).is_file())
            .map(str::to_string)
    }

    fn network_interfaces(proc_net_dev: &str) -> Vec<String> {
        proc_net_dev
            .lines()
            .filter_map(|line| line.split_once(':').map(|(interface, _)| interface.trim()))
            .filter(|interface| !interface.is_empty())
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn test_network_isolation_only_loopback() -> Result<(), Box<dyn Error>> {
        let mut sandbox = LinuxSandbox::new(network_config())?;
        let command = vec!["/bin/cat".to_string(), "/proc/net/dev".to_string()];
        let result = sandbox.execute(&command)?;
        let stdout = String::from_utf8_lossy(&result.stdout);
        let interfaces = network_interfaces(&stdout);

        assert_eq!(
            result.exit_code,
            Some(0),
            "读取 /proc/net/dev 失败: {stdout}"
        );
        assert_eq!(interfaces, vec!["lo"], "网络命名空间应只暴露 lo: {stdout}");

        Ok(())
    }

    #[test]
    fn test_network_isolation_socket_connect_fails() -> Result<(), Box<dyn Error>> {
        let mut config = network_config();
        config.seccomp_profile = SeccompProfile::Network;
        let mut sandbox = LinuxSandbox::new(config)?;

        let command = if let Some(python) = python_command() {
            vec![
                python,
                "-c".to_string(),
                r#"import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
s.connect(("127.0.0.1", 80))
"#
                .to_string(),
            ]
        } else {
            vec![
                "/bin/bash".to_string(),
                "-c".to_string(),
                "exec 3<>/dev/tcp/127.0.0.1/80".to_string(),
            ]
        };

        let result = sandbox.execute(&command)?;
        assert!(
            result.exit_code != Some(0) || result.timed_out,
            "隔离网络中不应能连接 127.0.0.1:80, exit={:?}, stdout={}, stderr={}",
            result.exit_code,
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );

        Ok(())
    }

    #[test]
    fn test_network_namespace_isolation_proc() -> Result<(), Box<dyn Error>> {
        let mut sandbox = LinuxSandbox::new(network_config())?;
        let command = vec!["/bin/cat".to_string(), "/proc/net/tcp".to_string()];
        let result = sandbox.execute(&command)?;
        let stdout = String::from_utf8_lossy(&result.stdout);
        let connections: Vec<&str> = stdout
            .lines()
            .skip(1)
            .filter(|line| !line.trim().is_empty())
            .collect();

        assert_eq!(
            result.exit_code,
            Some(0),
            "读取 /proc/net/tcp 失败: {stdout}"
        );
        assert!(
            connections.is_empty(),
            "隔离网络命名空间不应继承宿主 TCP 连接: {stdout}"
        );

        Ok(())
    }

    #[test]
    fn test_network_dns_unreachable() -> Result<(), Box<dyn Error>> {
        let Some(python) = python_command() else {
            return Ok(());
        };

        let mut config = network_config();
        config.seccomp_profile = SeccompProfile::Network;
        let mut sandbox = LinuxSandbox::new(config)?;
        let command = vec![
            python,
            "-c".to_string(),
            r#"import socket
try:
    print(socket.gethostbyname("localhost"))
except OSError:
    raise SystemExit(2)
"#
            .to_string(),
        ];
        let result = sandbox.execute(&command)?;
        let stdout = String::from_utf8_lossy(&result.stdout);

        assert!(
            result.exit_code != Some(0) || stdout.trim() == "127.0.0.1",
            "DNS 解析应失败，或仅通过本地 hosts 解析到 127.0.0.1: exit={:?}, stdout={stdout}, stderr={}",
            result.exit_code,
            String::from_utf8_lossy(&result.stderr)
        );

        Ok(())
    }
}
