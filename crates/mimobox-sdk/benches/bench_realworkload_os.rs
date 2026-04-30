#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
mod realworkload_os {
    use std::collections::HashMap;
    use std::hint::black_box;
    use std::time::{Duration, Instant};

    use mimobox_sdk::{Config, ExecuteResult, IsolationLevel, Sandbox};

    const STANDARD_ITERATIONS: usize = 100;
    const STORM_ITERATIONS: usize = 200;
    const LIST_SANDBOX_COUNT: usize = 100;
    const READY_TIMEOUT: Duration = Duration::from_secs(30);

    fn must<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(err) => panic!("{context}: {err}"),
        }
    }

    fn os_config() -> Config {
        must(
            Config::builder()
                .isolation(IsolationLevel::Os)
                .timeout(Duration::from_secs(30))
                .memory_limit_mb(256)
                .build(),
            "failed to build OS benchmark config",
        )
    }

    fn os_shell_config() -> Config {
        // shell、管道和后台进程负载需要允许子进程创建。
        must(
            Config::builder()
                .isolation(IsolationLevel::Os)
                .timeout(Duration::from_secs(30))
                .memory_limit_mb(256)
                .allow_fork(true)
                .build(),
            "failed to build OS shell benchmark config",
        )
    }

    fn os_config_with_env(env_count: usize) -> Config {
        must(
            Config::builder()
                .isolation(IsolationLevel::Os)
                .timeout(Duration::from_secs(30))
                .memory_limit_mb(256)
                .env_vars(make_env_vars(env_count))
                .build(),
            "failed to build OS env benchmark config",
        )
    }

    fn make_env_vars(env_count: usize) -> HashMap<String, String> {
        let mut vars = HashMap::with_capacity(env_count);
        for index in 0..env_count {
            vars.insert(
                format!("MIMOBOX_BENCH_VAR_{index:03}"),
                format!("bench-value-{index:03}"),
            );
        }
        vars
    }

    pub fn percentile(samples: &mut [f64], p: f64) -> f64 {
        if samples.is_empty() {
            return 0.0;
        }

        samples.sort_by(f64::total_cmp);
        let last_index = samples.len().saturating_sub(1);
        let rank = ((last_index as f64) * p.clamp(0.0, 1.0)).ceil() as usize;
        samples[rank.min(last_index)]
    }

    pub fn print_stats(label: &str, samples: &mut [Duration]) {
        if samples.is_empty() {
            println!(
                "[realworkload_os][{label}] Samples=0 Min=0.000000ms P50=0.000000ms P95=0.000000ms P99=0.000000ms Max=0.000000ms Avg=0.000000ms"
            );
            return;
        }

        let mut millis = samples
            .iter()
            .map(|sample| sample.as_secs_f64() * 1_000.0)
            .collect::<Vec<_>>();
        let avg = millis.iter().sum::<f64>() / millis.len() as f64;
        let p50 = percentile(&mut millis, 0.50);
        let p95 = percentile(&mut millis, 0.95);
        let p99 = percentile(&mut millis, 0.99);
        let min = match millis.first() {
            Some(value) => *value,
            None => 0.0,
        };
        let max = match millis.last() {
            Some(value) => *value,
            None => 0.0,
        };

        println!(
            "[realworkload_os][{label}] Samples={} Min={min:.6}ms P50={p50:.6}ms P95={p95:.6}ms P99={p99:.6}ms Max={max:.6}ms Avg={avg:.6}ms",
            samples.len()
        );
    }

    fn run_duration_samples<F>(label: &str, iterations: usize, mut sample: F)
    where
        F: FnMut() -> Duration,
    {
        let mut samples = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            samples.push(sample());
        }
        print_stats(label, &mut samples);
    }

    fn create_ready_sandbox(config: Config, context: &str) -> Sandbox {
        let mut sandbox = must(Sandbox::with_config(config), context);
        must(
            sandbox.wait_ready(READY_TIMEOUT),
            "failed to wait OS sandbox ready",
        );
        if !sandbox.is_ready() {
            panic!("OS sandbox is not ready after wait_ready");
        }
        sandbox
    }

    fn destroy_sandbox(sandbox: Sandbox, context: &str) {
        must(sandbox.destroy(), context);
    }

    fn assert_success(result: &ExecuteResult, context: &str) {
        if result.exit_code == Some(0) && !result.timed_out {
            return;
        }

        panic!(
            "{context}: exit_code={:?}, timed_out={}, stdout={}, stderr={}",
            result.exit_code,
            result.timed_out,
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }

    fn shell_quote(value: &str) -> String {
        let mut quoted = String::with_capacity(value.len() + 2);
        quoted.push('\'');
        for character in value.chars() {
            if character == '\'' {
                quoted.push_str("'\\''");
            } else {
                quoted.push(character);
            }
        }
        quoted.push('\'');
        quoted
    }

    fn shell_command(script: &str) -> String {
        format!("/bin/sh -c {}", shell_quote(script))
    }

    fn python_json_command() -> String {
        let program = r#"BEGIN { min = ""; max = 0; sum = 0; count = 0; for (i = 0; i < 1000; i++) { score = (i * 17) % 101; record = sprintf("{\"id\":%d,\"score\":%d}", i, score); split(record, parts, "\"score\":"); value = parts[2]; gsub(/[^0-9]/, "", value); value += 0; if (min == "" || value < min) min = value; if (value > max) max = value; sum += value; count++ } printf "%d %d %d %d\n", count, min, max, int(sum / count) }"#;
        format!("/usr/bin/awk {}", shell_quote(program))
    }

    fn filesystem_command() -> String {
        let script = r#"dir="${TMPDIR:-/tmp}"; i=0; count=0; while [ "$i" -lt 100 ]; do file="$dir/mimobox_file_$i.dat"; : > "$file" || exit 1; j=0; while [ "$j" -lt 10 ]; do printf "%1024s" "x" >> "$file" || exit 1; j=$((j + 1)); done; count=$((count + 1)); i=$((i + 1)); done; printf "%s\n" "$count""#;
        shell_command(script)
    }

    fn process_intensive_command() -> String {
        let script = r#"i=0; while [ "$i" -lt 50 ]; do /bin/sleep 0.01 & i=$((i + 1)); done; wait"#;
        shell_command(script)
    }

    fn date_command() -> &'static str {
        if cfg!(target_os = "macos") {
            "/bin/date +%s"
        } else {
            "/usr/bin/date +%s"
        }
    }

    fn mixed_commands() -> Vec<String> {
        vec![
            "/bin/echo mixed-throughput".to_string(),
            date_command().to_string(),
            "/bin/echo mimobox-user".to_string(),
            "/bin/ls /".to_string(),
            "/bin/cat /etc/hosts".to_string(),
            "/usr/bin/sort /etc/hosts".to_string(),
            "/usr/bin/wc -l /etc/hosts".to_string(),
            "/bin/echo mimobox-uid".to_string(),
            "/bin/echo mimobox-os".to_string(),
            "/bin/pwd".to_string(),
        ]
    }

    fn bench_cold_create_execute_destroy() {
        let mut create_samples = Vec::with_capacity(STANDARD_ITERATIONS);
        let mut execute_samples = Vec::with_capacity(STANDARD_ITERATIONS);
        let mut destroy_samples = Vec::with_capacity(STANDARD_ITERATIONS);
        let mut end_to_end_samples = Vec::with_capacity(STANDARD_ITERATIONS);

        for _ in 0..STANDARD_ITERATIONS {
            let end_to_end_start = Instant::now();

            let create_start = Instant::now();
            let mut sandbox = create_ready_sandbox(os_config(), "failed to create OS sandbox");
            create_samples.push(create_start.elapsed());

            let execute_start = Instant::now();
            let result = must(
                sandbox.execute("/bin/echo hello"),
                "failed to execute cold echo workload",
            );
            execute_samples.push(execute_start.elapsed());
            assert_success(&result, "cold echo workload failed");
            black_box(result);

            let destroy_start = Instant::now();
            destroy_sandbox(sandbox, "failed to destroy cold OS sandbox");
            destroy_samples.push(destroy_start.elapsed());

            end_to_end_samples.push(end_to_end_start.elapsed());
        }

        print_stats("os_cold_create_execute_destroy.create", &mut create_samples);
        print_stats(
            "os_cold_create_execute_destroy.execute",
            &mut execute_samples,
        );
        print_stats(
            "os_cold_create_execute_destroy.destroy",
            &mut destroy_samples,
        );
        print_stats(
            "os_cold_create_execute_destroy.end_to_end",
            &mut end_to_end_samples,
        );
    }

    fn bench_execute_workload(label: &str, config: Config, command: &str) {
        let mut sandbox = create_ready_sandbox(config, "failed to create workload OS sandbox");
        run_duration_samples(label, STANDARD_ITERATIONS, || {
            let start = Instant::now();
            let result = must(
                sandbox.execute(command),
                "failed to execute workload command",
            );
            let elapsed = start.elapsed();
            assert_success(&result, label);
            black_box(result);
            elapsed
        });
        destroy_sandbox(sandbox, "failed to destroy workload OS sandbox");
    }

    fn bench_mixed_throughput() {
        let commands = mixed_commands();
        let mut sandbox = create_ready_sandbox(os_config(), "failed to create mixed OS sandbox");

        run_duration_samples("os_mixed_throughput", STANDARD_ITERATIONS, || {
            let start = Instant::now();
            for command in &commands {
                let result = must(
                    sandbox.execute(command),
                    "failed to execute mixed throughput command",
                );
                assert_success(&result, "mixed throughput command failed");
                black_box(result);
            }
            start.elapsed()
        });

        destroy_sandbox(sandbox, "failed to destroy mixed OS sandbox");
    }

    fn bench_env_vars_impact(label: &str, env_count: usize) {
        run_duration_samples(label, STANDARD_ITERATIONS, || {
            let start = Instant::now();
            let mut sandbox = create_ready_sandbox(
                os_config_with_env(env_count),
                "failed to create env OS sandbox",
            );
            if sandbox.env_vars().len() != env_count {
                panic!(
                    "env var count mismatch: expected {env_count}, got {}",
                    sandbox.env_vars().len()
                );
            }

            let result = must(
                sandbox.execute("/bin/echo hello"),
                "failed to execute env impact command",
            );
            assert_success(&result, label);
            black_box(result);
            destroy_sandbox(sandbox, "failed to destroy env OS sandbox");
            start.elapsed()
        });
    }

    fn bench_metrics_sampling_overhead() {
        let mut sandbox = create_ready_sandbox(os_config(), "failed to create metrics OS sandbox");

        run_duration_samples("os_metrics_sampling_overhead", STANDARD_ITERATIONS, || {
            let before_start = Instant::now();
            black_box(sandbox.metrics());
            let before_elapsed = before_start.elapsed();

            let result = must(
                sandbox.execute("/bin/echo hello"),
                "failed to execute metrics overhead command",
            );
            assert_success(&result, "metrics overhead command failed");
            black_box(result);

            let after_start = Instant::now();
            black_box(sandbox.metrics());
            let after_elapsed = after_start.elapsed();

            before_elapsed.saturating_add(after_elapsed)
        });

        destroy_sandbox(sandbox, "failed to destroy metrics OS sandbox");
    }

    fn bench_create_destroy_storm() {
        run_duration_samples("os_create_destroy_storm", STORM_ITERATIONS, || {
            let start = Instant::now();
            let mut sandbox =
                create_ready_sandbox(os_config(), "failed to create storm OS sandbox");
            let result = must(
                sandbox.execute("/bin/echo storm"),
                "failed to execute storm command",
            );
            assert_success(&result, "storm command failed");
            black_box(result);
            destroy_sandbox(sandbox, "failed to destroy storm OS sandbox");
            start.elapsed()
        });
    }

    fn bench_list_100_sandboxes() {
        let mut sandboxes = Vec::with_capacity(LIST_SANDBOX_COUNT);
        for _ in 0..LIST_SANDBOX_COUNT {
            sandboxes.push(must(
                Sandbox::with_config(os_config()),
                "failed to create listed OS sandbox",
            ));
        }

        run_duration_samples("os_list_100_sandboxes", STANDARD_ITERATIONS, || {
            let start = Instant::now();
            let sandboxes = Sandbox::list();
            let elapsed = start.elapsed();
            if sandboxes.len() < LIST_SANDBOX_COUNT {
                panic!(
                    "sandbox list count too small: expected at least {LIST_SANDBOX_COUNT}, got {}",
                    sandboxes.len()
                );
            }
            black_box(sandboxes);
            elapsed
        });

        while let Some(sandbox) = sandboxes.pop() {
            destroy_sandbox(sandbox, "failed to destroy listed OS sandbox");
        }
    }

    pub fn run() {
        bench_cold_create_execute_destroy();
        bench_execute_workload(
            "os_python_json_workload",
            os_config(),
            &python_json_command(),
        );
        bench_execute_workload(
            "os_filesystem_workload",
            os_shell_config(),
            &filesystem_command(),
        );
        bench_execute_workload(
            "os_process_intensive",
            os_shell_config(),
            &process_intensive_command(),
        );
        bench_mixed_throughput();
        bench_env_vars_impact("os_env_vars_10_impact", 10);
        bench_env_vars_impact("os_env_vars_50_impact", 50);
        bench_env_vars_impact("os_env_vars_100_impact", 100);
        bench_metrics_sampling_overhead();
        bench_create_destroy_storm();
        bench_list_100_sandboxes();
    }
}

#[cfg(all(feature = "os", any(target_os = "linux", target_os = "macos")))]
fn main() {
    realworkload_os::run();
}

#[cfg(not(all(feature = "os", any(target_os = "linux", target_os = "macos"))))]
fn main() {}
