#[cfg(any(target_os = "linux", target_os = "macos"))]
use mimobox_os::run_pool_benchmark;

use super::*;
use crate::capture::capture_benchmark_output;
use crate::{DEFAULT_BENCH_ITERATIONS, DEFAULT_POOL_SIZE};
use tracing::info;

/// Handles the bench request.
pub(crate) fn handle_bench(args: BenchArgs) -> Result<BenchResponse, CliError> {
    info!(
        target = ?args.target,
        pool_size = DEFAULT_POOL_SIZE,
        iterations = DEFAULT_BENCH_ITERATIONS,
        "preparing to execute bench subcommand"
    );

    let raw_output = capture_benchmark_output(|| {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            run_pool_benchmark(DEFAULT_POOL_SIZE, DEFAULT_BENCH_ITERATIONS)
                .map_err(|error| CliError::Benchmark(error.to_string()))
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = args;
            Err(CliError::BenchUnsupported)
        }
    })?;

    let note = match args.target {
        BenchTarget::ColdStart => {
            "The bench subcommand reuses run_pool_benchmark; output includes both cold start and hot acquire summaries."
        }
        BenchTarget::HotAcquire => {
            "The bench subcommand reuses run_pool_benchmark; focus on the hot acquire metrics."
        }
        BenchTarget::WarmThroughput => {
            "The public API only exposes a combined pool benchmark; for finer-grained warm-throughput analysis, use criterion benchmarks directly."
        }
    };

    Ok(BenchResponse {
        target: args.target,
        pool_size: DEFAULT_POOL_SIZE,
        iterations: DEFAULT_BENCH_ITERATIONS,
        raw_output: raw_output.trim().to_string(),
        note,
    })
}
