//! mcp-shield entrypoint.

use clap::Parser;

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let cli = mcp_shield::cli::Cli::parse();
    let code = match dispatch(cli).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            2
        }
    };
    std::process::exit(code);
}

async fn dispatch(cli: mcp_shield::cli::Cli) -> anyhow::Result<i32> {
    use mcp_shield::cli::Commands;
    match cli.command {
        Commands::Audit { json } => Ok(mcp_shield::config::run_audit(json)?),
        Commands::Wrap { target, dry_run } => Ok(mcp_shield::config::run_wrap(&target, dry_run)?),
        Commands::Unwrap => Ok(mcp_shield::config::run_unwrap()?),
        Commands::Exec {
            server_name,
            policy,
            command,
        } => mcp_shield::proxy::run(server_name, policy, command).await,
        Commands::Verify => mcp_shield::verify::run().await,
        Commands::Doctor => mcp_shield::doctor::run_doctor(),
        Commands::ResignPolicy { policy } => mcp_shield::policy::resign_policy(policy),
        Commands::MockServer => {
            mcp_shield::mock_server::run()?;
            Ok(0)
        }
    }
}
