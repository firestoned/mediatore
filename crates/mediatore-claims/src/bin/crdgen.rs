// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Writes mediatore's CRDs (`AgentSandbox`, ADR-0008) as YAML: to stdout, or one file per
//! CRD into `--out-dir` under the kubebuilder name `<group>_<plural>.yaml`, which is how
//! `make crds` populates `deploy/base/crds/`. The Rust type is the source of truth; a unit
//! test fails when the checked-in file is stale.

use std::path::PathBuf;

use clap::Parser;
use mediatore_claims::sandbox;

#[derive(Parser)]
#[command(
    name = "crdgen",
    about = "Render mediatore's CRDs from their Rust types"
)]
struct Cli {
    /// Write `<group>_<plural>.yaml` files here instead of printing to stdout.
    #[arg(long)]
    out_dir: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let rendered = sandbox::crd_yaml()?;
    match cli.out_dir {
        Some(dir) => {
            std::fs::create_dir_all(&dir)?;
            let path = dir.join(sandbox::CRD_FILE_NAME);
            std::fs::write(&path, rendered)?;
            eprintln!("wrote {}", path.display());
        }
        None => print!("{rendered}"),
    }
    Ok(())
}
