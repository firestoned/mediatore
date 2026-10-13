// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Prints the fixture endorsement certificate (`--hash` for its EK hash instead), so the
//! kind tier and the unit tests agree on one certificate without copying it around.

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "ek-fixture",
    about = "The testkit's endorsement certificate fixture"
)]
struct Cli {
    /// Print the EK hash instead of the certificate.
    #[arg(long)]
    hash: bool,
}

fn main() {
    if Cli::parse().hash {
        println!("{}", mediatore_testkit::ek::RSA_EK_HASH);
    } else {
        print!("{}", mediatore_testkit::ek::RSA_EK_PEM);
    }
}
