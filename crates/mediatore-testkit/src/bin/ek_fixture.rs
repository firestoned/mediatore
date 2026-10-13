// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Prints the fixture endorsement certificate (`--hash` for its EK hash instead), so the
//! kind tier and the unit tests agree on one certificate without copying it around.

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--hash") {
        println!("{}", mediatore_testkit::ek::RSA_EK_HASH);
    } else {
        print!("{}", mediatore_testkit::ek::RSA_EK_PEM);
    }
}
