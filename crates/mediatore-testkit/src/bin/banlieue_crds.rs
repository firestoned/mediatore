// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Prints the banlieue CRDs the kind tier installs (`VirtualMachine`, `VirtualMachineClaim`),
//! rendered from the pinned `banlieue-api` so the cluster has exactly the schema the
//! watcher was compiled against. JSON, as a `v1/List`, which `kubectl apply -f` takes.

use banlieue_api::banlieue::{VirtualMachine, VirtualMachineClaim};
use banlieue_api::crdgen_support::prepared;
use kube::CustomResourceExt;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `prepared` is what banlieue's own crdgen applies: the raw derive output is not
    // what the API server accepts (nullable enums, descriptions).
    let list = serde_json::json!({
        "apiVersion": "v1",
        "kind": "List",
        "items": [prepared(VirtualMachine::crd()), prepared(VirtualMachineClaim::crd())],
    });
    println!("{}", serde_json::to_string_pretty(&list)?);
    Ok(())
}
