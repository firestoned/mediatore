// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! An in-memory stand-in for the Kubernetes API behind the user API's `AgentSandbox` front
//! door (ADR-0008 decision 4). No more permissive than the API server: a taken name is a
//! conflict, a spec the CRD schema would refuse is invalid, and a sandbox is only ever
//! found in the namespace it was created in. Reconciliation is not simulated; a test sets
//! the status it wants the API to mirror.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use kube::ResourceExt;
use mediatore_claims::sandbox::{
    AgentSandbox, AgentSandboxStatus, FrontDoorError, SandboxFrontDoor,
};

/// The fake API server, keyed by namespace and name.
#[derive(Default)]
pub struct MemorySandboxes {
    items: Mutex<HashMap<(String, String), AgentSandbox>>,
}

impl MemorySandboxes {
    /// Every sandbox, in no particular order.
    ///
    /// # Panics
    /// If the lock is poisoned (a test already failed).
    #[must_use]
    pub fn all(&self) -> Vec<AgentSandbox> {
        self.items.lock().unwrap().values().cloned().collect()
    }

    /// Set the status the reconciler would have written.
    ///
    /// # Panics
    /// If no such sandbox exists, or the lock is poisoned.
    pub fn set_status(&self, namespace: &str, name: &str, status: AgentSandboxStatus) {
        let mut items = self.items.lock().unwrap();
        let sb = items
            .get_mut(&(namespace.to_owned(), name.to_owned()))
            .expect("sandbox exists");
        sb.status = Some(status);
    }
}

/// What the CRD schema refuses (`crates/mediatore-claims/src/sandbox.rs`).
fn validate(sb: &AgentSandbox) -> Result<(), FrontDoorError> {
    let spec = &sb.spec;
    let invalid = |what: &str| Err(FrontDoorError::Invalid(what.to_owned()));
    if sb.metadata.name.as_deref().unwrap_or("").is_empty() {
        return invalid("metadata.name is required");
    }
    if sb.metadata.namespace.as_deref().unwrap_or("").is_empty() {
        return invalid("metadata.namespace is required");
    }
    if spec.ttl_seconds == 0 {
        return invalid("spec.ttlSeconds must be at least 1");
    }
    if spec.subject.issuer.is_empty() || spec.subject.id.is_empty() {
        return invalid("spec.subject.issuer and spec.subject.id must not be empty");
    }
    if spec.workload.image.is_empty() {
        return invalid("spec.workload.image must not be empty");
    }
    if spec.pool_ref.name.is_empty() {
        return invalid("spec.poolRef.name must not be empty");
    }
    Ok(())
}

#[async_trait]
impl SandboxFrontDoor for MemorySandboxes {
    async fn create(&self, mut sandbox: AgentSandbox) -> Result<AgentSandbox, FrontDoorError> {
        validate(&sandbox)?;
        let key = (sandbox.namespace().unwrap_or_default(), sandbox.name_any());
        let mut items = self.items.lock().unwrap();
        if items.contains_key(&key) {
            return Err(FrontDoorError::Conflict(format!(
                "agentsandboxes \"{}\" already exists",
                key.1
            )));
        }
        sandbox.metadata.uid = Some(uuid::Uuid::new_v4().to_string());
        sandbox.metadata.generation = Some(1);
        sandbox.metadata.creation_timestamp = Some(Time(k8s_openapi::jiff::Timestamp::now()));
        items.insert(key, sandbox.clone());
        Ok(sandbox)
    }

    async fn get(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Option<AgentSandbox>, FrontDoorError> {
        Ok(self
            .items
            .lock()
            .unwrap()
            .get(&(namespace.to_owned(), name.to_owned()))
            .cloned())
    }

    async fn delete(&self, namespace: &str, name: &str) -> Result<(), FrontDoorError> {
        self.items
            .lock()
            .unwrap()
            .remove(&(namespace.to_owned(), name.to_owned()));
        Ok(())
    }
}
