# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# The block server.conf gains (ADR-0018), inside `plugins { ... }`, beside the k8s_psat
# attestor the in-cluster agents use. The server refuses to load the plugin unless the
# binary's sha256 equals plugin_checksum. Only ca_path is set: the hash allowlist is
# empty by design (decision 2). The rendered server.conf is JSON when it comes from
# the hardened chart; the same block in JSON is:
#
#   "NodeAttestor": [{"tpm": {"plugin_cmd": "/tpm/tpm_attestor_server",
#     "plugin_checksum": "5f32c3e8cc6c81fa1060a9155eea0a455935d199278406384567ffa125127d83",
#     "plugin_data": {"ca_path": "/tpm/cas"}}}]
plugins {
  NodeAttestor "tpm" {
    plugin_cmd = "/tpm/tpm_attestor_server"
    plugin_checksum = "5f32c3e8cc6c81fa1060a9155eea0a455935d199278406384567ffa125127d83"
    plugin_data {
      # The copies the init container makes of the ConfigMap's files (statefulset-patch.yaml).
      ca_path = "/tpm/cas"
    }
  }
}
