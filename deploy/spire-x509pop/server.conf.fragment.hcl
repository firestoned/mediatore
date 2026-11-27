# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# The block server.conf gains (ADR-0049), inside `plugins { ... }`, beside the k8s_psat
# attestor the in-cluster agents use and the tpm attestor of deploy/spire-tpm. Built into
# the server: no plugin_cmd, no checksum. agent_path_template is decision 2 and must be
# exactly this: the issuer's common name confines a host CA to IDs under its own name, and
# the broker computes the same ID (spiffe://<td>/spire/agent/x509pop/<issuer CN>/<subject
# CN>) before the guest boots. The default template (a fingerprint of the certificate)
# would change the ID at every renewal. The rendered server.conf is JSON when it comes
# from the hardened chart; the same block in JSON is:
#
#   "NodeAttestor": [{"x509pop": {"plugin_data": {"ca_bundle_path": "/x509pop/ca-bundle.pem",
#     "agent_path_template": "/x509pop/{{ .Issuer.CommonName }}/{{ .Subject.CommonName }}"}}}]
plugins {
  NodeAttestor "x509pop" {
    plugin_data {
      # The file the init container joins from the ConfigMap's keys (statefulset-patch.yaml).
      ca_bundle_path = "/x509pop/ca-bundle.pem"
      agent_path_template = "/x509pop/{{ .Issuer.CommonName }}/{{ .Subject.CommonName }}"
    }
  }
}
