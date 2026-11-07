# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# The block server.conf gains (ADR-0031), inside `plugins { ... }`: the server's CA signed
# by OpenBao's PKI engine. vault_addr and the role are the operator's; the two paths are
# where statefulset-patch.yaml mounts the OpenBao CA and the projected ServiceAccount
# token (audience openbao, one hour). ca_ttl stays the server's (24h): it is the
# intermediate's life now, and the mount's maximum lease (a week in the kind setup) caps
# what any holder of the server's token could ask for. The
# rendered server.conf is JSON when it comes from the hardened chart; the same block in
# JSON is what dev/kind/spire/render-server-conf-patch.sh produces from this file.
plugins {
  UpstreamAuthority "vault" {
    plugin_data {
      vault_addr = "https://openbao.home.example:8200"
      pki_mount_point = "spire"
      ca_cert_path = "/upstream/ca/ca.pem"
      k8s_auth {
        k8s_auth_mount_point = "kubernetes"
        k8s_auth_role_name = "spire-server"
        token_path = "/upstream/token/token"
      }
    }
  }
}
