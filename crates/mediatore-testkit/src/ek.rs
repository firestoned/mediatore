// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! A vTPM endorsement certificate fixture: a throwaway self-signed RSA certificate (no
//! real TPM has this key) and the hash the guest, the attestor and `mediatore_proto::ek`
//! compute for it. The watcher tests feed it through a claim's status; the kind tier
//! patches it onto a `VirtualMachine`.

/// PEM of the fixture certificate.
pub const RSA_EK_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDKzCCAhOgAwIBAgIUc1LZdJY2wxbquwgnAWadY8bLBZkwDQYJKoZIhvcNAQEL
BQAwJTEjMCEGA1UEAwwaYmFubGlldWUtZWstcHJvYmU6dGVzdC1yc2EwHhcNMjYx
MDEyMDg1NDUyWhcNMzYxMDA5MDg1NDUyWjAlMSMwIQYDVQQDDBpiYW5saWV1ZS1l
ay1wcm9iZTp0ZXN0LXJzYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AIJ8QlviTjX4SiU2hPOG0RYmSQaXAN9sLHuKlQ7KI6g3DEG+qpHoEt75u7Yt+W0c
tPNIJ//+14E6PXlQRVcC8yOVcxX0Gs0pim44CGQVEtIWXJ//sgiY9Sa64ZJ7iiKv
wZXIMHrpgjNANA3jk9m4yNLhTsqhibPKAqLYnlS+bKXiZa6fG46wE+R2rak3B8GB
9lRZ/0JClYdy2q/gfZ5t0bfutUCHdOycErBDodUACLjKN1cERxyF0EFHuI1QcsPl
rtuCBuO97et36hhR1uckdfIVw6tta/E3tjBz92X0zKk0Cd9Wt8ZXfYzyPXA2J2q0
LqUGXM+8gz+WJl2bHL3Nb8kCAwEAAaNTMFEwHQYDVR0OBBYEFFHIqZWt35p1rFkC
N/uRZ/uaNFhuMB8GA1UdIwQYMBaAFFHIqZWt35p1rFkCN/uRZ/uaNFhuMA8GA1Ud
EwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAEEWRy7q8v1i+5C8N+SnRPEf
gusVTvKEF4ZWaiIwqVcSvXLOdsL/fczL08Kxxh607du+L+VXj1sTgszj0VclH+lT
hErz04WbstUkk6zYNKramByijTzgMGaF8KIHdA5ES1yOJGqMDgXYOr4f067pKPYC
HcxKBwr/OD4n8rHkbnFb+ewr3cDRKawW9P8j7m/ZaCBd/gvK5VWc1wzZU4/LfNVG
YBrfxo85qxRvJtmEk9mIC3mYhhovOizbIsIzR5vRNrXoTM7WImz6X/Yf6eNLKvjz
lIAMzxQTSBKBz/W/dLdog/AKmdZMAGaUs9RUtV7trtK+nNkTgzuFHsz7Tbs8fWk=
-----END CERTIFICATE-----
";

/// `sha256(SubjectPublicKeyInfo DER)` of [`RSA_EK_PEM`], hex: the node identity it maps to.
pub const RSA_EK_HASH: &str = "72c566555391e835a15c522680b51ec3b840561ed70af5605a5ae4835f040ee8";
