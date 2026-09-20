# Hibernation key service

This directory is an implementation candidate, not a qualified release. No
production VM should use it before the registration, hardware and disposable
VM rollout gates pass.

Build from the repository root with the Containerfile. Release builds must pin
both the Go builder and the resulting service image by digest. The same binary
provides the service and administration commands. There is no shell in the image.

On TrueNAS, create a dedicated dataset, owned by root with mode 0700, and deploy
`truenas-custom-app.yaml` through Apps / Install via YAML or the supported app
management API. Resolve the image, provider IP, TPM group and dataset variables
before submitting the definition. Compose uses `compose.yaml` with the same
settings. Restrict TCP 19443 at the provider/network firewall to the necessary
Orion hosts before starting the listener. Do not expose it through a public proxy.

Initialization is an explicit one-time command using the same image, dataset,
TPM device, memory/swap and capability restrictions, overriding the command to
`init --state-dir=/state --hostname=nas.home.hawara.nz`. It refuses an existing
state directory or orphaned hibernation TPM objects. Copy only the resulting
public CA certificate and TPM provider identity into registration configuration.
Never publish the CA key, server key, client key or database in Git.

Administrative requests use stdin and the root-only Unix socket:

```sh
printf '%s\n' '{"operation":"inspect"}' | docker exec -i CONTAINER /key-service admin
```

Supported JSON operations:

- `inspect`: public registration and attempt records, including pending requests.
- `approve`: include `requestID` and independently verified `fingerprint`.
- `grant` / `ungrant`: include `requestID` and `grant` containing exact `clusterID`
  and `vmUID`. Approval alone grants no VM access.
- `revoke`: include `requestID`; effective on every operation, including existing
  TLS connections. This never deletes an attempt or key.
- `renew-server`: renews the server certificate under the current CA and key.
  New TLS connections load it immediately. CA replacement needs planned public
  trust-bundle maintenance; it must not change the TPM provider identity.

Client registration uses a dedicated persistent root-only directory on the node.
Compare the fingerprint obtained through trusted node access with the pending
request before approval. A lost key requires explicit re-enrollment and fresh
approval. CRD status and requested VM hints never grant service access.

Container replacement is supported with the same dataset and TPM. Moving active
keys to another TPM is unsupported. Never restore an old database and assume a
consumed attempt is reusable: consumption is authoritative in the TPM. Startup
refuses missing or inconsistent ownership metadata. Preserve the dataset and TPM
and perform recovery inspection rather than initializing over them. Do not delete
keys in response to expiry, an outage or a missing Kubernetes resource.

Host reboot/power-loss and full-size/cross-kernel qualification are separate
maintenance activities. This deployment definition does not authorize them.

The non-loopback listener also requires `--allow-client-cidrs`, supplied through
`HIBERNATION_ALLOWED_CLIENT_CIDRS` in Compose. Use individual host `/32` or `/128`
entries where possible. The listener rejects other source addresses before the
TLS handshake and rejects an unrestricted `/0` configuration.

When startup refuses metadata, stop the service and run `inspect-offline` with
the same dataset, TPM mapping and memory restrictions. It reads the database and
compares public TPM identity, known attempt states and ownership inventory. It
never consumes, opens or deletes a key. Preserve its nonsecret report and resolve
the discrepancy explicitly. Do not use `init` as recovery.

`alerts.yaml` contains alert templates. Configure an authenticated mTLS scrape of
the service; a dedicated approved monitoring identity needs no VM grants. The
handler exposes registration readiness, renewal failures and certificate expiry
through its existing metrics endpoint. Label the service scrape job
`hibernation-key-service` to match the availability rule. A missing scrape target
must also be covered by the site's configuration/target-presence monitoring.

The operator installs `hibernation.kubevirt.io:registration-admin` without a
binding. It permits registration configuration and the separate `use` verb for
VM selection, but not status writes. Delegate it only to infrastructure
administrators. To delegate one existing registration, grant `use` with that
registration in `resourceNames`; ordinary VM edit permissions are insufficient.
The VM must select the registered node's `kubernetes.io/hostname` label. Its
registration annotation cannot change during an active attempt, even for a
trusted controller.
