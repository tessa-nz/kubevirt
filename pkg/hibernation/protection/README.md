# Hibernation state protection

The node TPM retains an attempt-specific age X25519 identity across reboot.
Only authenticated ciphertext is published on the state PVC. Restore verifies
a private memory-backed copy before libvirt reads it. A persistent TPM NV
record commits consumption before unpause; removing the persistent key and
verifying its absence completes cryptographic erasure.

Qualification is revision-specific: use the corresponding image lock and guest
results in the Orion lab. Emulator and mocked-libvirt tests alone do not qualify
a deployment image. Hardware TPM and target guest-size qualification are
required before production. The guest TPM, guest encryption setup, and guest
unlock keys are unchanged.

## Node and namespace requirements

- Linux, `/dev/tpmrm0`, TPM 2.0 owner hierarchy with existing empty authorization,
  SHA-256, ECC P-256, AES-128 salted HMAC sessions, sealed `CreatePrimary`
  objects, owner persistent handles, and NV `WRITEDEFINE`/`NV_WriteLock`.
  Nonempty owner authorization currently fails closed; the runtime does not
  change hierarchy authorization, PCR policy, or ownership.
- The low 16 bits of each attempt binding select handles in `0x814b0000` and
  `0x014b0000`. Both public identities are checked. A collision or exhausted
  TPM capacity rejects the operation without evicting another object. Capacity
  and persistence semantics must be qualified on the actual node TPM.
- No swap for handler and launcher: either the host has no active swap, or each
  process inherits cgroup-v2 `memory.swap.max=0`. Core dumps and process dumping
  are disabled before handling key/plaintext material. The launcher refuses to
  start its protected RPC server if these conditions or private tmpfs are absent.
- The node-shared runtime lock serializes TPM transactions across overlapping
  handler processes during rollouts. It is not a key or a recovery record.
- An administrator labels the namespace
  `hibernation.kubevirt.io/state-protection=enabled` before VM creation. The
  controller reserves a dedicated filesystem state PVC for that VM UID before
  creating its VMI. The PVC must satisfy the existing StorageClass, capacity,
  and RWO/RWOP admission requirements and cannot also be a guest disk.
- The private memory-backed `emptyDir` reserves guest RAM plus 10 percent plus
  1 GiB. Ordinary memory requests cover guest RAM, that full staging capacity,
  and normal KubeVirt overhead, even with guest-overhead overcommit enabled.
  A 32 GiB guest therefore needs at least 68.2 GiB plus normal overhead on the
  worker, before other workloads and the node's own memory. Hugepage-backed
  guest RAM is accounted in its separate resource. No plaintext-disk fallback
  or best-effort memory reservation exists.

## Trust and recovery

Node and cluster administrators remain in the existing guest-RAM trust
boundary. Private identities travel only over the existing private node Unix
RPC and are redacted from text/JSON formatting. Temporary byte buffers are
cleared; this is not a claim of forensic erasure of all Go heap or CPU copies.
The implementation never writes a private identity or reloadable private TPM
blob to a PVC, a Kubernetes object, or a host file. TPM CreatePrimary sensitive
input and Unseal output use salted encrypted sessions.

State-PVC readers see ciphertext. An external immutable VM/VMI digest binds the
ciphertext, plaintext checksum, public key identity, and compatibility data.
A forged age stream made with the public recipient fails that digest check.
Restore authenticates and verifies the entire stream before handing its
private copy to libvirt, so changing the PVC during the read cannot substitute
restored bytes. Metadata reads are bounded and reject symlinks/nonregular files.

Admission denies ordinary Pod mounts, exec/attach/ephemeral-container access to
protected launchers, VolumeSnapshots, PVC/DataVolume clones, DataSource aliases,
and VM exports involving reserved state PVCs. Mount and snapshot webhooks use
the namespace opt-in. Cross-namespace copy/export guards also inspect ordinary
namespaces and fail closed when their lookup fails; those operations depend on
virt-api availability. The guards remain active when the feature gate is off
so existing artifacts stay protected. Cross-resource admission is not a
transaction: an already-in-flight mount or copy can race reservation. Encryption
and the private authenticated restore copy still protect confidentiality and
integrity. Raw CSI/admin backups and availability attacks are outside this
ordinary-user boundary; storage-level backups need separate operator policy.

If libvirt has stopped the guest but ciphertext publication fails, the existing
save fence retains the private tmpfs image for same-launcher retry. Retry checks
libvirt's completed-save header and does not invoke save again. Loss of that
launcher or node before publication loses its private staged RAM and requires
terminal/manual recovery. A consumed artifact is never restored again, even
when its PVC metadata is rolled back. An uncertain consumption acknowledgement
never permits a second unpause. Finalization requires the current running,
Ready VMI and a freshly observed running domain before destroying the key.
Interrupted key destruction is retryable. Never clear a TPM to recover an
attempt; doing so can destroy unrelated keys and the last resumable state.

## Discarding a failed attempt

`PUT /apis/subresources.kubevirt.io/v1/namespaces/{namespace}/virtualmachines/{name}/discardhibernation`
accepts `{"attemptID":"the-current-attempt-id"}` and optional `"dryRun":["All"]`.
It requires the Hibernation gate and the `virtualmachines/discardhibernation`
update permission. Only `SaveIncomplete`, `ResumeRejected`, and
`RestoreCommitLost` may be discarded, after the previous VMI is absent.
Discarding `ResumeRejected` permanently gives up its possible recovery.
A missing or stale attempt ID is rejected; repeating the same pending or
completed request is safe.

The controller verifies the original reserved state PVC, binds cleanup to the
recorded source node, and moves the VM to `Discarding` with `runStrategy: Halted`.
Older attempts without a recorded source node require a frozen single-host
node selector that resolves to exactly one node. Otherwise cleanup stops for
operator investigation; it never guesses a node from the state files.
A small cleanup VMI mounts only the state PVC and cannot boot, restore, or
attach guest disks. It does not require the guest's memory allocation or
DataVolumes. Its protected server retains a small tmpfs and no-swap checks.

With no guest domain present, the handler destroys the matching TPM key and NV
record, accepting either unused or consumed state. Key and NV identity checks,
node binding, the shared transaction lock, and deletion readback remain in
force. The launcher then removes ciphertext and interrupted publication files
from the exclusively reserved slot and writes a nonsecret erasure receipt.
Unknown TPM or filesystem outcomes retain `Discarding` for retry, including
after launcher/controller replacement or a node reboot. The controller accepts
only a receipt for the exact current attempt and then removes the cleanup VMI.

Completion is `Discarded`, with the VM still halted. An explicit normal start
can cold-boot the guest later; it cannot recover the abandoned RAM or guest
unlock keys. A later hibernation uses a new attempt ID. The `discardedAt` receipt
does not claim that a successful resume occurred. Discard never clears the TPM
or deletes the VM, state PVC, or guest disks. Physical TPM erasure and power-loss
qualification remain separate from the emulator and local guest tests.

## Development checks

`go test -mod=vendor ./pkg/hibernation/protection` uses the pinned Microsoft
in-process TPM emulator through go-tpm-tools. It does not open a hardware TPM.
The emulator needs a C compiler and OpenSSL development headers; production
code has neither dependency. `hack/builder/Dockerfile` includes `openssl-devel`.
The older published builder `2606231619-4fe2cd536f` needs that package added in a
disposable derived image before running these tests. Production image builds
must use a rebuilt builder or equivalent explicitly recorded toolchain.

The same suite runs through
`bazel test --config=x86_64 //pkg/hibernation/protection:go_default_test`.
`hack/dep-update.sh` copies the emulator C tree from its checksum-verified pinned
module; `hack/bazel-generate.sh` restores its C input and OpenSSL declarations.
The suite covers reboot persistence, consumed-state replay, persistent NV write
locking, lost write/lock/erasure acknowledgements, concurrent handler instances,
foreign-handle preservation, cipher tampering, and key redaction.

Launcher lifecycle fixtures must run inside an isolated no-swap cgroup with
private tmpfs mounted at `/var/run/kubevirt-private/hibernation-staging` and
read access to `/dev/kvm` for capability checks. They use mocked libvirt calls;
a passing test is not a guest restore or hardware TPM qualification. The
`hibernation_lab` build tag enables fault hooks and must be omitted from
production builds.
