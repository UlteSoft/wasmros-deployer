# Deploying a bundle from one XML file

Pass the entry XML to `wros-deployer plan`, `review`, `verify`, `authorize`, `service` or `run`. The deployment and recommendation documents have independent schemas. Every file path in a bundle, including paths inside a fragment, is relative to the directory containing the entry XML.

For example, a cell can keep its telemetry process in a separate package.

```xml
<deployment id="cell">
  <include file="telemetry/process.xml"/>
</deployment>
```

In `telemetry/process.xml`, declare the Wasm artifact, digest, protected trust policy and separate recommendations. Replace the example digest with the SHA-256 of the signed artifact. The trust policy paths resolve beneath the operator's policy root.

```xml
<deployment-fragment>
  <vm id="telemetry" module="telemetry/reader.wasm"
      sha256="0000000000000000000000000000000000000000000000000000000000000000"
      policy="telemetry-admission.policy" vm-policy="telemetry-runtime.policy"
      recommendations="telemetry/rights.xml" uid="10021" gid="10021"
      memory-bytes="134217728" pids="8"/>
</deployment-fragment>
```

A deployment fragment can include further fragments and declare VMs or drivers. The entry document owns the supervisor settings. The parser checks process IDs, driver attachments and resource conflicts across the expanded deployment. Each VM has its own recommendation set. For example, `telemetry/rights.xml` can reuse a file containing clock decisions.

```xml
<recommendations>
  <include file="common/clocks.xml"/>
  <interface name="type.describe" expose="allow"/>
</recommendations>
```

The included file also has a `recommendations` root. The review prints the source paths, digests, executable inputs and effective permissions. Repeated references to the same file contribute one copy to each graph. Duplicate decisions from distinct declarations, dependency cycles, symbolic links, absolute paths and missing files fail admission. All inputs in a review share a limit of 256 XML files and 8 MiB. A graph has a depth limit of 16 and an expanded size limit of 256 KiB.

A run checks the Wasm and ELF inputs before the first permission prompt. Before it consumes approval it rechecks the reviewed XML files. A durable restart binds the deployment graph and uses the rights previously confirmed for each VM. Changes to workload declarations require fresh approval.

## Wasm libraries in the same VM

A VM can register up to 32 libraries. Give the main image and each library its signed WSEA `module-id`. A library's `namespace` is the exact name used by its Wasm consumers. Each consumer lists its direct dependencies with `requires`. All module paths are relative to the bundle root. Replace the example digests with the SHA-256 of each complete signed file.

```xml
<deployment id="cell">
  <vm id="telemetry" module-id="example.telemetry" module="telemetry.wasm"
      sha256="0000000000000000000000000000000000000000000000000000000000000000"
      policy="admission.policy" vm-policy="runtime.policy"
      uid="10021" gid="10021" memory-bytes="134217728" pids="8">
    <requires module="units"/>
    <library namespace="units" module-id="example.units" module="lib/units.wasm"
        sha256="1111111111111111111111111111111111111111111111111111111111111111"
        policy="admission.policy" vm-policy="runtime.policy"/>
  </vm>
</deployment>
```

A library can contain its own `requires` elements. The deployer rejects cycles, unreachable declarations, duplicate names and missing or extra edges. It checks the actual import namespace, field and signature against the submitted provider. Supported links are core Wasm functions with numeric `i32`, `i64`, `f32` and `f64` parameters and results. A library has zero host permissions at every start. Library host imports, shared memory and inter-module memory, table, global, tag or reference links fail preflight. The VM's reviewed host interfaces remain scoped to the main module.

The deployer checks each signed identity and complete file digest. The VM independently checks every selected identity using its own protected rollback store. Shared WSEA policies can authorize several identities. Each primary/VM policy pair needs identical rules and separate rollback directories. The supervisor copies only sealed bytes into guest-private, read-only files. Main and library images share a 256 MiB limit. Static import names select explicit declarations, and system search paths are never used.

`--allow-unsigned telemetry/units=SHA256` and `--allow-invalid-signature telemetry/units=SHA256` apply only to the named VM, library namespace, digest and rejection class. A different valid signed identity still fails. An exception preserves the same link checks and zero host permissions. Durable resume reopens and verifies the complete graph against the bound configuration, image digests, trust files and stored decisions. A restart under the running supervisor uses the same sealed files and repeats VM verification.
