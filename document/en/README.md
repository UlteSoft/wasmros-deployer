# Local deployment preflight

Build with `cargo build --release --locked --offline`. Rust dependencies are included under `third-parties/cargo`.

Use `wros-deployer plan deployment.xml` to check bundle paths, pinned Wasm and native driver hashes, budgets and permissions. `wros-deployer review deployment.xml` opens a terminal review for each VM. At the edit prompt use `allow NAME`, `deny NAME`, `remove NAME` and `confirm`. An absent recommendation file starts with empty permissions. The explicit `--accept-recommendations` option emits a warning. Output includes the proposed verifier and VM argument vectors. These commands perform local preflight. The supervisor, privileged launch, live update and physical safety receiver still require implementation and qualification.

```xml
<deployment id="cell">
  <vm id="body" module="body.wasm" sha256="REPLACE_WITH_64_LOWERCASE_HEX"
      policy="body.policy" recommendations="body-permissions.xml"
      memory-bytes="268435456" pids="8" start-on-boot="false" restart-on-crash="false"/>
  <driver id="joints" file="vendor/driver.so" vendor-version="1.2"
      sha256="REPLACE_WITH_64_LOWERCASE_HEX" hardware-id="cell-arm" kind="shared-library"/>
</deployment>
```

Use a separate file for recommendations. A recommendation exposes an import. Device and resource grants require their own reviewed policies. The current preflight covers interface exposure.

```xml
<recommendations><interface name="abi" expose="allow"/></recommendations>
```

The upstream fetcher resolves vendor URLs. It hands over local artifacts and release digests. The deployer rejects absent files, changed digests and duplicate hardware ownership within a manifest. Vendor code stays in separate processes. Full device exclusivity across deployments requires a trusted platform owner. Systemd is the preferred ultimate supervisor on Linux. A different platform supervisor must provide equivalent restart, user shutdown and resource ownership semantics.

Normal signed execution requires both wasm-cosign and VM verification. The design reserves separate operator warnings for accepting unsigned and invalidly signed modules. Network-facing DDS policies and authenticated local IPC are separate. Motion after a power or authority loss requires independent safety confirmation and human authorization. The recovery state machine performs a cold restart only when approved. Its host ABI remains experimental pending fault tests.
