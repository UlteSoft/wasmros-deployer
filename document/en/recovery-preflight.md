# Check a recovery module

Run the local installer check before assigning a recovery module to a watchdog.

```sh
wros-deployer inspect-recovery candidate.wasm
```

The command opens one regular file and hashes the same bytes that it validates. It prints the SHA-256 digest, selected function, linear memory range and static instruction count. It requires no deployment XML, root access, policy directory or running VM. The command only reads the candidate. It grants zero host operations. Deployment still uses the reviewed native cold-restart policy.

## Accepted profile

The validator checks the original WebAssembly MVP grammar, operand types, indices, function bodies and branch rules. The module must provide exactly one private 32-bit memory with an explicit maximum. A standard start section or a single exported `_start` function selects the entry point. Its signature must be `() -> ()`. Declaring both entry mechanisms is an error. Recovery ABI experiments, WASI, external tables, foreign functions, private MTE instructions and threads are outside this profile. WebAssembly Component Model binaries and component-type metadata are rejected.

| Resource | Maximum |
| --- | ---: |
| Module file | 65,536 bytes |
| Private linear memory | 16 standard pages (1 MiB) |
| Functions and function types | 128 each |
| Parameters per function type | 32 |
| Declared locals per function, excluding parameters | 256 |
| Static instructions across all function bodies | 8,192 |
| Nested control frames including the function frame | 64 |
| Globals | 64 |
| Optional private table | 256 elements with an explicit maximum |
| Element segments and data segments | 128 each |

Loops and recursion are legal MVP. The static instruction count bounds the validator's input. Runtime fuel, operand and call stack limits, an independently enforced timeout and fault-specific authority still belong to the future watchdog. A module that passes this check may trap when executed. The deployer neither runs it nor lets it request a restart, a software update or motion.

## Implementation and reproduction

The default `recovery-preflight` Cargo feature belongs to the installer. It enables the vendored wasmparser validator with its MVP feature mask. Building with `--no-default-features` removes the validator dependency. A separate minimal watchdog must have its own MVP-only interpreter and dependency closure. The recovery host ABI remains under qualification.

`tests/recovery_preflight.py` uses the upstream WABT assembler and validator as an independent reference and executes permitted samples with the upstream interpreter. Run it inside the shared qualification cgroup. It takes `--deployer PATH` and a fresh `--output` directory under this repository's `.tmp`. Tests cover both entry mechanisms, a real linear-memory computation, a deliberate runtime trap, extension and import rejection, resource ceilings, malformed input and special files. WABT is a test dependency.
