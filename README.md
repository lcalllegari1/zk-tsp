# ZK-TSP architectures

*Architectural Trade-offs in Zero-Knowledge Proof Decomposition*  
*A Traveling-Salesman Case Study*

The prover holds a route and certifies that it visits every node once, returns
to its start, and stays below a public cost threshold. The privacy objective is
to hide the route and its exact cost. Route search and optimality are outside
the proved statement.

The thesis compares one monolithic proof with smaller segment proofs followed
by recombination. It measures how those choices affect prover memory and
completion time, and examines what the final verifier must check and can learn.
The circuits use Noir and UltraHonk through Barretenberg.

## Constructions

Every construction below authenticates route costs against a public Poseidon2
Merkle root. `K` is the number of route segments.

| Construction | Coverage | Final proof set | Per-segment information exposed to the final verifier |
|---|---|---|---|
| Monolithic sort | Exact | One proof | None |
| Plain sort | Exact | `K + 1` proofs | Node sets, endpoints and partial costs |
| Plain product | Product fingerprint | `K + 1` proofs | Endpoints, partial costs and testable fingerprints |
| Committed sort | Exact | `K + 1` proofs | Blinded commitments |
| Committed product | Product fingerprint | `K + 1` proofs | Blinded commitments, plus a public route-derived challenge |
| Recursive product | Product fingerprint | One outer proof | None |

Product coverage adds a negligible probabilistic soundness error under the
thesis's stated assumptions. External composition requires both verification
of all `K + 1` proofs and reconciliation of their public inputs. Recursion
performs the inner proof checks inside the outer circuit.

The repository also includes the four public-matrix coverage mechanisms studied
in Chapter 4: pairwise distinctness, an indicator vector, an inverse permutation
and sorting. Monolithic product provides the mechanism-matched control used in
Chapter 6. See [Architecture](docs/architecture.md) for the interfaces and code
layout.

## Quick start

Use Linux with Python 3.12 and the measured toolchain available on `PATH`:

| Tool | Version |
|---|---|
| Noir / Nargo | `1.0.0-beta.20`, noirc commit `b4236c1957d0c26cb65d82adc9e5447b6ff1d629` |
| Barretenberg | `5.0.0-nightly.20260324` |
| Rust / Cargo | `1.94.0` |

Run from the repository root:

```bash
make install BOOTSTRAP_PYTHON=python3.12
source .venv/bin/activate
zk-tsp check-toolchain
```

`make install` creates the Python environment and installs the package with
NumPy 2.4.4. It does not install Nargo, Barretenberg or Rust. The Python
interpreter needs venv support. The first circuit and Rust builds fetch their
pinned dependencies and require network access.

Prove and verify an eight-node instance with the canonical monolithic baseline:

```bash
zk-tsp benchmark monolithic \
  --mechanism sort --nodes 8 --runs 1 --seed 42 \
  --output build/monolithic-smoke.csv
```

This runs witness generation, proving and verification, then writes one CSV row
with circuit size, timings, proof size and backend-reported memory. The
benchmark uses temporary circuit workspaces and does not retain the proof.

To run the four external constructions on the same small instance:

```bash
zk-tsp benchmark composite \
  --variant all --nodes 8 --segments 2 --runs 1 --seed 42 \
  --output build/composite-smoke.csv
```

Each variant produces two segment proofs and one glue proof, including the
verifier's cross-proof checks. Choose a new output filename when repeating a
benchmark. Composite configurations require `K >= 2`, `N % K = 0` and
`N / K > 2`.

The [Reproduction guide](docs/reproduction.md) covers retained proof sets,
recursive setup and proving, and larger benchmark grids. Canonical circuit
sources stay unchanged during all runs. Generated workspaces and caches may
contain private witness data and should not be shared as verifier packages.

## Experimental data

The repository preserves the thesis measurements in `results/frozen/` and the
derived recursive inputs in `results/derived/`. Validate those files and
reproduce the aggregate CSV tables without running the prover:

```bash
zk-tsp results validate
zk-tsp results reproduce --output build/reproduced-results
```

The output contains component observations, complete architecture runs and
summary statistics. Figure generation and a complete check of the printed
thesis tables are not included in these commands.

The recursive inputs preserve historical timings and memory measurements.
Their outer gate and ACIR counts include the calibrated correction of 113 for
the embedded verification key. The [results manifest](provenance/results-manifest.json)
records the source files and hashes. New benchmarks remain separate from the
frozen observations.

Measurements describe one consumer host and one proving stack. Timings use the
minimum successful repeated observation, and memory uses the median of each
run's maximum backend-reported checkpoint. Distributed completion times are
projections from component measurements with additional comparable workers.
They exclude communication and coordination costs.

## Tests and security

```bash
make test
make smoke
```

The tests check source and witness equivalence, valid and adversarial inputs,
external proof mixing, recursive key binding and result aggregation. Both
commands require the proving toolchain. `make smoke` runs small benchmarks
across every construction, including actual recursive proof generation.

The tests provide implementation checks, not a formal security proof or an
external audit. A verifier must obtain the intended matrix root, threshold and
verification keys independently of the prover. Recursive verification defaults
to `workspace-local` metadata, which checks consistency within that workspace.
Independent key authentication requires trusted build metadata.

Privacy concerns the final verifier. Workers receiving witness material are
outside that guarantee. Public summaries can disclose or allow inference of
route information. See [Security](docs/security.md) for the assumptions and
disclosure profiles.
