# Architecture

## Statement

The artifact studies proofs of this thresholded TSP relation: a private ordered
cycle visits every node exactly once, its authenticated edge costs come from one
cost matrix, and its total cost is at most the public threshold `T`.

The implementations are grouped by cost-matrix interface and proof structure:

| Group | Cost-matrix interface | Coverage mechanism | Proof shape |
|---|---|---|---|
| `monolithic/study` | Public `N × N` matrix | pairwise, presence, inverse, or sort | one proof |
| `monolithic/committed` | Public Poseidon2 Merkle root | exact sort or route-bound product | one proof |
| `composite/{plain,committed}_{sort,product}` | Public Poseidon2 Merkle root | exact global sort or route-bound product | `K` segment proofs plus one glue proof |
| `composite/recursive_product` | Public Poseidon2 Merkle root | route-bound product | one outer proof verifying `K` private inner proofs |

The [source manifest](../provenance/import-manifest.json) maps each circuit to
its experimental source and records compilation-equivalence fingerprints.

## External composite relation

For valid geometry, `K >= 2`, `N mod K = 0`, and `M = N / K > 2`. The witness
builder partitions the ordered cycle into `K` consecutive segments of length
`M`.

Each segment circuit authenticates its `M - 1` internal edges against the
matrix root and sums their costs. It publishes either the values needed to
reconnect the proof set or a commitment to them. The glue circuit authenticates
the `K` boundary edges, checks the full cost against `T`, and establishes global
coverage. This division accounts for every edge exactly once:
`K(M - 1) + K = N`.

The two coverage mechanisms differ as follows:

| Variant | Segment public output | Glue coverage check |
|---|---|---|
| `plain-sort` | sorted nodes, endpoints, partial cost, root | concatenated summaries sort to `0..N-1` |
| `plain-product` | endpoints, partial cost, root, product and chain anchors, `c`, `X` | chain continuity and `∏ P_i = ∏(X + j)` for `j = 0..N-1` |
| `committed-sort` | root and commitment `C_i` | opens every commitment, checks the concatenated nodes sort to `0..N-1` |
| `committed-product` | root, `X`, and commitment `C_i` | opens every commitment, then checks chain continuity and the global product identity |

For product coverage, `c` is the terminal value of a Poseidon2 fold over the
ordered route and `X = Poseidon2(c)`. Every segment proves its portion of the
same fold and its product at the same `X`.

The committed variants replace the publicly exposed per-segment summaries with
Poseidon2 fold commitments. Each fold starts from an independently sampled
128-bit operating-system blinding. A segment proves its committed local
summary, while glue privately opens the same commitment to the data needed for
coverage, boundary, and threshold checks. The builder copies each `r_i` and
`C_i` consistently into both witnesses and regenerates them before every
benchmark run.

The `K + 1` circuits are independent Noir programs. Backend verification alone
does not compose them. The external verifier therefore performs this sequence:

1. Verify every segment proof under the shared segment verification key.
2. Verify the glue proof under its verification key.
3. Parse the declared public inputs.
4. Match exposed summaries for plain variants, or segment commitments for
   committed variants; also match the product challenge where applicable.
5. Match the glue root and threshold to `statement.json`.

## Recursive product relation

Recursive product reuses the plain-product segment relation as its inner
circuit. The outer circuit receives the `K` inner proofs and their nine-field
public-input vectors as private witness, verifies them under one fixed segment
key, and performs the product, chain, boundary-Merkle, and threshold checks
inside the outer relation. Its only public inputs are `(root, threshold)`.

The segment verification key is not a witness. Preparation first compiles the
configured inner circuit and generates its 115-field recursive key and key
hash. Those values become source constants in the configured outer workspace.
Compiling that source produces an outer verification key that transitively
identifies the inner relation. `build-metadata.json` records the complete
artifact-to-key chain.

The final verifier checks one outer proof. It must select the intended outer key
through trusted build metadata; accepting a key and metadata supplied together
by an untrusted prover would authenticate only the prover's chosen circuit.

## Workspace layout

A prepared composite workspace is self-contained:

```text
workspace/
├── metadata.json
├── statement.json
├── instance.json
├── cycle.json
├── sub_0/ ... sub_{K-1}/
│   ├── Nargo.toml
│   ├── Prover.toml
│   └── src/main.nr
└── glue/
    ├── Nargo.toml
    ├── Prover.toml
    └── src/main.nr
```

A recursive workspace instead separates `inner/`, `outer/`, `witnesses/`, and
`proofs/`. The generated `outer/src/expected_segment_vk.nr` exists only in that
workspace. It is never a canonical source file.

Compilation adds `target/` only inside the generated workspace. Canonical
circuit directories never receive witnesses, proofs, keys, or configured
source copies.

## Code layout

- `circuits/` contains the canonical Noir relations.
- `crates/merkle_builder/` constructs the matrix tree and monolithic or
  composite witnesses. Tree, flat, and composite responsibilities are separate
  Rust modules.
- `src/zk_tsp/` contains deterministic instances, caching, workspace creation,
  backend execution, benchmarking, external reconciliation, and recursive
  key-chain verification. Its results layer normalizes component observations
  and composes complete architecture runs before applying summary statistics.
- `results/frozen/` preserves historical observations and calibration evidence;
  `results/derived/` contains the two reproducible recursive thesis inputs.
- The provenance manifests freeze circuit/source identities and the complete
  results chain of custody.
- `tests/` separates unit, equivalence, circuit-correctness, proof-set, and
  benchmark smoke checks.
