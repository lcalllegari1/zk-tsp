# Reproduction

## Toolchain

The measured environment is Python 3.12, Rust/Cargo 1.94, Nargo
`1.0.0-beta.20` at noirc commit
`b4236c1957d0c26cb65d82adc9e5447b6ff1d629`, and Barretenberg
`5.0.0-nightly.20260324`.

Run these commands from the repository root with the tools above on `PATH`:

```bash
make install BOOTSTRAP_PYTHON=python3.12
source .venv/bin/activate
make check
```

`make check` fails on a different Nargo/noirc or Barretenberg build. Rust is
reported for traceability but is not pinned by that check.

## Acceptance tests

```bash
make test
make smoke
```

`make test` runs Rust tests, Python unit tests, immutable-source equivalence,
Noir adversarial witnesses, Poseidon compatibility, repository cleanliness,
real composite proof-set reconciliation, and recursive key-substitution tests.
`make smoke` exercises every
benchmark family at `N = 8`, including all four external composite variants at
`K = 2` and the recursive-product construction.

## Preparing and proving a composite set

```bash
zk-tsp prepare composite \
  --variant plain-product --nodes 8 --segments 2 --seed 42 \
  --output build/plain-product-n8-k2
```

The preparation command is transactional and refuses a nonempty destination.
It configures copies of the canonical sources and writes all witnesses. To
create a retained proof set manually, run the backend once in each generated
circuit directory:

```bash
prove_one() {
  circuit_dir=$1
  package=$2
  (
    cd "$circuit_dir"
    nargo compile
    bb write_vk -b "target/$package.json" -o target/vk
    nargo execute
    bb prove -b "target/$package.json" -w "target/$package.gz" \
      -k target/vk/vk -o target/proof
  )
}

prove_one build/plain-product-n8-k2/sub_0 composite_plain_product_segment
prove_one build/plain-product-n8-k2/sub_1 composite_plain_product_segment
prove_one build/plain-product-n8-k2/glue composite_plain_product_glue
zk-tsp verify composite --workspace build/plain-product-n8-k2
```

Repeat the segment command for every `sub_i`. For `plain-sort`, use package
names `composite_plain_sort_segment` and `composite_plain_sort_glue`. The
committed package pairs follow the same convention:
`composite_committed_sort_{segment,glue}` and
`composite_committed_product_{segment,glue}`.

`prepare composite` samples a fresh 128-bit operating-system blinding for each
segment of a committed variant. The seed controls the instance and route, not
those commitment openings. Consequently two committed workspaces prepared with
the same arguments are semantically equivalent but do not have byte-identical
witness files. Frozen equivalence checks remove only `r`, `r_is`, `C_i`, and
`C_is`; fixed blindings are available only inside the Rust vector test.

## Composite benchmark

```bash
zk-tsp benchmark composite \
  --variant all \
  --nodes 8 16 \
  --segments 2 \
  --runs 3 \
  --seed 42 \
  --cache-dir data/cache \
  --output build/benchmarks/composite.csv
```

Node and segment arguments form a Cartesian grid. Every cell is validated
before the output file is created. The output path must not already exist.

Each run proves circuits sequentially in isolated subprocesses: `sub_0` through
`sub_{K-1}`, then `glue`. The reported online measurements do not include
instance generation, route solving, tree construction, compilation, or key
generation. `verify_hier_s` measures serial verification of all `K + 1` proofs
plus public-input reconciliation.

For committed variants, witnesses and commitments are regenerated immediately
before each measured run. This refresh occurs outside the reported online
metrics.

The raw CSV columns are exactly:

```text
variant,n,k,m,run,circuit,circuit_size,acir_opcodes,compile_s,witness_s,prove_s,verify_s,proof_bytes,peak_mb,verify_hier_s,xchecks_ok
```

Historical tags are `hier_a_iso` for plain sort, `hier_fs_iso` for plain
product, `hier_c_iso` for committed sort, and `hier_cfs_iso` for committed
product. The benchmark writes one row per circuit, so a cell with `R` runs has
`R(K + 1)` rows.

## Recursive setup, proving, and verification

Recursive setup and online proving are separate because the outer circuit must
be compiled against the configured inner circuit's recursive verification key:

```bash
zk-tsp prepare recursive \
  --nodes 8 --segments 2 --seed 42 \
  --cache-dir data/cache \
  --output build/recursive-n8-k2

zk-tsp prove recursive --workspace build/recursive-n8-k2
zk-tsp verify recursive --workspace build/recursive-n8-k2
```

Preparation is transactional and includes inner/outer compilation and key
generation. It writes `build-metadata.json`, but does not create proofs. Proving
refuses to overwrite an existing completed proof set. It creates the `K` inner
proofs sequentially with target `noir-recursive`, assembles their fields into
the private outer witness, and creates the dependent outer proof.

The default verification command uses the workspace's own build metadata and
reports `workspace-local` trust. This is sufficient for reproduction and
internal consistency, not independent circuit authentication. To select a
trusted build explicitly, use:

```bash
zk-tsp verify recursive \
  --workspace build/recursive-n8-k2 \
  --build-metadata trusted-builds/n8-k2.json
```

The selected file must be obtained independently of the proof package for that
choice to constitute an authenticated outer-key policy.

## Recursive benchmark

```bash
zk-tsp benchmark recursive \
  --nodes 48 96 \
  --segments 2 4 8 \
  --runs 2 \
  --seed 42 \
  --cache-dir data/cache \
  --output build/benchmarks/recursive.csv
```

The benchmark validates the full Cartesian grid before writing. Setup occurs
once per `(N,K)`. Each measured run contains `K` sequential inner witness/prove
tasks followed by the dependent outer witness/prove/verify task. Instance and
route generation, Merkle work, serialization, compilation, key generation, and
outer-witness assembly remain outside online measurements.

The raw recursive columns exactly match the thesis input:

```text
exp,n,k,m,depth,run,role,circuit,gates,acir,compile_s,witness_s,prove_s,verify_s,proof_bytes,peak_mb
```

`exp` is fixed to `2`. Inner rows leave `verify_s` and `proof_bytes` blank; the
outer row contains the final one-proof verification time and 14,656-byte proof.
Deterministic build metadata is written beside the CSV in `<stem>_builds/`.

## Frozen results and architecture aggregation

The repository tracks seven byte-identical non-recursive raw datasets, two
pre-repair recursive raw datasets, and the recursive key-embedding calibration
under `results/frozen/`. The two files under `results/derived/` are the recursive
inputs used by the thesis. They retain the historical timing and memory
observations and change only `gates` and `acir` on outer rows by the calibrated
delta of 113.

Audit the hashes, schemas, benchmark grids, proof-set completeness, calibration,
and exact recursive derivation without writing anything:

```bash
zk-tsp results validate
```

Reproduce the derived views and normalized tables in a new directory:

```bash
zk-tsp results reproduce --output build/reproduced-results
```

The command is transactional and refuses a nonempty destination. It writes
`components.csv` with one row per measured circuit task, `architectures.csv`
with one row per complete matched run, and `summaries.csv` with the thesis
statistics. All decimal arithmetic is exact until later presentation formatting.

For every complete run, external sequential time sums all segment and glue
online tasks, while its distributed projection is their maximum. Recursive
sequential time sums all inner and outer tasks; its distributed projection is
the maximum inner task followed by the dependent outer task. Architectural peak
memory is the maximum component peak within the run. Timed central values are
the minimum of complete run-level values, and memory is the median of complete
run-level maxima. External backend verification sums the `K + 1` backend calls
but excludes the application reconciliation time.

The results manifest in `provenance/results-manifest.json` records every file's
role, origin, schema, row count, and SHA-256. Keep new benchmarks separate from
the frozen historical series. The examples write generated files under `build/`.

The results-custody test currently treats every CSV under `results/` as frozen
evidence, including files in `results/generated/`. Use `build/` for generated
outputs when running `make test`.

These commands reproduce CSV data and aggregate tables. Figure generation and
complete validation of the tables printed in the thesis are not included.

## Cache and generated files

The shared cache key is `(N, seed)`. It stores the canonical instance, route,
cost, threshold, and validated binary Merkle tree. A digest, shape, or policy
mismatch causes reconstruction. `data/cache`, `build`, prepared workspaces,
proofs, keys, targets, newly generated benchmark CSVs, and reproduced aggregate
tables are ignored artifacts. The explicitly catalogued files under
`results/frozen/` and `results/derived/` are repository evidence and are tracked.
