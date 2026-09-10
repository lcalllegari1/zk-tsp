# Security model

## Public statement and trust boundary

The Merkle-based relations prove a route against a public Poseidon2 matrix root
and public threshold. In a prepared composite workspace, those intended values
are recorded in `statement.json`. The external verifier rejects a proof set if
the glue proof declares different values.

`statement.json` is not itself an authenticated distribution mechanism. A real
verifier must obtain the intended root, threshold, circuit versions, and
verification keys from a trusted channel. Accepting an entire workspace chosen
by the prover would only prove the prover's chosen statement.

The benchmark uses locally compiled keys for a fixed measured source. The
external verifier applies the `sub_0` segment key to every segment proof and the
glue key to the glue proof. Key publication and authentication remain deployment
responsibilities.

## Why external reconciliation is mandatory

Each of the `K + 1` backend proofs is valid independently. Without equality
checks, a prover could combine segment and glue proofs produced from different
routes or statements. Acceptance therefore requires both backend verification
and reconciliation of all shared public values.

The implementation checks:

- the root in every proof and the root and threshold in the intended statement;
- every segment's start, end, and partial cost against the glue arrays;
- each plain-sort segment's sorted-node summary against the corresponding glue
  chunk;
- each plain-product segment's product, chain input/output, route terminal `c`,
  and challenge `X` against the glue values;
- each committed segment's public commitment against the corresponding glue
  commitment, plus `X` for committed product.

The proof-mixing regression test constructs two complete, independently valid
proof sets, substitutes a valid glue proof from one into the other, confirms
backend verification still succeeds, and confirms external reconciliation
rejects the mixture. Plain variants use rotated routes; committed variants use
the same route with independently sampled blindings, specifically exercising
commitment-set binding.

## Coverage guarantees

Plain sort provides exact coverage in-circuit: each segment proves its sorted
summary and the glue circuit checks that all summaries together sort to
`0..N-1`.

Plain product uses a route-bound grand-product argument. Segments prove
`P_i = ∏(X + node)` and a continuous Poseidon2 fold over the ordered route. The
glue circuit derives `X = Poseidon2(c)` from the terminal fold and checks
`∏P_i = ∏(X + j)` over the intended node set. Conditional on route binding,
the thesis bounds the additional coverage error by `Q(N - 1) / q`, where `q`
is the field size and `Q` counts fresh random-oracle queries, including grinding
over candidate routes. The route binding prevents choosing segment products
independently after seeing `X`. Committed product and recursive product inherit
this coverage guarantee.

All four glue circuits authenticate every boundary edge. Together with the
segments' internal-edge checks, this binds all `N` route edges to the same
matrix root and enforces the threshold.

Committed sort and committed product prove the same respective coverage
relations while replacing the public segment summaries with commitments. A
segment proves knowledge of a valid opening; glue proves that the matching
opening participates in the global relation. The external verifier must still
match every segment `C_i` to the glue array. The Poseidon2 folds are treated as
binding under collision resistance and computationally hiding in the
random-oracle model, with hiding capped by the 128-bit blinding space. Fresh
blindings come from `/dev/urandom`; there is no production deterministic-seed
interface.

## Recursive key chain and hiding

Recursive product makes the segment proofs and their nominally public
nine-field vectors private inputs to one outer proof. The outer relation verifies
each inner proof, binds the endpoint and cost mirrors, and performs the inherited
plain-product recombination checks. The final public surface is exactly
`(root, threshold)`.

The inner verification key and key hash are generated source constants, not
prover witness. The outer verification key therefore identifies both the outer
logic and the embedded inner relation. The final verifier authenticates that
outer key against `build-metadata.json`, checks the intended statement, enforces
the two-field public-input shape and 14,656-byte ZK proof length, and then runs
one backend verification.

When build metadata is loaded from the same workspace as the proof, this is only
a self-consistency check: a prover could replace the outer circuit, key, and
metadata together. The CLI labels that mode `workspace-local`. A deployment
claim requires an independently authenticated metadata file or outer key.

The proof-length guard is intentional. The segment summaries are hidden from
the final verifier only when the outer proof is zero knowledge. It detects the
measured backend's non-ZK proof shape if a future default changes, but it is not
a substitute for authenticating the toolchain or proof system.

## Quantitative evidence boundary

The frozen CSVs are experimental observations, not security evidence and not a
claim about other hardware or toolchains. The recursive pre-repair observations
are retained separately. Their derived thesis views change only the outer gate
and ACIR counts by the calibrated deterministic delta of 113; proving time,
verification time, proof size, and memory remain explicitly historical. New
benchmark runs are written elsewhere and are never merged into that series.

## Disclosure

- Plain sort publicly reveals every segment's sorted node set, endpoints and
  partial cost, with the matrix root and threshold defining the public problem.
  Internal ordering is not directly published, but may be inferred. For a
  three-node segment, its node set and endpoints determine the entire order.
- Plain product removes the sorted node lists but still reveals segment
  endpoints, partial costs, products, chain anchors, `c`, `X`, root, and
  threshold.
- Committed sort reveals each segment commitment and root, while glue also
  reveals the threshold. Committed product additionally reveals `X`, a
  route-derived value against which an observer can test candidate routes.
  The summary values and commitment openings are private witnesses.
- Recursive product exposes only the final root and threshold. The segment
  summaries become private outer witness, while `K` remains identifiable from
  the selected outer circuit and verification key.

Privacy is defined against the final verifier. Workers receiving route segments
or other witness material are outside that guarantee. Prepared workspaces
contain private data and are not verifier-facing proof packages.

## Known limitations

- Poseidon2 domain separation is not added because it is absent from the
  measured thesis circuits.
- The product construction relies on its stated random-oracle/grinding
  assumption.
- Workers are controlled by one logical prover. The experiments do not evaluate
  a networked cluster, malicious workers or witness confidentiality between workers.
- Regression tests check the implementation. They do not establish a formal
  security proof or replace an external audit of the circuits and toolchain.
