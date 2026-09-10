global N: u32 = 8;
global DEPTH: u32 = 6;

use poseidon::poseidon2::Poseidon2;

fn main(
    cycle: [u32; N],
    edge_costs: [u64; N],
    siblings: [Field; N * DEPTH],
    path_bits: [bool; N * DEPTH],
    root: pub Field,
    threshold: pub u64,
) {
    let sorted = cycle.sort_via(|a: u32, b: u32| a <= b);
    for i in 0..N {
        assert(sorted[i] == i as u32, "cycle is not a permutation of {0,...,N-1}");
    }

    let mut total_cost: u64 = 0;
    for i in 0..N {
        let from: u32 = cycle[i];
        let to: u32 = cycle[(i + 1) % N];

        let expected_idx: u32 = from * N + to;
        let mut reconstructed_idx: u32 = 0;
        let mut pow2: u32 = 1;
        for d in 0..DEPTH {
            if path_bits[i * DEPTH + d] {
                reconstructed_idx += pow2;
            }
            pow2 *= 2;
        }
        assert(reconstructed_idx == expected_idx, "path bits encode wrong leaf index");

        let mut current: Field = edge_costs[i] as Field;
        for d in 0..DEPTH {
            let sibling: Field = siblings[i * DEPTH + d];
            let (left, right) = if path_bits[i * DEPTH + d] {
                (sibling, current)
            } else {
                (current, sibling)
            };
            current = Poseidon2::hash([left, right], 2);
        }
        assert(current == root, "Merkle proof does not match committed root");

        total_cost += edge_costs[i];
    }

    assert(total_cost <= threshold, "cycle cost exceeds threshold");
}
