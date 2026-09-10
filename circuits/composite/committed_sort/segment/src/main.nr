global N: u32 = 8;
global M: u32 = 4;
global DEPTH: u32 = 6;

use poseidon::poseidon2::Poseidon2;

fn main(
    cycle_segment: [u32; M],
    edge_costs: [u64; M - 1],
    siblings: [Field; (M - 1) * DEPTH],
    path_bits: [bool; (M - 1) * DEPTH],
    r: Field,
    root: pub Field,
    C_i: pub Field,
) {
    for i in 0..M {
        assert(cycle_segment[i] < N, "node index out of range");
    }

    let mut sum: u64 = 0;
    for i in 0..(M - 1) {
        let from: u32 = cycle_segment[i];
        let to: u32 = cycle_segment[i + 1];
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
        sum += edge_costs[i];
    }
    let partial_cost: u64 = sum;

    let mut acc: Field = r;
    for j in 0..M {
        acc = Poseidon2::hash([acc, cycle_segment[j] as Field], 2);
    }
    acc = Poseidon2::hash([acc, partial_cost as Field], 2);
    assert(acc == C_i, "commitment mismatch");
}
