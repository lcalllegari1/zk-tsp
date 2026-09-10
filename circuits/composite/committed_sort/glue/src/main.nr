global N: u32 = 8;
global K: u32 = 2;
global M: u32 = 4;
global DEPTH: u32 = 6;

use poseidon::poseidon2::Poseidon2;

fn main(
    boundary_costs: [u64; K],
    boundary_siblings: [Field; K * DEPTH],
    boundary_path_bits: [bool; K * DEPTH],
    all_nodes: [u32; N],
    partial_costs: [u64; K],
    r_is: [Field; K],
    root: pub Field,
    threshold: pub u64,
    C_is: pub [Field; K],
) {
    for i in 0..K {
        let mut acc: Field = r_is[i];
        for j in 0..M {
            acc = Poseidon2::hash([acc, all_nodes[i * M + j] as Field], 2);
        }
        acc = Poseidon2::hash([acc, partial_costs[i] as Field], 2);
        assert(acc == C_is[i], "commitment mismatch");
    }

    let sorted = all_nodes.sort_via(|a: u32, b: u32| a <= b);
    for i in 0..N {
        assert(sorted[i] == i as u32, "partition does not cover {0..N-1}");
    }

    let mut boundary_sum: u64 = 0;
    for i in 0..K {
        let from: u32 = all_nodes[i * M + M - 1];
        let to: u32 = all_nodes[((i + 1) % K) * M];
        let expected_idx: u32 = from * N + to;
        let mut reconstructed_idx: u32 = 0;
        let mut pow2: u32 = 1;
        for d in 0..DEPTH {
            if boundary_path_bits[i * DEPTH + d] {
                reconstructed_idx += pow2;
            }
            pow2 *= 2;
        }
        assert(reconstructed_idx == expected_idx, "boundary path bits encode wrong leaf index");

        let mut current: Field = boundary_costs[i] as Field;
        for d in 0..DEPTH {
            let sibling: Field = boundary_siblings[i * DEPTH + d];
            let (left, right) = if boundary_path_bits[i * DEPTH + d] {
                (sibling, current)
            } else {
                (current, sibling)
            };
            current = Poseidon2::hash([left, right], 2);
        }
        assert(current == root, "boundary Merkle proof does not match committed root");
        boundary_sum += boundary_costs[i];
    }

    let mut total: u64 = 0;
    for i in 0..K {
        total += partial_costs[i];
    }
    total += boundary_sum;
    assert(total <= threshold, "cycle cost exceeds threshold");
}
