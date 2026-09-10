global N: u32 = 8;
global M: u32 = 4;
global DEPTH: u32 = 6;

use poseidon::poseidon2::Poseidon2;

fn main(
    cycle_segment: [u32; M],
    edge_costs: [u64; M - 1],
    siblings: [Field; (M - 1) * DEPTH],
    path_bits: [bool; (M - 1) * DEPTH],
    sorted_nodes: pub [u32; M],
    start_node: pub u32,
    end_node: pub u32,
    partial_cost: pub u64,
    root: pub Field,
) {
    for i in 0..M {
        assert(cycle_segment[i] < N, "node index out of range");
    }

    let sorted = cycle_segment.sort_via(|a: u32, b: u32| a <= b);
    for i in 0..M {
        assert(sorted[i] == sorted_nodes[i], "sorted_nodes does not match sorted segment");
    }

    assert(start_node == cycle_segment[0], "start_node mismatch");
    assert(end_node == cycle_segment[M - 1], "end_node mismatch");

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
    assert(sum == partial_cost, "partial_cost does not match sum of internal edge costs");
}
