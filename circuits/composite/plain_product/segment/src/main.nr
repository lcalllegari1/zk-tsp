global N: u32 = 8;
global M: u32 = 4;
global DEPTH: u32 = 6;

use poseidon::poseidon2::Poseidon2;

fn main(
    cycle_segment: [u32; M],
    edge_costs: [u64; M - 1],
    siblings: [Field; (M - 1) * DEPTH],
    path_bits: [bool; (M - 1) * DEPTH],
    start_node: pub u32,
    end_node: pub u32,
    partial_cost: pub u64,
    root: pub Field,
    P_i: pub Field,
    h_in_i: pub Field,
    h_out_i: pub Field,
    c: pub Field,
    X: pub Field,
) {
    for i in 0..M {
        assert(cycle_segment[i] < N, "node index out of range");
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

    let mut h: Field = h_in_i;
    for j in 0..M {
        h = Poseidon2::hash([h, cycle_segment[j] as Field], 2);
    }
    assert(h == h_out_i, "chain link mismatch");

    let mut prod: Field = 1;
    for j in 0..M {
        prod = prod * (X + cycle_segment[j] as Field);
    }
    assert(prod == P_i, "P_i mismatch");

    let x_expected: Field = Poseidon2::hash([c], 1);
    assert(X == x_expected, "X != Poseidon2(c)");
}
