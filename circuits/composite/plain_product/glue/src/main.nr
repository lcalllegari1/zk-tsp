global N: u32 = 8;
global K: u32 = 2;
global DEPTH: u32 = 6;

use poseidon::poseidon2::Poseidon2;

fn main(
    boundary_costs: [u64; K],
    boundary_siblings: [Field; K * DEPTH],
    boundary_path_bits: [bool; K * DEPTH],
    starts: pub [u32; K],
    ends: pub [u32; K],
    partial_costs: pub [u64; K],
    threshold: pub u64,
    root: pub Field,
    P_is: pub [Field; K],
    h_ins: pub [Field; K],
    h_outs: pub [Field; K],
    c: pub Field,
    X: pub Field,
) {
    assert(h_ins[0] == 0, "chain must start from 0");
    for i in 0..(K - 1) {
        assert(h_ins[i + 1] == h_outs[i], "chain not continuous");
    }
    assert(h_outs[K - 1] == c, "chain does not terminate at c");

    let x_expected: Field = Poseidon2::hash([c], 1);
    assert(X == x_expected, "X != Poseidon2(c)");

    let mut lhs: Field = 1;
    for i in 0..K {
        lhs = lhs * P_is[i];
    }
    let mut rhs: Field = 1;
    for j in 0..N {
        rhs = rhs * (X + j as Field);
    }
    assert(lhs == rhs, "grand-product partition mismatch");

    let mut boundary_sum: u64 = 0;
    for i in 0..K {
        let from: u32 = ends[i];
        let to: u32 = starts[(i + 1) % K];
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
