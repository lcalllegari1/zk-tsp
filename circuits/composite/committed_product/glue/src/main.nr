global N: u32 = 8;
global K: u32 = 2;
global DEPTH: u32 = 6;

use poseidon::poseidon2::Poseidon2;

fn main(
    boundary_costs: [u64; K],
    boundary_siblings: [Field; K * DEPTH],
    boundary_path_bits: [bool; K * DEPTH],
    starts: [u32; K],
    ends: [u32; K],
    partial_costs: [u64; K],
    P_is: [Field; K],
    h_ins: [Field; K],
    h_outs: [Field; K],
    r_is: [Field; K],
    c: Field,
    root: pub Field,
    threshold: pub u64,
    X: pub Field,
    C_is: pub [Field; K],
) {
    for i in 0..K {
        let mut acc: Field = r_is[i];
        acc = Poseidon2::hash([acc, P_is[i]], 2);
        acc = Poseidon2::hash([acc, h_ins[i]], 2);
        acc = Poseidon2::hash([acc, h_outs[i]], 2);
        acc = Poseidon2::hash([acc, starts[i] as Field], 2);
        acc = Poseidon2::hash([acc, ends[i] as Field], 2);
        acc = Poseidon2::hash([acc, partial_costs[i] as Field], 2);
        assert(acc == C_is[i], "commitment mismatch");
    }

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
