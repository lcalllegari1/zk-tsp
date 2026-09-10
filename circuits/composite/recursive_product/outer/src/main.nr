global N: u32 = 8;
global K: u32 = 2;
global DEPTH: u32 = 6;

mod expected_segment_vk;

use poseidon::poseidon2::Poseidon2;
use bb_proof_verification::{UltraHonkZKProof, verify_honk_proof};
use expected_segment_vk::{
    EXPECTED_SEGMENT_DEPTH,
    EXPECTED_SEGMENT_KEY_HASH,
    EXPECTED_SEGMENT_M,
    EXPECTED_SEGMENT_N,
    EXPECTED_SEGMENT_VK,
};

fn main(
    proofs: [UltraHonkZKProof; K],
    sub_pubs: [[Field; 9]; K],
    boundary_costs: [u64; K],
    boundary_siblings: [Field; K * DEPTH],
    boundary_path_bits: [bool; K * DEPTH],
    starts: [u32; K],
    ends: [u32; K],
    partial_costs: [u64; K],
    root: pub Field,
    threshold: pub u64,
) {
    assert(EXPECTED_SEGMENT_N == N, "generated segment key has wrong N");
    assert(EXPECTED_SEGMENT_M * K == N, "generated segment key has wrong M");
    assert(EXPECTED_SEGMENT_DEPTH == DEPTH, "generated segment key has wrong DEPTH");

    for i in 0..K {
        verify_honk_proof(
            EXPECTED_SEGMENT_VK,
            proofs[i],
            sub_pubs[i],
            EXPECTED_SEGMENT_KEY_HASH,
        );
    }

    for i in 0..K {
        assert(starts[i] as Field == sub_pubs[i][0], "start bind");
        assert(ends[i] as Field == sub_pubs[i][1], "end bind");
        assert(partial_costs[i] as Field == sub_pubs[i][2], "pcost bind");
    }

    let c: Field = sub_pubs[0][7];
    let x: Field = sub_pubs[0][8];
    for i in 0..K {
        assert(sub_pubs[i][3] == root, "root mismatch");
        assert(sub_pubs[i][7] == c, "c not shared");
        assert(sub_pubs[i][8] == x, "X not shared");
    }

    assert(sub_pubs[0][5] == 0, "chain must start from 0");
    for i in 0..(K - 1) {
        assert(sub_pubs[i + 1][5] == sub_pubs[i][6], "chain not continuous");
    }
    assert(sub_pubs[K - 1][6] == c, "chain does not terminate at c");
    assert(x == Poseidon2::hash([c], 1), "X != Poseidon2(c)");

    let mut lhs: Field = 1;
    for i in 0..K {
        lhs = lhs * sub_pubs[i][4];
    }
    let mut rhs: Field = 1;
    for j in 0..N {
        rhs = rhs * (x + j as Field);
    }
    assert(lhs == rhs, "grand-product partition mismatch");

    let mut boundary_sum: u64 = 0;
    for i in 0..K {
        let from: u32 = ends[i];
        let to: u32 = starts[(i + 1) % K];
        let expected_idx: u32 = from * N + to;
        let mut recon: u32 = 0;
        let mut pow2: u32 = 1;
        for d in 0..DEPTH {
            if boundary_path_bits[i * DEPTH + d] {
                recon += pow2;
            }
            pow2 *= 2;
        }
        assert(recon == expected_idx, "boundary path bits encode wrong leaf index");

        let mut current: Field = boundary_costs[i] as Field;
        for d in 0..DEPTH {
            let sib: Field = boundary_siblings[i * DEPTH + d];
            let (l, r) = if boundary_path_bits[i * DEPTH + d] {
                (sib, current)
            } else {
                (current, sib)
            };
            current = Poseidon2::hash([l, r], 2);
        }
        assert(current == root, "boundary Merkle proof does not match committed root");
        boundary_sum += boundary_costs[i];
    }

    let mut total: u64 = boundary_sum;
    for i in 0..K {
        total += partial_costs[i];
    }
    assert(total <= threshold, "cycle cost exceeds threshold");
}
