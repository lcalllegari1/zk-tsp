// Public-matrix TSP relation with an inverse-permutation witness.
// Public: cost_matrix, threshold. Private: cycle, inv_perm.
global N: u32 = 8;

fn main(
    cycle: [u32; N],
    inv_perm: [u32; N],
    cost_matrix: pub [u64; N * N],
    threshold: pub u64,
) {
    // These two constraints make the externally prepared map a valid inverse.
    for v in 0..N {
        assert(inv_perm[v] < N, "inv_perm entry out of range");
        assert(cycle[inv_perm[v]] == v as u32, "cycle missing node v at claimed position");
    }

    let mut total_cost: u64 = 0;
    for i in 0..N {
        let from: u32 = cycle[i];
        let to:   u32 = cycle[(i + 1) % N];
        let edge_cost: u64 = cost_matrix[from * N + to];
        total_cost += edge_cost;
    }

    assert(total_cost <= threshold, "cycle cost exceeds threshold");
}
