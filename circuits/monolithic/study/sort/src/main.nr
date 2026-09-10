// Public-matrix TSP relation with sort-and-shuffle coverage.
// Public: cost_matrix, threshold. Private: cycle.
global N: u32 = 8;

fn main(
    cycle: [u32; N],
    cost_matrix: pub [u64; N * N],
    threshold: pub u64,
) {
    let sorted = cycle.sort_via(|a: u32, b: u32| a <= b);
    for i in 0..N {
        assert(sorted[i] == i as u32, "cycle is not a permutation of {0,...,N-1}");
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
