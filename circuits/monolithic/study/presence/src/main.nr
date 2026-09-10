// Public-matrix TSP relation with an indicator-vector coverage check.
// Public: cost_matrix, threshold. Private: cycle.
global N: u32 = 8;

fn main(
    cycle: [u32; N],
    cost_matrix: pub [u64; N * N],
    threshold: pub u64,
) {
    for i in 0..N {
        assert(cycle[i] < N, "node index out of range");
    }

    let mut seen: [bool; N] = [false; N];
    for i in 0..N {
        assert(seen[cycle[i]] == false, "duplicate node in cycle");
        seen[cycle[i]] = true;
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
