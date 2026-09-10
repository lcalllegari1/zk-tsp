mod composite;
mod flat;
mod tree;

use serde::Deserialize;

pub use composite::{write_composite, CompositeSummary, CompositeVariant};
pub use flat::{build_witness, write_witness_toml, Witness};
pub use tree::{poseidon2_compress, poseidon2_hash_single, MerkleTree};

#[derive(Debug, Deserialize)]
pub struct Input {
    pub n: usize,
    pub flat_matrix: Vec<u64>,
    pub cycle: Vec<usize>,
    pub threshold: u64,
}

pub(crate) fn validate_input(input: &Input) -> Result<(), String> {
    if input.n == 0 {
        return Err("n must be at least 1".into());
    }
    let expected = input.n.checked_mul(input.n).ok_or("n*n overflow")?;
    if input.flat_matrix.len() != expected {
        return Err(format!(
            "flat_matrix length {} does not equal n*n={expected}",
            input.flat_matrix.len()
        ));
    }
    if input.cycle.len() != input.n {
        return Err(format!(
            "cycle length {} does not equal n={}",
            input.cycle.len(),
            input.n
        ));
    }
    if let Some((index, value)) = input
        .cycle
        .iter()
        .copied()
        .enumerate()
        .find(|(_, value)| *value >= input.n)
    {
        return Err(format!(
            "cycle[{index}]={value} is outside [0, {})",
            input.n
        ));
    }
    Ok(())
}
