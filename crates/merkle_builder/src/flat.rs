use crate::tree::{atomic_write, booleans, quoted_decimals, quoted_fields, MerkleTree};
use crate::{validate_input, Input};
use acir::{AcirField, FieldElement};
use std::fmt::Write as FmtWrite;
use std::io;
use std::path::Path;

#[derive(Debug)]
pub struct Witness {
    pub cycle: Vec<usize>,
    pub edge_costs: Vec<u64>,
    pub siblings: Vec<FieldElement>,
    pub path_bits: Vec<bool>,
    pub root: FieldElement,
    pub threshold: u64,
}

pub fn build_witness(input: &Input, cache_path: Option<&Path>) -> Result<Witness, String> {
    validate_input(input)?;
    let tree = MerkleTree::load_or_build(&input.flat_matrix, cache_path)?;
    let mut edge_costs = Vec::with_capacity(input.n);
    let mut siblings = Vec::with_capacity(input.n * tree.depth() as usize);
    let mut path_bits = Vec::with_capacity(input.n * tree.depth() as usize);
    for index in 0..input.n {
        let from = input.cycle[index];
        let to = input.cycle[(index + 1) % input.n];
        let leaf_index = from * input.n + to;
        edge_costs.push(input.flat_matrix[leaf_index]);
        let (edge_siblings, edge_bits) = tree.proof(leaf_index)?;
        siblings.extend(edge_siblings);
        path_bits.extend(edge_bits);
    }
    Ok(Witness {
        cycle: input.cycle.clone(),
        edge_costs,
        siblings,
        path_bits,
        root: tree.root(),
        threshold: input.threshold,
    })
}

pub fn write_witness_toml(path: &Path, witness: &Witness) -> io::Result<()> {
    let mut output = String::new();
    writeln!(output, "cycle = [{}]", quoted_decimals(&witness.cycle)).unwrap();
    writeln!(
        output,
        "edge_costs = [{}]",
        quoted_decimals(&witness.edge_costs)
    )
    .unwrap();
    writeln!(output, "siblings = [{}]", quoted_fields(&witness.siblings)).unwrap();
    writeln!(output, "path_bits = [{}]", booleans(&witness.path_bits)).unwrap();
    writeln!(output, "root = \"0x{}\"", witness.root.to_hex()).unwrap();
    writeln!(output, "threshold = \"{}\"", witness.threshold).unwrap();
    atomic_write(path, output.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_inputs_are_rejected_but_duplicates_and_low_thresholds_are_allowed() {
        let duplicate = Input {
            n: 2,
            flat_matrix: vec![0, 1, 1, 0],
            cycle: vec![0, 0],
            threshold: 0,
        };
        assert!(build_witness(&duplicate, None).is_ok());
        let malformed = Input {
            n: duplicate.n,
            flat_matrix: vec![0],
            cycle: duplicate.cycle.clone(),
            threshold: duplicate.threshold,
        };
        assert!(build_witness(&malformed, None).is_err());
        let out_of_range = Input {
            n: 2,
            flat_matrix: vec![0, 1, 1, 0],
            cycle: vec![0, 2],
            threshold: 0,
        };
        assert!(build_witness(&out_of_range, None).is_err());
    }
}
