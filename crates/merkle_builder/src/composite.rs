use crate::tree::{
    atomic_write, booleans, poseidon2_compress, poseidon2_hash_single, quoted_decimals,
    quoted_fields, MerkleTree,
};
use crate::{validate_input, Input};
use acir::{AcirField, FieldElement};
use serde::Serialize;
use std::fmt::Write as FmtWrite;
use std::io::Read;
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompositeVariant {
    PlainSort,
    PlainProduct,
    CommittedSort,
    CommittedProduct,
}

impl CompositeVariant {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "plain-sort" => Ok(Self::PlainSort),
            "plain-product" => Ok(Self::PlainProduct),
            "committed-sort" => Ok(Self::CommittedSort),
            "committed-product" => Ok(Self::CommittedProduct),
            _ => Err(format!("unknown composite variant: {value}")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PlainSort => "plain-sort",
            Self::PlainProduct => "plain-product",
            Self::CommittedSort => "committed-sort",
            Self::CommittedProduct => "committed-product",
        }
    }

    fn is_product(self) -> bool {
        matches!(self, Self::PlainProduct | Self::CommittedProduct)
    }

    fn is_committed(self) -> bool {
        matches!(self, Self::CommittedSort | Self::CommittedProduct)
    }
}

#[derive(Debug, Serialize)]
pub struct CompositeSummary {
    pub variant: &'static str,
    pub n: usize,
    pub k: usize,
    pub m: usize,
    pub depth: u32,
    pub root: String,
    pub threshold: u64,
}

struct SegmentWitness {
    cycle: Vec<usize>,
    edge_costs: Vec<u64>,
    siblings: Vec<FieldElement>,
    path_bits: Vec<bool>,
    sorted_nodes: Vec<usize>,
    start: usize,
    end: usize,
    partial_cost: u64,
    product: FieldElement,
    h_in: FieldElement,
    h_out: FieldElement,
    blinding: FieldElement,
    commitment: FieldElement,
}

struct GlueWitness {
    boundary_costs: Vec<u64>,
    siblings: Vec<FieldElement>,
    path_bits: Vec<bool>,
}

pub fn write_composite(
    input: &Input,
    variant: CompositeVariant,
    k: usize,
    output: &Path,
    cache_path: Option<&Path>,
) -> Result<CompositeSummary, String> {
    let mut random_blinding = os_random_blinding;
    write_composite_with_blinding_source(
        input,
        variant,
        k,
        output,
        cache_path,
        &mut random_blinding,
    )
}

fn write_composite_with_blinding_source<F>(
    input: &Input,
    variant: CompositeVariant,
    k: usize,
    output: &Path,
    cache_path: Option<&Path>,
    blinding_source: &mut F,
) -> Result<CompositeSummary, String>
where
    F: FnMut() -> Result<FieldElement, String>,
{
    validate_input(input)?;
    if k < 2 {
        return Err("composite circuits require at least 2 segments".into());
    }
    if input.n % k != 0 {
        return Err(format!(
            "nodes {} must be divisible by segments {k}",
            input.n
        ));
    }
    let m = input.n / k;
    if m <= 2 {
        return Err(format!("segment length must exceed 2, got {m}"));
    }

    let tree = MerkleTree::load_or_build(&input.flat_matrix, cache_path)?;
    let mut chain = vec![FieldElement::zero(); input.n + 1];
    if variant.is_product() {
        for index in 0..input.n {
            chain[index + 1] =
                poseidon2_compress(chain[index], FieldElement::from(input.cycle[index] as u128));
        }
    }
    let terminal = chain[input.n];
    let challenge = poseidon2_hash_single(terminal);

    let mut segments = Vec::with_capacity(k);
    for segment_index in 0..k {
        let begin = segment_index * m;
        let cycle = input.cycle[begin..begin + m].to_vec();
        let mut edge_costs = Vec::with_capacity(m - 1);
        let mut siblings = Vec::with_capacity((m - 1) * tree.depth() as usize);
        let mut path_bits = Vec::with_capacity((m - 1) * tree.depth() as usize);
        for index in 0..m - 1 {
            let leaf_index = cycle[index] * input.n + cycle[index + 1];
            edge_costs.push(input.flat_matrix[leaf_index]);
            let (proof_siblings, proof_bits) = tree.proof(leaf_index)?;
            siblings.extend(proof_siblings);
            path_bits.extend(proof_bits);
        }
        let partial_cost = checked_sum(&edge_costs)?;
        let mut sorted_nodes = cycle.clone();
        sorted_nodes.sort_unstable();
        let mut product = FieldElement::one();
        if variant.is_product() {
            for node in &cycle {
                product = product * (challenge + FieldElement::from(*node as u128));
            }
        }
        let start = cycle[0];
        let end = cycle[m - 1];
        let h_in = chain[begin];
        let h_out = chain[begin + m];
        let blinding = if variant.is_committed() {
            blinding_source()?
        } else {
            FieldElement::zero()
        };
        let commitment = match variant {
            CompositeVariant::CommittedSort => {
                let mut values = cycle
                    .iter()
                    .map(|node| FieldElement::from(*node as u128))
                    .collect::<Vec<_>>();
                values.push(FieldElement::from(partial_cost as u128));
                commit_fold(blinding, &values)
            }
            CompositeVariant::CommittedProduct => commit_fold(
                blinding,
                &[
                    product,
                    h_in,
                    h_out,
                    FieldElement::from(start as u128),
                    FieldElement::from(end as u128),
                    FieldElement::from(partial_cost as u128),
                ],
            ),
            _ => FieldElement::zero(),
        };
        segments.push(SegmentWitness {
            cycle,
            edge_costs,
            siblings,
            path_bits,
            sorted_nodes,
            start,
            end,
            partial_cost,
            product,
            h_in,
            h_out,
            blinding,
            commitment,
        });
    }

    let mut boundary_costs = Vec::with_capacity(k);
    let mut boundary_siblings = Vec::with_capacity(k * tree.depth() as usize);
    let mut boundary_path_bits = Vec::with_capacity(k * tree.depth() as usize);
    for index in 0..k {
        let leaf_index = segments[index].end * input.n + segments[(index + 1) % k].start;
        boundary_costs.push(input.flat_matrix[leaf_index]);
        let (proof_siblings, proof_bits) = tree.proof(leaf_index)?;
        boundary_siblings.extend(proof_siblings);
        boundary_path_bits.extend(proof_bits);
    }
    let glue = GlueWitness {
        boundary_costs,
        siblings: boundary_siblings,
        path_bits: boundary_path_bits,
    };

    for (index, segment) in segments.iter().enumerate() {
        let path = output.join(format!("sub_{index}/Prover.toml"));
        match variant {
            CompositeVariant::PlainSort => write_plain_sort_segment(&path, segment, tree.root())?,
            CompositeVariant::PlainProduct => {
                write_plain_product_segment(&path, segment, tree.root(), terminal, challenge)?
            }
            CompositeVariant::CommittedSort => {
                write_committed_sort_segment(&path, segment, tree.root())?
            }
            CompositeVariant::CommittedProduct => {
                write_committed_product_segment(&path, segment, tree.root(), challenge)?
            }
        }
    }
    let glue_path = output.join("glue/Prover.toml");
    match variant {
        CompositeVariant::PlainSort => {
            write_plain_sort_glue(&glue_path, &segments, &glue, input.threshold, tree.root())?
        }
        CompositeVariant::PlainProduct => write_plain_product_glue(
            &glue_path,
            &segments,
            &glue,
            input.threshold,
            tree.root(),
            terminal,
            challenge,
        )?,
        CompositeVariant::CommittedSort => {
            write_committed_sort_glue(&glue_path, &segments, &glue, input.threshold, tree.root())?
        }
        CompositeVariant::CommittedProduct => write_committed_product_glue(
            &glue_path,
            &segments,
            &glue,
            input.threshold,
            tree.root(),
            terminal,
            challenge,
        )?,
    }

    Ok(CompositeSummary {
        variant: variant.as_str(),
        n: input.n,
        k,
        m,
        depth: tree.depth(),
        root: format!("0x{}", tree.root().to_hex()),
        threshold: input.threshold,
    })
}

fn checked_sum(values: &[u64]) -> Result<u64, String> {
    values
        .iter()
        .try_fold(0u64, |sum, value| sum.checked_add(*value))
        .ok_or_else(|| "edge cost sum exceeds u64".into())
}

fn commit_fold(blinding: FieldElement, values: &[FieldElement]) -> FieldElement {
    values.iter().copied().fold(blinding, poseidon2_compress)
}

fn os_random_blinding() -> Result<FieldElement, String> {
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(|error| format!("cannot read 128-bit segment blinding: {error}"))?;
    Ok(FieldElement::from(u128::from_le_bytes(bytes)))
}

fn write_common_segment(output: &mut String, segment: &SegmentWitness) {
    writeln!(
        output,
        "cycle_segment = [{}]",
        quoted_decimals(&segment.cycle)
    )
    .unwrap();
    writeln!(
        output,
        "edge_costs = [{}]",
        quoted_decimals(&segment.edge_costs)
    )
    .unwrap();
    writeln!(output, "siblings = [{}]", quoted_fields(&segment.siblings)).unwrap();
    writeln!(output, "path_bits = [{}]", booleans(&segment.path_bits)).unwrap();
}

fn write_plain_sort_segment(
    path: &Path,
    segment: &SegmentWitness,
    root: FieldElement,
) -> Result<(), String> {
    let mut output = String::new();
    write_common_segment(&mut output, segment);
    writeln!(
        output,
        "sorted_nodes = [{}]",
        quoted_decimals(&segment.sorted_nodes)
    )
    .unwrap();
    writeln!(output, "start_node = \"{}\"", segment.start).unwrap();
    writeln!(output, "end_node = \"{}\"", segment.end).unwrap();
    writeln!(output, "partial_cost = \"{}\"", segment.partial_cost).unwrap();
    writeln!(output, "root = \"0x{}\"", root.to_hex()).unwrap();
    write_output(path, output)
}

fn write_plain_product_segment(
    path: &Path,
    segment: &SegmentWitness,
    root: FieldElement,
    terminal: FieldElement,
    challenge: FieldElement,
) -> Result<(), String> {
    let mut output = String::new();
    write_common_segment(&mut output, segment);
    writeln!(output, "start_node = \"{}\"", segment.start).unwrap();
    writeln!(output, "end_node = \"{}\"", segment.end).unwrap();
    writeln!(output, "partial_cost = \"{}\"", segment.partial_cost).unwrap();
    writeln!(output, "root = \"0x{}\"", root.to_hex()).unwrap();
    writeln!(output, "P_i = \"0x{}\"", segment.product.to_hex()).unwrap();
    writeln!(output, "h_in_i = \"0x{}\"", segment.h_in.to_hex()).unwrap();
    writeln!(output, "h_out_i = \"0x{}\"", segment.h_out.to_hex()).unwrap();
    writeln!(output, "c = \"0x{}\"", terminal.to_hex()).unwrap();
    writeln!(output, "X = \"0x{}\"", challenge.to_hex()).unwrap();
    write_output(path, output)
}

fn write_committed_sort_segment(
    path: &Path,
    segment: &SegmentWitness,
    root: FieldElement,
) -> Result<(), String> {
    let mut output = String::new();
    write_common_segment(&mut output, segment);
    writeln!(output, "r = \"0x{}\"", segment.blinding.to_hex()).unwrap();
    writeln!(output, "root = \"0x{}\"", root.to_hex()).unwrap();
    writeln!(output, "C_i = \"0x{}\"", segment.commitment.to_hex()).unwrap();
    write_output(path, output)
}

fn write_committed_product_segment(
    path: &Path,
    segment: &SegmentWitness,
    root: FieldElement,
    challenge: FieldElement,
) -> Result<(), String> {
    let mut output = String::new();
    write_common_segment(&mut output, segment);
    writeln!(output, "h_in_i = \"0x{}\"", segment.h_in.to_hex()).unwrap();
    writeln!(output, "r = \"0x{}\"", segment.blinding.to_hex()).unwrap();
    writeln!(output, "root = \"0x{}\"", root.to_hex()).unwrap();
    writeln!(output, "X = \"0x{}\"", challenge.to_hex()).unwrap();
    writeln!(output, "C_i = \"0x{}\"", segment.commitment.to_hex()).unwrap();
    write_output(path, output)
}

fn write_common_glue(output: &mut String, glue: &GlueWitness) {
    writeln!(
        output,
        "boundary_costs = [{}]",
        quoted_decimals(&glue.boundary_costs)
    )
    .unwrap();
    writeln!(
        output,
        "boundary_siblings = [{}]",
        quoted_fields(&glue.siblings)
    )
    .unwrap();
    writeln!(
        output,
        "boundary_path_bits = [{}]",
        booleans(&glue.path_bits)
    )
    .unwrap();
}

fn write_plain_sort_glue(
    path: &Path,
    segments: &[SegmentWitness],
    glue: &GlueWitness,
    threshold: u64,
    root: FieldElement,
) -> Result<(), String> {
    let mut output = String::new();
    write_common_glue(&mut output, glue);
    let all_sorted = segments
        .iter()
        .flat_map(|segment| segment.sorted_nodes.iter().copied())
        .collect::<Vec<_>>();
    write_summary_arrays(&mut output, segments, Some(&all_sorted));
    writeln!(output, "threshold = \"{threshold}\"").unwrap();
    writeln!(output, "root = \"0x{}\"", root.to_hex()).unwrap();
    write_output(path, output)
}

fn write_plain_product_glue(
    path: &Path,
    segments: &[SegmentWitness],
    glue: &GlueWitness,
    threshold: u64,
    root: FieldElement,
    terminal: FieldElement,
    challenge: FieldElement,
) -> Result<(), String> {
    let mut output = String::new();
    write_common_glue(&mut output, glue);
    write_summary_arrays(&mut output, segments, None);
    writeln!(output, "threshold = \"{threshold}\"").unwrap();
    writeln!(output, "root = \"0x{}\"", root.to_hex()).unwrap();
    write_product_arrays(&mut output, segments);
    writeln!(output, "c = \"0x{}\"", terminal.to_hex()).unwrap();
    writeln!(output, "X = \"0x{}\"", challenge.to_hex()).unwrap();
    write_output(path, output)
}

fn write_committed_sort_glue(
    path: &Path,
    segments: &[SegmentWitness],
    glue: &GlueWitness,
    threshold: u64,
    root: FieldElement,
) -> Result<(), String> {
    let mut output = String::new();
    write_common_glue(&mut output, glue);
    let all_nodes = segments
        .iter()
        .flat_map(|segment| segment.cycle.iter().copied())
        .collect::<Vec<_>>();
    writeln!(output, "all_nodes = [{}]", quoted_decimals(&all_nodes)).unwrap();
    write_partial_costs(&mut output, segments);
    write_blindings(&mut output, segments);
    writeln!(output, "root = \"0x{}\"", root.to_hex()).unwrap();
    writeln!(output, "threshold = \"{threshold}\"").unwrap();
    write_commitments(&mut output, segments);
    write_output(path, output)
}

fn write_committed_product_glue(
    path: &Path,
    segments: &[SegmentWitness],
    glue: &GlueWitness,
    threshold: u64,
    root: FieldElement,
    terminal: FieldElement,
    challenge: FieldElement,
) -> Result<(), String> {
    let mut output = String::new();
    write_common_glue(&mut output, glue);
    write_summary_arrays(&mut output, segments, None);
    write_product_arrays(&mut output, segments);
    write_blindings(&mut output, segments);
    writeln!(output, "c = \"0x{}\"", terminal.to_hex()).unwrap();
    writeln!(output, "root = \"0x{}\"", root.to_hex()).unwrap();
    writeln!(output, "threshold = \"{threshold}\"").unwrap();
    writeln!(output, "X = \"0x{}\"", challenge.to_hex()).unwrap();
    write_commitments(&mut output, segments);
    write_output(path, output)
}

fn write_summary_arrays(
    output: &mut String,
    segments: &[SegmentWitness],
    all_sorted: Option<&[usize]>,
) {
    if let Some(values) = all_sorted {
        writeln!(output, "all_sorted_nodes = [{}]", quoted_decimals(values)).unwrap();
    }
    let starts = segments
        .iter()
        .map(|segment| segment.start)
        .collect::<Vec<_>>();
    let ends = segments
        .iter()
        .map(|segment| segment.end)
        .collect::<Vec<_>>();
    writeln!(output, "starts = [{}]", quoted_decimals(&starts)).unwrap();
    writeln!(output, "ends = [{}]", quoted_decimals(&ends)).unwrap();
    write_partial_costs(output, segments);
}

fn write_partial_costs(output: &mut String, segments: &[SegmentWitness]) {
    let partial_costs = segments
        .iter()
        .map(|segment| segment.partial_cost)
        .collect::<Vec<_>>();
    writeln!(
        output,
        "partial_costs = [{}]",
        quoted_decimals(&partial_costs)
    )
    .unwrap();
}

fn write_product_arrays(output: &mut String, segments: &[SegmentWitness]) {
    let products = segments
        .iter()
        .map(|segment| segment.product)
        .collect::<Vec<_>>();
    let h_ins = segments
        .iter()
        .map(|segment| segment.h_in)
        .collect::<Vec<_>>();
    let h_outs = segments
        .iter()
        .map(|segment| segment.h_out)
        .collect::<Vec<_>>();
    writeln!(output, "P_is = [{}]", quoted_fields(&products)).unwrap();
    writeln!(output, "h_ins = [{}]", quoted_fields(&h_ins)).unwrap();
    writeln!(output, "h_outs = [{}]", quoted_fields(&h_outs)).unwrap();
}

fn write_blindings(output: &mut String, segments: &[SegmentWitness]) {
    let blindings = segments
        .iter()
        .map(|segment| segment.blinding)
        .collect::<Vec<_>>();
    writeln!(output, "r_is = [{}]", quoted_fields(&blindings)).unwrap();
}

fn write_commitments(output: &mut String, segments: &[SegmentWitness]) {
    let commitments = segments
        .iter()
        .map(|segment| segment.commitment)
        .collect::<Vec<_>>();
    writeln!(output, "C_is = [{}]", quoted_fields(&commitments)).unwrap();
}

fn write_output(path: &Path, output: String) -> Result<(), String> {
    atomic_write(path, output.as_bytes())
        .map_err(|error| format!("cannot write {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture(n: usize) -> Input {
        let flat_matrix = (0..n)
            .flat_map(|row| {
                (0..n).map(move |column| {
                    if row == column {
                        0
                    } else {
                        (row * n + column) as u64
                    }
                })
            })
            .collect();
        Input {
            n,
            flat_matrix,
            cycle: (0..n).collect(),
            threshold: u64::MAX,
        }
    }

    fn temporary_root() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "zk-tsp-composite-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn geometry_is_validated() {
        let input = fixture(8);
        let root = std::env::temp_dir();
        for variant in [
            CompositeVariant::PlainSort,
            CompositeVariant::CommittedProduct,
        ] {
            assert!(write_composite(&input, variant, 1, &root, None).is_err());
            assert!(write_composite(&input, variant, 3, &root, None).is_err());
            assert!(write_composite(&input, variant, 4, &root, None).is_err());
        }
    }

    #[test]
    fn all_variants_write_complete_comment_free_sets() {
        let root = temporary_root();
        for variant in [
            CompositeVariant::PlainSort,
            CompositeVariant::PlainProduct,
            CompositeVariant::CommittedSort,
            CompositeVariant::CommittedProduct,
        ] {
            let output = root.join(variant.as_str());
            let mut next = 1u128;
            let mut fixed = || {
                let value = FieldElement::from(next);
                next += 1;
                Ok(value)
            };
            let summary = write_composite_with_blinding_source(
                &fixture(8),
                variant,
                2,
                &output,
                None,
                &mut fixed,
            )
            .unwrap();
            assert_eq!(summary.m, 4);
            for relative in ["sub_0/Prover.toml", "sub_1/Prover.toml", "glue/Prover.toml"] {
                let text = std::fs::read_to_string(output.join(relative)).unwrap();
                assert!(!text.contains('#'));
            }
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn commitment_fold_matches_frozen_legacy_vectors() {
        let sort_blinding = FieldElement::from_hex(
            "00000000000000000000000000000000bce9a2f865f6b848be96284873a5b7d7",
        )
        .unwrap();
        let sort_values = [0u128, 5, 3, 2, 1_181_680].map(FieldElement::from);
        assert_eq!(
            commit_fold(sort_blinding, &sort_values).to_hex(),
            "030501be99000968b71ab05b36e079c3cef0baecb1850e2294546cfda59e0993"
        );

        let product_blinding = FieldElement::from_hex(
            "00000000000000000000000000000000441268fb622941e282b1305135d36ffe",
        )
        .unwrap();
        let product_values = [
            "2b587013a3e3935d037b692b48d640695eadb8f5f03b933110b96053dee42216",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "249b4bd9b262e23c79d1aa87fa77ea200b5622cef472355bb916564bfe320736",
            "0",
            "2",
            "1207f0",
        ]
        .map(|value| FieldElement::from_hex(value).unwrap());
        assert_eq!(
            commit_fold(product_blinding, &product_values).to_hex(),
            "2832a34e48688b31dacf780c184dcff198ee3aee7975e24a9274c2c9f2bfe6c4"
        );
    }

    #[test]
    fn production_committed_sets_use_fresh_blindings() {
        let root = temporary_root();
        let first = root.join("first");
        let second = root.join("second");
        write_composite(
            &fixture(8),
            CompositeVariant::CommittedSort,
            2,
            &first,
            None,
        )
        .unwrap();
        write_composite(
            &fixture(8),
            CompositeVariant::CommittedSort,
            2,
            &second,
            None,
        )
        .unwrap();
        let read_blinding = |path: &Path| {
            std::fs::read_to_string(path)
                .unwrap()
                .lines()
                .find(|line| line.starts_with("r = "))
                .unwrap()
                .to_owned()
        };
        assert_ne!(
            read_blinding(&first.join("sub_0/Prover.toml")),
            read_blinding(&second.join("sub_0/Prover.toml"))
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
