use acir::{AcirField, FieldElement};
use bn254_blackbox_solver::poseidon2_permutation;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const CACHE_MAGIC: &[u8; 4] = b"MTC1";
const CACHE_VERSION: u32 = 1;
const FIELD_BYTES: usize = 32;
const CACHE_HEADER_BYTES: usize = 36;

pub fn poseidon2_compress(left: FieldElement, right: FieldElement) -> FieldElement {
    let iv = FieldElement::from(2u128 * (1u128 << 64));
    let state = vec![left, right, FieldElement::zero(), iv];
    poseidon2_permutation(&state).expect("Poseidon2 permutation failed")[0]
}

pub fn poseidon2_hash_single(value: FieldElement) -> FieldElement {
    let iv = FieldElement::from(1u128 << 64);
    let state = vec![value, FieldElement::zero(), FieldElement::zero(), iv];
    poseidon2_permutation(&state).expect("Poseidon2 permutation failed")[0]
}

#[derive(Debug)]
pub struct MerkleTree {
    nodes: Vec<FieldElement>,
    n_padded: usize,
    depth: u32,
}

impl MerkleTree {
    pub fn build(leaves: &[u64]) -> Result<Self, String> {
        if leaves.is_empty() {
            return Err("the Merkle tree requires at least one leaf".into());
        }
        let n_padded = leaves
            .len()
            .checked_next_power_of_two()
            .ok_or("leaf count is too large")?;
        let node_count = n_padded.checked_mul(2).ok_or("tree size overflow")?;
        let depth = n_padded.trailing_zeros();
        let mut nodes = vec![FieldElement::zero(); node_count];
        for (index, value) in leaves.iter().copied().enumerate() {
            nodes[n_padded + index] = FieldElement::from(value as u128);
        }
        for index in (1..n_padded).rev() {
            nodes[index] = poseidon2_compress(nodes[2 * index], nodes[2 * index + 1]);
        }
        Ok(Self {
            nodes,
            n_padded,
            depth,
        })
    }

    pub fn load_or_build(leaves: &[u64], cache_path: Option<&Path>) -> Result<Self, String> {
        let checksum = matrix_checksum(leaves);
        if let Some(path) = cache_path {
            if let Some(cached) = Self::load(path, leaves.len(), checksum) {
                return Ok(cached);
            }
            let built = Self::build(leaves)?;
            built
                .save(path, leaves.len(), checksum)
                .map_err(|error| format!("cannot write tree cache {}: {error}", path.display()))?;
            Ok(built)
        } else {
            Self::build(leaves)
        }
    }

    pub fn root(&self) -> FieldElement {
        self.nodes[1]
    }

    pub fn depth(&self) -> u32 {
        self.depth
    }

    pub fn proof(&self, leaf_index: usize) -> Result<(Vec<FieldElement>, Vec<bool>), String> {
        if leaf_index >= self.n_padded {
            return Err(format!(
                "leaf index {leaf_index} is outside the padded tree"
            ));
        }
        let mut siblings = Vec::with_capacity(self.depth as usize);
        let mut path_bits = Vec::with_capacity(self.depth as usize);
        let mut position = self.n_padded + leaf_index;
        while position > 1 {
            let is_right = position % 2 == 1;
            siblings.push(self.nodes[position ^ 1]);
            path_bits.push(is_right);
            position /= 2;
        }
        Ok((siblings, path_bits))
    }

    fn save(&self, path: &Path, leaf_count: usize, checksum: u64) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temporary = temporary_sibling(path);
        let result = (|| {
            let file = std::fs::File::create(&temporary)?;
            let mut writer = io::BufWriter::new(file);
            writer.write_all(CACHE_MAGIC)?;
            writer.write_all(&CACHE_VERSION.to_le_bytes())?;
            writer.write_all(&(leaf_count as u64).to_le_bytes())?;
            writer.write_all(&(self.n_padded as u64).to_le_bytes())?;
            writer.write_all(&self.depth.to_le_bytes())?;
            writer.write_all(&checksum.to_le_bytes())?;
            for node in &self.nodes {
                writer.write_all(&node.to_be_bytes())?;
            }
            writer.flush()?;
            std::fs::rename(&temporary, path)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }

    fn load(path: &Path, leaf_count: usize, checksum: u64) -> Option<Self> {
        let bytes = std::fs::read(path).ok()?;
        if bytes.len() < CACHE_HEADER_BYTES || &bytes[0..4] != CACHE_MAGIC {
            return None;
        }
        let read_u32 = |offset: usize| {
            u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?).into()
        };
        let read_u64 = |offset: usize| {
            u64::from_le_bytes(bytes.get(offset..offset + 8)?.try_into().ok()?).into()
        };
        let version: Option<u32> = read_u32(4);
        let stored_leaves: Option<u64> = read_u64(8);
        let stored_padded: Option<u64> = read_u64(16);
        let stored_depth: Option<u32> = read_u32(24);
        let stored_checksum: Option<u64> = read_u64(28);
        if version? != CACHE_VERSION
            || stored_leaves? != leaf_count as u64
            || stored_checksum? != checksum
        {
            return None;
        }
        let n_padded = usize::try_from(stored_padded?).ok()?;
        let depth = stored_depth?;
        if !n_padded.is_power_of_two()
            || leaf_count > n_padded
            || depth != n_padded.trailing_zeros()
        {
            return None;
        }
        let node_count = n_padded.checked_mul(2)?;
        let body_bytes = node_count.checked_mul(FIELD_BYTES)?;
        if bytes.len() != CACHE_HEADER_BYTES.checked_add(body_bytes)? {
            return None;
        }
        let mut nodes = Vec::with_capacity(node_count);
        for chunk in bytes[CACHE_HEADER_BYTES..].chunks_exact(FIELD_BYTES) {
            nodes.push(FieldElement::from_be_bytes_reduce(chunk));
        }
        Some(Self {
            nodes,
            n_padded,
            depth,
        })
    }
}

pub(crate) fn quoted_decimals<T: std::fmt::Display>(values: &[T]) -> String {
    values
        .iter()
        .map(|value| format!("\"{value}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(crate) fn quoted_fields(values: &[FieldElement]) -> String {
    values
        .iter()
        .map(|value| format!("\"0x{}\"", value.to_hex()))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(crate) fn booleans(values: &[bool]) -> String {
    values
        .iter()
        .map(|value| if *value { "true" } else { "false" })
        .collect::<Vec<_>>()
        .join(", ")
}

fn matrix_checksum(values: &[u64]) -> u64 {
    let mut checksum = 0xcbf29ce484222325u64;
    for value in values {
        for byte in value.to_le_bytes() {
            checksum ^= byte as u64;
            checksum = checksum.wrapping_mul(0x100000001b3);
        }
    }
    checksum
}

fn temporary_sibling(path: &Path) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("output");
    path.with_file_name(format!(".{name}.{}.{}.tmp", std::process::id(), nonce))
}

pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = temporary_sibling(path);
    let result = (|| {
        std::fs::write(&temporary, bytes)?;
        std::fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verify(tree: &MerkleTree, leaves: &[u64], index: usize) {
        let (siblings, bits) = tree.proof(index).unwrap();
        let reconstructed = bits
            .iter()
            .enumerate()
            .map(|(depth, bit)| if *bit { 1usize << depth } else { 0 })
            .sum::<usize>();
        assert_eq!(reconstructed, index);
        let mut current = FieldElement::from(leaves[index] as u128);
        for (sibling, is_right) in siblings.into_iter().zip(bits) {
            current = if is_right {
                poseidon2_compress(sibling, current)
            } else {
                poseidon2_compress(current, sibling)
            };
        }
        assert_eq!(current, tree.root());
    }

    #[test]
    fn trees_and_proofs_cover_power_and_non_power_sizes() {
        for count in [1usize, 2, 4, 9, 25] {
            let leaves = (0..count as u64).collect::<Vec<_>>();
            let tree = MerkleTree::build(&leaves).unwrap();
            for index in 0..count {
                verify(&tree, &leaves, index);
            }
        }
    }

    #[test]
    fn poseidon_zero_permutation_matches_measured_vector() {
        let state = vec![FieldElement::zero(); 4];
        let result = poseidon2_permutation(&state).unwrap();
        let expected = [
            "18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e",
            "095c230d1d37a246e8d2d5a63b165fe0fade040d442f61e25f0590e5fb76f839",
            "0bb9545846e1afa4fa3c97414a60a20fc4949f537a68cceca34c5ce71e28aa59",
            "18a4f34c9c6f99335ff7638b82aeed9018026618358873c982bbdde265b2ed6d",
        ];
        assert_eq!(
            result
                .iter()
                .map(|value| value.to_hex())
                .collect::<Vec<_>>(),
            expected
        );
    }

    #[test]
    fn cache_round_trip_and_stale_or_corrupt_entries_rebuild() {
        let root = std::env::temp_dir().join(format!(
            "zk-tsp-merkle-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let cache = root.join("tree.bin");
        let first = vec![0, 10, 20, 0];
        let witness = MerkleTree::load_or_build(&first, Some(&cache)).unwrap();
        let bytes = std::fs::read(&cache).unwrap();
        assert_eq!(
            MerkleTree::load_or_build(&first, Some(&cache))
                .unwrap()
                .root(),
            witness.root()
        );

        let stale = vec![0, 11, 20, 0];
        assert_ne!(
            MerkleTree::load_or_build(&stale, Some(&cache))
                .unwrap()
                .root(),
            witness.root()
        );
        std::fs::write(&cache, &bytes[..bytes.len() / 2]).unwrap();
        assert_eq!(
            MerkleTree::load_or_build(&first, Some(&cache))
                .unwrap()
                .root(),
            witness.root()
        );
        std::fs::write(&cache, b"corrupt").unwrap();
        assert_eq!(
            MerkleTree::load_or_build(&first, Some(&cache))
                .unwrap()
                .root(),
            witness.root()
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
