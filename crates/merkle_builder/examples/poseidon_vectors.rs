use acir::{AcirField, FieldElement};
use merkle_builder::{poseidon2_compress, poseidon2_hash_single};

fn main() {
    let left = FieldElement::from(1u128);
    let right = FieldElement::from(2u128);
    let pair = poseidon2_compress(left, right);
    let single = poseidon2_hash_single(pair);
    println!(
        "{{\"left\":\"1\",\"right\":\"2\",\"pair\":\"0x{}\",\"single_input\":\"0x{}\",\"single\":\"0x{}\"}}",
        pair.to_hex(),
        pair.to_hex(),
        single.to_hex()
    );
}
