use poseidon::poseidon2::Poseidon2;

fn main(
    left: Field,
    right: Field,
    pair: Field,
    single_input: Field,
    single: Field,
) {
    assert(Poseidon2::hash([left, right], 2) == pair);
    assert(Poseidon2::hash([single_input], 1) == single);
}
