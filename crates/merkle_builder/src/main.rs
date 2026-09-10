use acir::AcirField;
use merkle_builder::{build_witness, write_composite, write_witness_toml, CompositeVariant, Input};
use std::io::{self, Read};
use std::path::PathBuf;

fn main() {
    if let Err(error) = run() {
        eprintln!("merkle_builder: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut output = None;
    let mut output_directory = None;
    let mut cache = None;
    let mut composite = None;
    let mut segments = None;
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("{argument} requires a path"))?;
        match argument.as_str() {
            "--out" => output = Some(PathBuf::from(value)),
            "--out-dir" => output_directory = Some(PathBuf::from(value)),
            "--tree-cache" => cache = Some(PathBuf::from(value)),
            "--composite" => composite = Some(CompositeVariant::parse(&value)?),
            "--segments" => {
                segments = Some(
                    value
                        .parse::<usize>()
                        .map_err(|_| format!("invalid segment count: {value}"))?,
                )
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    let mut json = String::new();
    io::stdin()
        .read_to_string(&mut json)
        .map_err(|error| format!("cannot read stdin: {error}"))?;
    let input: Input =
        serde_json::from_str(&json).map_err(|error| format!("invalid input JSON: {error}"))?;
    if let Some(variant) = composite {
        let output_directory = output_directory.ok_or(
            "composite usage: merkle_builder --composite VARIANT --segments K --out-dir DIR",
        )?;
        let segments = segments.ok_or("--segments is required for composite witnesses")?;
        let summary = write_composite(
            &input,
            variant,
            segments,
            &output_directory,
            cache.as_deref(),
        )?;
        println!(
            "{}",
            serde_json::to_string(&summary)
                .map_err(|error| format!("cannot serialize summary: {error}"))?
        );
        return Ok(());
    }
    let output = output.ok_or("usage: merkle_builder --out PATH [--tree-cache PATH]")?;
    let witness = build_witness(&input, cache.as_deref())?;
    write_witness_toml(&output, &witness)
        .map_err(|error| format!("cannot write {}: {error}", output.display()))?;
    eprintln!(
        "merkle_builder: N={} DEPTH={} root=0x{}",
        input.n,
        witness.path_bits.len() / input.n,
        witness.root.to_hex()
    );
    Ok(())
}
