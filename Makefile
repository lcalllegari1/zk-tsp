VENV ?= .venv
BOOTSTRAP_PYTHON ?= python3
PYTHON ?= $(VENV)/bin/python

.PHONY: install check test test-unit test-rust test-circuits test-equivalence \
	test-poseidon test-composite-verification test-recursive test-results \
	test-clean smoke \
	smoke-study smoke-monolithic smoke-composite smoke-recursive

install:
	$(BOOTSTRAP_PYTHON) -m venv $(VENV)
	$(VENV)/bin/python -m pip install -e .

check:
	$(PYTHON) -m zk_tsp check-toolchain

test: test-rust test-unit test-equivalence test-circuits test-poseidon \
	test-composite-verification test-recursive test-results test-clean

test-rust:
	cargo test --locked --manifest-path crates/merkle_builder/Cargo.toml --target-dir build/cargo

test-unit:
	$(PYTHON) -m unittest -v tests.test_unit

test-equivalence:
	$(PYTHON) -m unittest -v tests.test_equivalence tests.test_refined_equivalence

test-circuits:
	$(PYTHON) -m unittest -v tests.test_circuit_correctness \
		tests.test_committed_correctness tests.test_composite_correctness \
		tests.test_committed_composite_correctness

test-poseidon:
	$(PYTHON) -m unittest -v tests.test_poseidon_compat

test-composite-verification:
	$(PYTHON) -m unittest -v tests.test_composite_verification

test-recursive:
	$(PYTHON) -m unittest -v tests.test_recursive_correctness

test-results:
	$(PYTHON) -m unittest -v tests.test_results

test-clean:
	$(PYTHON) -m unittest -v tests.test_repository_cleanliness

smoke: smoke-study smoke-monolithic smoke-composite smoke-recursive

smoke-study:
	$(PYTHON) -m unittest -v tests.test_benchmark_smoke

smoke-monolithic:
	$(PYTHON) -m unittest -v tests.test_refined_benchmark_smoke

smoke-composite:
	$(PYTHON) -m unittest -v tests.test_composite_benchmark_smoke

smoke-recursive:
	$(PYTHON) -m unittest -v tests.test_recursive_benchmark_smoke
