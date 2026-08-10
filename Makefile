.PHONY: test demo experiment clean

PYTHON ?= python3
TRIALS ?= 250
BENCHMARK_CASES ?= 2000
SEED ?= 20260806

export PYTHONPATH := src

test:
	$(PYTHON) -m unittest discover -s tests -v

demo:
	$(PYTHON) -m soa.demo

experiment:
	$(PYTHON) -m soa.experiment \
		--trials $(TRIALS) \
		--benchmark-cases $(BENCHMARK_CASES) \
		--seed $(SEED) \
		--output results

clean:
	rm -rf build dist *.egg-info src/*.egg-info .coverage .pytest_cache results-test
