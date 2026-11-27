.PHONY: install test demo gate clean

install:
	pip install -e ".[dev]"

test:
	pytest -q

demo:
	gatekeep demo --out runs/demo

gate: demo
	gatekeep gate --summary runs/demo/summary.json --posture enforced --max-asr 0.05 --min-utility 0.9

clean:
	rm -rf runs build dist *.egg-info .pytest_cache
