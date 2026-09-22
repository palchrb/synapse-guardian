PY ?= .venv/bin/python
PYTEST ?= .venv/bin/pytest
SYNAPSE_TAG ?= v1.161.0
SYNAPSE_TESTS_DIR ?= .synapse-tests

.PHONY: venv synapse-tests test-unit test-module test lint bot-build clean

venv:
	python3 -m venv .venv && .venv/bin/pip install -U pip && .venv/bin/pip install -e ".[dev]"

# Sparse checkout of ONLY Synapse's tests/ package (the wheel does not ship it).
# Never check out synapse/ here: it would shadow the installed wheel.
synapse-tests:
	@if [ ! -f $(SYNAPSE_TESTS_DIR)/tests/unittest.py ]; then \
	  rm -rf $(SYNAPSE_TESTS_DIR); \
	  git clone -q --depth 1 --filter=blob:none --sparse --branch $(SYNAPSE_TAG) \
	    https://github.com/element-hq/synapse.git $(SYNAPSE_TESTS_DIR); \
	  git -C $(SYNAPSE_TESTS_DIR) sparse-checkout set tests; \
	fi

# Collect the whole directory (minus the trial-only suite) so a new test file
# is never silently left out of `make test`.
test-unit:
	$(PYTEST) family_guard_tests --ignore=family_guard_tests/test_module.py

test-module: synapse-tests
	PYTHONPATH=$(SYNAPSE_TESTS_DIR) $(PY) -m twisted.trial family_guard_tests.test_module

test: test-unit test-module

lint:
	$(PY) -m pyflakes family_guard family_guard_tests scripts bot/family_guard_bot
	$(PY) -m compileall -q family_guard family_guard_tests scripts bot/family_guard_bot

# maubot plugins are zipped; the bot needs its own copy of policy.py.
bot-build:
	cp family_guard/policy.py bot/family_guard_bot/policy.py
	@if command -v mbc >/dev/null 2>&1; then cd bot && mbc build; \
	 else echo "mbc not found: bot/family_guard_bot is ready, run 'mbc build' in bot/ yourself"; fi

clean:
	rm -rf _trial_temp .pytest_cache build dist *.egg-info bot/*.mbp
	find . -name __pycache__ -not -path './.venv/*' -exec rm -rf {} +
