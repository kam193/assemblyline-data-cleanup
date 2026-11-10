PYTHON ?= python3

.PHONY: test

test:
	$(PYTHON) -m unittest discover -s ip_intel -p 'test_*.py'
