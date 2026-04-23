.PHONY:	venv

.venv:
	uv venv

venv:	.venv
	echo "Using .venv"

deps:
	uv sync
