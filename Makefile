# SPDX-License-Identifier: Apache-2.0

GOOSE ?= .toolchain/goose/build/goose
CC ?= gcc
BENCH_ITERATIONS ?= 100000

.NOTPARALLEL:
.PHONY: all setup format check test bench fuzz clean

all: test

setup:
	./scripts/setup-goose.sh

format:
	"$(GOOSE)" format url.goose tests examples bench

check:
	"$(GOOSE)" format --check url.goose tests examples bench
	"$(GOOSE)" check tests/api.goose
	"$(GOOSE)" check tests/fuzz.goose
	"$(GOOSE)" check bench/bench.goose
	"$(GOOSE)" check examples/resolve.goose
	python3 -m py_compile scripts/*.py

test:
	mkdir -p .build
	"$(GOOSE)" run tests/api.goose
	"$(GOOSE)" build -O2 --cc "$(CC)" -o .build/api tests/api.goose
	./.build/api
	"$(GOOSE)" build --debug --no-bce --cc "$(CC)" -o .build/api-debug tests/api.goose
	./.build/api-debug
	"$(GOOSE)" run examples/resolve.goose

fuzz:
	mkdir -p .build
	python3 scripts/fuzz.py

bench:
	mkdir -p .build
	"$(GOOSE)" build -O2 --cc "$(CC)" -o .build/bench bench/bench.goose
	./.build/bench $(BENCH_ITERATIONS)

bench-compare:
	python3 scripts/compare.py

clean:
	rm -rf .build __pycache__ scripts/__pycache__ tests/__pycache__ bench/__pycache__
