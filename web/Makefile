PYTHON ?= python3
# Source for the C++ ZK library. Sibling 'lib/' directory by default; override
# LIB_SRC / BUILD to point elsewhere (e.g. a system install or a private fork).
LIB_SRC ?= ../lib
BUILD ?= ../build
# Default to an -O3 optimized build (CMake Release == -O3 -DNDEBUG).
# Override with e.g. BUILD_TYPE=Debug for an unoptimized build.
BUILD_TYPE ?= Release
TARGETS = delegation_demo_issuer delegation_demo_alice delegation_demo_agent delegation_demo_verifier

.PHONY: deps configure build demo clean check

deps:
	@if [ ! -d .venv ]; then $(PYTHON) -m venv .venv; fi
	./.venv/bin/pip install -r requirements.txt

configure:
	cmake -S $(LIB_SRC) -B $(BUILD) -DCMAKE_BUILD_TYPE=$(BUILD_TYPE)

build:
	@if [ ! -f $(BUILD)/CMakeCache.txt ]; then $(MAKE) configure; fi
	cmake --build $(BUILD) --target $(TARGETS) -j

check:
	@test -x $(BUILD)/examples/delegation_demo/delegation_demo_issuer || (echo "binaries missing; run: make build" && exit 1)
	@echo "binaries OK"

demo: check
	chmod +x start.sh
	./start.sh

clean:
	rm -rf data/wallet/holder data/wallet/delegation data/wallet/tasks/* data/shared/issuer_public data/tripgo/orders.json data/tripgo/tasks/*
