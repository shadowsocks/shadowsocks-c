#!/bin/sh
set -e
set -o xtrace

cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build -L 'unit|vendor' --output-on-failure
cmake --install build
