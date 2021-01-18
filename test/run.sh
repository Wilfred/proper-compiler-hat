#!/bin/bash

set -eu

for f in test/*.wlp; do
    echo "==> $f"
    ./compiler.py "$f"
    ./hello
done
