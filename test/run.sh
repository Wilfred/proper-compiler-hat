#!/bin/bash

set -eu

GREEN=$(tput setaf 2)
WHITE=$(tput setaf 7)

BOLD=$(tput bold)
RESET=$(tput sgr0)


for f in test/*.wlp; do
    echo -e "$BOLD$GREEN==>$WHITE ${f}$RESET"
    ./compiler.py "$f"
    ./hello
done
