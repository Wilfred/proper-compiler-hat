#!/bin/bash

set -u

GREEN=$(tput setaf 2)
WHITE=$(tput setaf 7)

BOLD=$(tput bold)
RESET=$(tput sgr0)


for f in test/*.wlp; do
    echo -e "$BOLD$GREEN==>$WHITE ${f}$RESET"
    ./compiler.py "$f"
    ./hello > "$f.stdout"
    exit=$?
    diff --color -u "$f.stdout" "$f.out"
    echo "exit code: $exit"
done
