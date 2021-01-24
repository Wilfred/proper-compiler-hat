#!/bin/bash

set -u

GREEN=$(tput setaf 2)
WHITE=$(tput setaf 7)

BOLD=$(tput bold)
RESET=$(tput sgr0)


for f in test/*.wlp; do
    exe=${f%.*} # strip .wlp
    echo -e "$BOLD$GREEN==>$WHITE ${f}$RESET"
    ./compiler.py "$f"
    "./$exe" > "$f.out"
    exit=$?
    rm "$exe"
    diff --color -u "$f.stdout" "$f.out"
    rm "$f.out"
    echo "exit code: $exit"
done
