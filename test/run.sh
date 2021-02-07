#!/bin/bash

set -u

GREEN=$(tput setaf 2)
WHITE=$(tput setaf 7)

BOLD=$(tput bold)
RESET=$(tput sgr0)


for f in test/*.wlp; do
    exe=${f%.*} # strip .wlp
    echo -e "$BOLD$GREEN==>$WHITE ${f}$RESET"

    # Compile the program.
    ./compiler.py "$f"

    # Run the binary, and save the output.
    "./$exe" > "$f.out"
    
    exit=$?
    rm "$exe"

    # Create an empty .stdout file if it doesn't exist.
    if [ ! -f "$f.stdout" ]; then
        touch "$f.stdout"
    fi
    
    diff --color -u "$f.stdout" "$f.out"
    rm "$f.out"
    echo "exit code: $exit"
done
