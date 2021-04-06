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
    "./$exe" > "$f.out" 2> "$f.outerr"
    
    exit=$?
    rm -f "$exe"

    # Create an empty .stdout file if it doesn't exist.
    if [ ! -f "$f.stdout" ]; then
        touch "$f.stdout"
    fi

    # Check that stdout matches what we expected.
    diff --color -u "$f.stdout" "$f.out"

    # If we wrote anything to stderr, check it was what we expected.
    if [ -s "$f.outerr" ]; then
        # Create an empty .stderr if it doesn't exist.
        if [ ! -f "$f.stderr" ]; then
            touch "$f.stderr"
        fi

        diff --color -u "$f.stderr" "$f.outerr"
    elif [ -s "$f.stderr" ]; then
        echo "Expected something on stderr!"
    fi

    rm "$f.out"
    rm "$f.outerr"

    expected_exit=0
    if [ -f "$f.exitcode" ]; then
        expected_exit=$(cat "$f.exitcode")
    fi
    
    if [ $exit -ne $expected_exit ]; then
        echo "Got exit code $exit (expected $expected_exit)"
    fi
done
