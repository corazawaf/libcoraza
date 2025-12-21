#!/bin/bash

# Check that we have an argument
if [ $# -eq 0 ]; then
    echo "Usage: $0 <executable_name>"
    exit 1
fi

EXECUTABLE_NAME="$1"
EXECUTABLE="./${EXECUTABLE_NAME}"
OUT_FILE="./${EXECUTABLE_NAME}.out"

# Check if executable exists
if [ ! -f "$EXECUTABLE" ]; then
    echo "Error: Executable '$EXECUTABLE' not found"
    exit 1
fi

# Check if .out file exists
if [ ! -f "$OUT_FILE" ]; then
    echo "Error: Expected output file '$OUT_FILE' not found"
    exit 1
fi

# Run the executable and capture output to environment variable
ACTUAL_OUTPUT=$("$EXECUTABLE" 2>&1)
EXIT_CODE=$?

# Check if execution was successful
if [ $EXIT_CODE -ne 0 ]; then
    echo "Error: Executable '$EXECUTABLE_NAME' exited with code $EXIT_CODE"
    exit 1
fi

# Compare output with expected output using diff
if diff -u <(cat "$OUT_FILE") <(printf '%s\n' "$ACTUAL_OUTPUT") > /dev/null; then
    echo "PASS: Output matches expected output"
    exit 0
else
    echo "FAIL: Output does not match expected output"
    echo ""
    diff -u <(cat "$OUT_FILE") <(printf '%s\n' "$ACTUAL_OUTPUT")
    exit 1
fi

