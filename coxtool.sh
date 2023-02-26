#!/bin/bash
args=""
for var in "$@"; do
    args="${args} $var "
done
$(which python3) clitool.py $args