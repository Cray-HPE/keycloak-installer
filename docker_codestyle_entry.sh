#!/bin/bash
# Copyright 2019-2020 Hewlett Packard Enterprise Development LP

set -ex
set -o pipefail

if [[ -z "$QUIET" ]]; then
  ls -al
fi

mkdir -p /results

if [[ -z "$QUIET" ]]; then
  pip freeze 2>&1 | tee /results/pip_freeze.out
fi

flake8 --ignore E501 2>&1 | tee /results/flake8.out
