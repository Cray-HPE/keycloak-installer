#!/bin/sh
# Copyright 2019-2020, Cray Inc. All Rights Reserved.

set -ex
set -o pipefail

if [[ -z "$QUIET" ]]; then
  ls -al
fi
mkdir -p /results
if [[ -z "$QUIET" ]]; then
  pip freeze 2>&1 | tee /results/pip_freeze.out
fi
pytest -v \
 --cov-report html:/results/coverage \
 --cov=keycloak_setup \
 --junit-xml=/results/pytest.xml \
 2>&1 | tee /results/pytest.out
