#!/bin/bash

# Copyright 2022 The Centipede Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This sh_test runs various tests on test_fuzz_target,
# which is linked against :centipede_runner.

set -eu

source "$(dirname "$0")/../test_util.sh"

# Binaries.
centipede="$(centipede::get_centipede_test_srcdir)/centipede"
target="$(centipede::get_centipede_test_srcdir)/testing/clusterfuzz_format_target"
sanitized_target="$(centipede::get_centipede_test_srcdir)/testing/clusterfuzz_format_sanitized_target"

# Create input files.
oom="${TEST_TMPDIR}/oom"
uaf="${TEST_TMPDIR}/uaf"

echo -n oom > "${oom}"  # Triggers out-of-memory.
echo -n uaf > "${uaf}"  # Triggers heap-use-after-free.

# Shorthand to run centipede with necessary flags.
abort_test_fuzz() {
  set -x
  "${centipede}" \
    --workdir="${WD}" \
    --binary="${target}" --symbolizer_path=/dev/null \
    --extra_binaries="${sanitized_target}" \
    --address_space_limit_mb=4096 \
    "$@" 2>&1
  set +x
}

# Tests fuzzing with a target that crashes.
test_crashing_target() {
  FUNC="${FUNCNAME[0]}"
  WD="${TEST_TMPDIR}/${FUNC}/WD"
  TMPCORPUS="${TEST_TMPDIR}/${FUNC}/C"
  LOG="${TEST_TMPDIR}/${FUNC}/log"
  centipede::ensure_empty_dir "${WD}"
  centipede::ensure_empty_dir "${TMPCORPUS}"

  # Create a corpus with one crasher and one other input.
  cp "$1" "${TMPCORPUS}"  # Triggers an error.
  echo -n "foo" >"${TMPCORPUS}/foo"     # Just some input.
  abort_test_fuzz --export_corpus_from_local_dir="${TMPCORPUS}"

  # Run fuzzing with num_runs=0, i.e. only run the inputs from the corpus.
  # Expecting a crash to be observed and reported.
  abort_test_fuzz --num_runs=0 | tee "${LOG}"

  # Validate format.
  for expected_regex in "${@:2}"
  do
    centipede::assert_regex_in_file "$expected_regex" "${LOG}"
  done
}

#The following test target triggers ASAN heap-use-after-free error.
# We check if each crash log is in the format expected by ClusterFuzz.
echo ======== Check UAF crash log format.
test_crashing_target ${uaf} \
  'ERROR: AddressSanitizer: heap-use-after-free' \
  '[Ss]aving input to[ \t]*: ..*'

#The following test targets trigger out-of-memory error.
# We check if each crash log is in the format expected by ClusterFuzz.
echo ======== Check OOM crash log format.
test_crashing_target ${oom} \
  'Failure[ \t]*: rss-limit-exceeded' \
  '[Ss]aving input to[ \t]*: ..*'


echo "PASS"
