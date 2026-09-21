#!/usr/bin/env bash
# Disposable test process, no host filesystem mounts or live TC attachment.
set -Eeuo pipefail
[[ ${UNF_MAIN_LOCALITY_ISOLATED_CONTAINER:-} == yes && $EUID == 0 ]]
export UNF_EBPF_OBJECT=/usr/local/lib/unf/main-locality-test
[[ ${UNF_EXPECT_BUILD_REVISION:-} =~ ^[0-9a-f]{40}$ ]]
output=$(mktemp /tmp/unf-main-locality.XXXXXX)
trap 'rm -f -- "$output"' EXIT
for name in \
    diagnostic_build_revision_matches_source \
    privileged_encryption_finalizer_is_dual_stack_late_bound_and_fail_closed \
    privileged_locality_bridge_missing_bank_keeps_exact_encryption_and_marks \
    privileged_egress_source_steering_is_policy_first_destination_exact_and_dual_stack \
    privileged_load_balancer_dsr_preserves_dual_stack_vips_and_direct_return; do
    /usr/local/bin/unf-main-tests --ignored --exact "tests::$name" --nocapture --test-threads=1 | tee "$output"
    grep -Eq '^test result: ok\. 1 passed; 0 failed; 0 ignored;' "$output"
    printf 'main-locality-check: name=%s passed=true\n' "$name"
done
printf 'main-locality-suite: PASS tests=5 compiled-source=true actual-main=true missing-bank-fallback=true live-attachment=false bank-delivery=false\n'
