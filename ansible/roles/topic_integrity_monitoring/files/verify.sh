#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# verify.sh -- expected-versus-actual comparison for
# topic_integrity_monitoring. Non-zero on drift.
#
# One judgement call is encoded here deliberately: an aggregate status of 1
# (findings) is a PASS. Known findings that are deliberately left visible --
# context drift awaiting a fix, for instance -- keep the aggregate at 1
# indefinitely, and that is the intended behaviour. A verify that treated 1 as
# failure would push an operator toward accepting real drift just to make the
# check go green, which is exactly the self-confirming loop this topic removes.
# Only a tool failure (2) is a verify failure.

set -uo pipefail
export LC_ALL=C

readonly UNIT_DIR="/etc/systemd/system"
readonly WRAPPER="/usr/local/sbin/integrity-check"
readonly AIDE_CONF="/etc/aide.conf"
readonly AIDE_DB="/var/lib/aide/aide.db.gz"
readonly ACCEPT_DIR="/etc/integrity-check"
readonly BANNER="/etc/profile.d/aide-alert.sh"

RC=0

fail() { printf '  [FAIL] %s\n' "$*"; RC=1; }
ok()   { printf '  [ok]   %s\n' "$*"; }

check_file() {
  local path="$1" mode="$2" seltype="$3"
  if [[ ! -e "$path" ]]; then
    fail "missing: ${path}"
    return
  fi
  local m o c
  m="$(stat -c '%a' "$path")"
  o="$(stat -c '%U:%G' "$path")"
  c="$(stat -c '%C' "$path")"
  if [[ "$m" != "$mode" || "$o" != "root:root" ]]; then
    fail "${path} mode=${m} owner=${o} (expected ${mode} root:root)"
    return
  fi
  case "$c" in
    *:"${seltype}":*) ok "${path} ${mode} root:root ${seltype}" ;;
    *) fail "${path} label ${c} (expected ${seltype})" ;;
  esac
}

# check_file above compares the SELinux *type* against a hardcoded expectation
# and stops there. That leaves two gaps this function closes: the SELinux user
# field is never looked at, and the acceptance directory is not an artefact in
# check_file's list at all. Both matter here more than elsewhere, because this
# topic's fourth check is itself a context comparison -- and it compares types,
# so it can never report drift confined to the user field.
context_matches() {
  local path="$1" mode ftype actual expected
  ftype="$(LC_ALL=C stat -c '%F' "$path" 2>/dev/null)" || {
    fail "context: ${path} not stat-able"
    return
  }
  case "$ftype" in
    *"symbolic link"*) mode="link" ;;
    "directory") mode="dir" ;;
    *) mode="file" ;;
  esac
  actual="$(stat -c '%C' "$path" 2>/dev/null || true)"
  expected="$(matchpathcon -m "$mode" "$path" 2>/dev/null | sed 's#.*\t##')"
  if [[ -z "$expected" || -z "$actual" ]]; then
    fail "context: ${path} not resolvable"
  elif [[ "$actual" != "$expected" ]]; then
    fail "context: ${path} is ${actual}, file_contexts says ${expected}"
  else
    ok "context: ${path} ${actual}"
  fi
}

verify_context() {
  printf '== selinux context (full, including the user field) ==\n'
  if ! command -v matchpathcon >/dev/null 2>&1; then
    printf '  [skip] matchpathcon not available\n'
    return
  fi
  local p
  for p in "$WRAPPER" \
           "${UNIT_DIR}/integrity-check.service" \
           "${UNIT_DIR}/integrity-check.timer" \
           "${UNIT_DIR}/aide-check.service" \
           "${UNIT_DIR}/aide-init.service" \
           "$ACCEPT_DIR"; do
    [[ -e "$p" ]] && context_matches "$p"
  done
  [[ -e "$BANNER" ]] && context_matches "$BANNER"
  for p in "$ACCEPT_DIR"/*; do
    [[ -e "$p" ]] && context_matches "$p"
  done
  return 0
}

verify_artefacts() {
  printf '== artefacts ==\n'
  check_file "$WRAPPER" 755 bin_t
  check_file "${UNIT_DIR}/integrity-check.service" 644 systemd_unit_file_t
  check_file "${UNIT_DIR}/integrity-check.timer" 644 systemd_unit_file_t
  check_file "${UNIT_DIR}/aide-check.service" 644 systemd_unit_file_t
  check_file "${UNIT_DIR}/aide-init.service" 644 systemd_unit_file_t
  [[ -e "$BANNER" ]] && check_file "$BANNER" 644 bin_t
}

verify_timers() {
  printf '\n== timers ==\n'
  if [[ -e "${UNIT_DIR}/aide-check.timer" ]]; then
    fail "superseded aide-check.timer still present"
  else
    ok "superseded aide-check.timer removed"
  fi
  if systemctl is-enabled integrity-check.timer >/dev/null 2>&1; then
    ok "integrity-check.timer enabled (next: $(systemctl show -p NextElapseUSecRealtime --value integrity-check.timer))"
  else
    fail "integrity-check.timer not enabled"
  fi
}

verify_scope() {
  printf '\n== AIDE scope ==\n'
  local n
  n="$(grep -c '^# ic-inverted' "$AIDE_CONF" 2>/dev/null || true)"
  if [[ "$n" -gt 0 ]]; then
    ok "${n} whole-tree rule(s) commented out"
  else
    fail "no inverted rules found in ${AIDE_CONF}"
  fi
  if grep -qE '^/boot\s+NORMAL' "$AIDE_CONF" 2>/dev/null; then
    ok "/boot still in scope"
  else
    fail "/boot no longer in scope -- the early-boot image would be uncovered"
  fi
  if grep -qE "^${ACCEPT_DIR}\s+NORMAL" "$AIDE_CONF" 2>/dev/null; then
    ok "acceptance lists are hashed, not merely permission-checked"
  else
    fail "no hash rule for ${ACCEPT_DIR} -- a content edit there would be invisible"
  fi
  if aide --config-check --config "$AIDE_CONF" >/dev/null 2>&1; then
    ok "aide --config-check silent"
  else
    fail "aide --config-check reports a problem"
  fi
  if [[ -s "$AIDE_DB" ]]; then
    ok "baseline present ($(stat -c '%s' "$AIDE_DB") bytes, $(stat -c '%C' "$AIDE_DB"))"
  else
    fail "baseline missing or empty"
  fi
}

verify_accept_lists() {
  printf '\n== acceptance lists ==\n'
  local f
  for f in accepted-rpm-verify.txt accepted-unowned.txt accepted-context.txt; do
    if [[ -r "${ACCEPT_DIR}/${f}" ]]; then
      ok "${f} ($(grep -cvE '^\s*(#|$)' "${ACCEPT_DIR}/${f}" || true) entries)"
    else
      fail "${f} missing"
    fi
  done
}

verify_run() {
  printf '\n== full run through the unit ==\n'
  systemctl reset-failed integrity-check.service 2>/dev/null || true
  local t0 t1 status
  t0="$(date +%s)"
  systemctl start --wait integrity-check.service 2>/dev/null || true
  t1="$(date +%s)"
  status="$(systemctl show -p ExecMainStatus --value integrity-check.service)"
  printf '  runtime %ss, ExecMainStatus=%s\n' "$((t1 - t0))" "$status"
  case "$status" in
    0) ok "clean" ;;
    1) ok "findings -- a PASS; review them, do not accept them to silence the check" ;;
    2) fail "tool failure" ;;
    *) fail "unexpected status ${status}" ;;
  esac
}

verify_log() {
  printf '\n== run log ==\n'
  local newest
  newest="$(find /var/log/aide -maxdepth 1 -name 'integrity-*.log' -printf '%T@ %p\n' \
    2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)"
  if [[ -n "$newest" && -s "$newest" ]]; then
    ok "${newest} ($(grep -c . "$newest") lines)"
    case "${newest##*/}" in
      *-dnf[0-9]*) ok "transaction id present in the file name" ;;
      *-dnfNONE*)  printf '  [warn] transaction id NONE -- package history unreadable?\n' ;;
      *)           fail "no transaction id in the file name" ;;
    esac
  else
    fail "no non-empty run log found"
  fi
}

verify_serialisation() {
  printf '\n== serialisation ==\n'
  systemctl start --no-block integrity-check.service 2>/dev/null || true
  sleep 2
  local t0 t1
  t0="$(date +%s)"
  systemctl start --wait integrity-check.service 2>/dev/null || true
  t1="$(date +%s)"
  if [[ "$((t1 - t0))" -gt 0 ]]; then
    ok "second start waited $((t1 - t0))s -- systemd serialises"
  else
    printf '  [warn] second start did not wait; the first may have finished already\n'
  fi
}

main() {
  printf 'topic_integrity_monitoring verify\n'
  printf 'context: %s\n\n' "$(id -Z 2>/dev/null || echo '?')"
  verify_artefacts
  verify_context
  verify_timers
  verify_scope
  verify_accept_lists
  verify_run
  verify_log
  verify_serialisation
  printf '\nverify rc=%d\n' "$RC"
  return "$RC"
}

main "$@"
