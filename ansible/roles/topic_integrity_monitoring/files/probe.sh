#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# probe.sh -- read-only diagnostics for topic_integrity_monitoring.
#
# Answers the question the topic rests on: how much of this host's monitored
# tree does the package database already cover? If the answer is not
# "overwhelmingly", the inversion is not worth applying here and the operator
# should know that before, not after.
#
# Changes nothing. Safe to run repeatedly.

set -uo pipefail
export LC_ALL=C

readonly AIDE_CONF="/etc/aide.conf"
readonly AIDE_DB="/var/lib/aide/aide.db.gz"
readonly ACCEPT_DIR="/etc/integrity-check"
readonly -a SCAN_ROOTS=(/usr /opt /boot /etc)

# Resolves both path-aliasing classes. Without the second substitution the
# comparison reports every compatibility symlink under the merged sbin
# directory as unowned -- hundreds of false positives, silently.
normalize_paths() {
  sed -E -e 's#^/(bin|sbin|lib|lib64)/#/usr/\1/#' -e 's#^/usr/sbin/#/usr/bin/#'
}

probe_share() {
  printf '== package-owned share ==\n'
  local owned fs total n_owned n_unowned pct
  owned="$(rpm -qal 2>/dev/null | normalize_paths | sort -u)"
  fs="$(find "${SCAN_ROOTS[@]}" -xdev \( -type f -o -type l \) 2>/dev/null \
    | normalize_paths | sort -u)"
  total="$(printf '%s\n' "$fs" | grep -c . || true)"
  n_owned="$(comm -12 <(printf '%s\n' "$fs") <(printf '%s\n' "$owned") | grep -c . || true)"
  n_unowned="$(comm -23 <(printf '%s\n' "$fs") <(printf '%s\n' "$owned") | grep -c . || true)"
  if [[ "$total" -gt 0 ]]; then
    pct="$(awk -v a="$n_owned" -v b="$total" 'BEGIN { printf "%.2f", (a * 100) / b }')"
  else
    pct="0.00"
  fi
  printf '  scanned      : %s\n' "$total"
  printf '  package-owned: %s (%s%%)\n' "$n_owned" "$pct"
  printf '  unowned      : %s\n' "$n_unowned"
  printf '\n  unowned by directory (top 15):\n'
  comm -23 <(printf '%s\n' "$fs") <(printf '%s\n' "$owned") \
    | sed -E 's#/[^/]+$##' | sort | uniq -c | sort -rn | head -15 | sed 's/^/    /'
}

probe_current_state() {
  printf '\n== current state ==\n'
  if [[ -f "$AIDE_DB" ]]; then
    printf '  baseline     : %s bytes, label %s\n' \
      "$(stat -c '%s' "$AIDE_DB")" "$(stat -c '%C' "$AIDE_DB")"
  else
    printf '  baseline     : absent (the apply will take the first one)\n'
  fi
  printf '  scope inverted: %s\n' \
    "$(grep -qE '^# ic-inverted' "$AIDE_CONF" 2>/dev/null && echo yes || echo no)"
  printf '  acceptance dir: %s\n' \
    "$([[ -d "$ACCEPT_DIR" ]] && echo present || echo absent)"
  printf '  old timer     : %s\n' \
    "$(systemctl is-enabled aide-check.timer 2>/dev/null || echo absent)"
  printf '  new timer     : %s\n' \
    "$(systemctl is-enabled integrity-check.timer 2>/dev/null || echo absent)"
}

probe_noise_baseline() {
  printf '\n== noise baseline (what each check reports today) ==\n'
  local t0 t1 out n

  t0="$(date +%s)"
  out="$(rpm -Va 2>&1)"
  t1="$(date +%s)"
  n="$(printf '%s\n' "$out" | grep -vE '^\S+\s+g\s' | grep -c . || true)"
  printf '  rpm -Va        : %ss, %s line(s) after filtering ghost entries\n' \
    "$((t1 - t0))" "$n"

  t0="$(date +%s)"
  out="$(restorecon -nvR "${SCAN_ROOTS[@]}" 2>&1)"
  t1="$(date +%s)"
  n="$(printf '%s\n' "$out" | grep -c . || true)"
  printf '  restorecon -n  : %ss, %s context deviation(s)\n' "$((t1 - t0))" "$n"
  if [[ "$n" -gt 0 ]]; then
    printf '\n  context deviations (these become findings unless fixed):\n'
    printf '%s\n' "$out" | head -25 | sed 's/^/    /'
  fi
}

main() {
  printf 'topic_integrity_monitoring probe\n'
  printf 'context: %s\n\n' "$(id -Z 2>/dev/null || echo '?')"
  probe_share
  probe_current_state
  probe_noise_baseline
  printf '\nprobe complete -- nothing changed.\n'
}

main "$@"
