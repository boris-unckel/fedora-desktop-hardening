# SPDX-License-Identifier: AGPL-3.0-or-later
# /etc/profile.d/aide-alert.sh
# Surfaces the AIDE file-integrity delta as a banner on interactive shell
# start. Silent when aide-check.service exited 0; prints a banner on any
# non-zero exit and stays silent once the operator acknowledges the
# current run. Mode 0644 root:root. Sourced by the /etc/profile loop on
# login shells.

# Skip non-interactive shells (cron, scp, sftp).
case $- in *i*) ;; *) return 0 ;; esac

# Last invocation exit status. Empty (never ran) or 0 (clean) -> silent.
_aide_rc=$(systemctl show -p ExecMainStatus --value aide-check.service 2>/dev/null)
case "$_aide_rc" in 0|"") unset _aide_rc; return 0 ;; esac

_aide_ts=$(systemctl show -p ExecMainExitTimestamp --value aide-check.service 2>/dev/null)

# Run identity + acknowledgement: silent when this run was already
# acknowledged. The run is identified by its monotonic exit timestamp; a
# per-user stamp file holds the acknowledged value. A new check run yields
# a new monotonic value, which re-arms the banner automatically.
_aide_mono=$(systemctl show -p ExecMainExitTimestampMonotonic --value aide-check.service 2>/dev/null)
_aide_ack="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/aide-alert.ack"
if [ -n "$_aide_mono" ] && [ -f "$_aide_ack" ] && \
   [ "$(cat "$_aide_ack" 2>/dev/null)" = "$_aide_mono" ]; then
    unset _aide_rc _aide_ts _aide_mono _aide_ack ; return 0
fi

# Decode the AIDE bitmask (1=new, 2=removed, 4=changed); >= 8 is a
# tool-internal error (I/O, database, or hash-library failure).
_aide_parts=""
case "$_aide_rc" in
    [1-7])
        [ $((_aide_rc & 1)) -ne 0 ] && _aide_parts="${_aide_parts}new "
        [ $((_aide_rc & 2)) -ne 0 ] && _aide_parts="${_aide_parts}removed "
        [ $((_aide_rc & 4)) -ne 0 ] && _aide_parts="${_aide_parts}changed "
        ;;
    *)
        _aide_parts="(non-bitmask exit=$_aide_rc - I/O or database error, check the journal)"
        ;;
esac

printf '\n  \033[1;33m! AIDE delta:\033[0m %s\n' "${_aide_parts% }"
printf '    Last run: %s\n' "${_aide_ts:-?}"
printf '    Review:   journalctl -u aide-check.service -b 0 --no-pager\n'
printf '    Refresh:  sudo -r sysadm_r -t sysadm_t aide --init   (then move the new database into place and restorecon -Fv)\n'
printf '    Ack:      echo %s > %s\n\n' "$_aide_mono" "$_aide_ack"

unset _aide_rc _aide_ts _aide_parts _aide_mono _aide_ack
