#!/usr/bin/bash
# Collect-NetScalerEvidence.sh
#
# Interactive NetScaler evidence collector.
#
# What it does:
# - Captures volatile state FIRST.
# - Preserves locally available /var/log and /var/nslog data.
# - Preserves configuration, existing cores/crashes and IOC output.
# - Optionally creates an NSPPE core dump.
# - If an NSPPE core is requested, installs a temporary one-shot boot hook
#   in /nsconfig/rc.netscaler AFTER the pre-reboot evidence has been captured.
# - After the warm restart, the script resumes automatically, removes its
#   own boot hook, collects the generated NSPPE core(s), and creates ONE
#   final .tar.gz archive.
#
# The temporary boot hook is added only after the original rc.netscaler
# has already been copied into the evidence set.
#
# No command-line parameters are required.

BASE="/var/tmp/NetScalerEvidence"
RUNONCE_SCRIPT="/nsconfig/scripts/Collect-NetScalerEvidence-RunOnce.sh"
RUNONCE_MARKER="# NETSCALER-EVIDENCE-RUNONCE"
STATEFILE="$BASE/.awaiting-nsppe-core"
PRE_ARCHIVE="$BASE/.pre-reboot-evidence.tar.gz"
HOST=$(hostname -s 2>/dev/null)
[ -z "$HOST" ] && HOST="NetScaler"

STAMP=$(date "+%Y%m%d-%H%M%S")
WORK="$BASE/${HOST}-${STAMP}"
FINAL="/var/tmp/${HOST}-Evidence-${STAMP}.tar.gz"

mkdir -p "$BASE" "$WORK/state" "$WORK/config" "$WORK/logs" "$WORK/cores" "$WORK/meta"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

save_cmd() {
    NAME="$1"
    shift
    "$@" > "$WORK/state/$NAME.txt" 2>&1
}

copy_dir() {
    SRC="$1"
    DST="$2"
    [ -d "$SRC" ] || return 0
    mkdir -p "$DST"
    cp -pR "$SRC"/. "$DST/" 2>/dev/null
}

copy_file() {
    SRC="$1"
    DST="$2"
    [ -f "$SRC" ] || return 0
    mkdir -p "$DST"
    cp -p "$SRC" "$DST/" 2>/dev/null
}

remove_runonce_hook() {
    RC="/nsconfig/rc.netscaler"
    if [ -f "$RC" ]; then
        sed -i '' "/NETSCALER-EVIDENCE-RUNONCE/d" "$RC" 2>/dev/null
    fi
}

collect_evidence() {
    PHASE="$1"
    log "Collecting $PHASE evidence in $WORK"

    {
        echo "Phase:     $PHASE"
        echo "Collected: $(date)"
        echo "Hostname:  $(hostname 2>/dev/null)"
        echo "Uptime:"
        uptime 2>/dev/null
        echo
        echo "adc.version:"
        cat /var/nsinstall/adc.version 2>/dev/null
    } > "$WORK/meta/collection.txt"

    save_cmd "ps-auxww" ps auxww
    save_cmd "ps-tree" ps -axo user=,pid=,ppid=,start=,etime=,command=
    save_cmd "top" top -b -n 1
    save_cmd "mount" mount
    save_cmd "df" df -h
    save_cmd "ifconfig" ifconfig -a
    save_cmd "netstat-an" netstat -an
    save_cmd "netstat-rn" netstat -rn

    if command -v sockstat >/dev/null 2>&1; then
        save_cmd "sockstat" sockstat -46
    fi

    if command -v sysctl >/dev/null 2>&1; then
        sysctl -a 2>/dev/null | grep -E 'num_pe_running|hw\.physmem|hw\.realmem|hw\.ncpu' \
            > "$WORK/state/sysctl-relevant.txt"
    fi

    if [ -x /netscaler/nsconmsg ] && [ -f /var/nslog/newnslog ]; then
        /netscaler/nsconmsg -K /var/nslog/newnslog -d setime \
            > "$WORK/state/newnslog-timespan.txt" 2>&1
        /netscaler/nsconmsg -K /var/nslog/newnslog -d event \
            > "$WORK/state/newnslog-events.txt" 2>&1
    fi

    copy_file "/var/nsinstall/adc.version" "$WORK/config"
    copy_file "/nsconfig/ns.conf" "$WORK/config"
    copy_file "/nsconfig/ns.conf.0" "$WORK/config"
    copy_file "/nsconfig/ns.conf.1" "$WORK/config"
    copy_file "/nsconfig/rc.netscaler" "$WORK/config"
    copy_file "/etc/crontab" "$WORK/config"

    copy_file "/nsconfig/scripts/iocADM.sh" "$WORK/config"
    copy_file "/nsconfig/scripts/iocADM.log" "$WORK/logs"

    copy_dir "/var/log" "$WORK/logs/var-log"
    copy_dir "/var/nslog" "$WORK/logs/var-nslog"
    copy_dir "/var/core" "$WORK/cores/var-core"
    copy_dir "/var/crash" "$WORK/cores/var-crash"

    if [ -e /var/tmp/support/support.tgz ]; then
        mkdir -p "$WORK/support"
        cp -pL /var/tmp/support/support.tgz "$WORK/support/" 2>/dev/null
    fi

    for P in \
        /var/netscaler/logon \
        /netscaler/portal \
        /netscaler/ns_gui \
        /var/tmp \
        /tmp
    do
        [ -e "$P" ] || continue
        SAFE=$(echo "$P" | sed 's#/#_#g')
        find "$P" -xdev -type f -exec ls -lT {} + \
            > "$WORK/meta/files${SAFE}.txt" 2>/dev/null
    done

    if command -v sha256 >/dev/null 2>&1; then
        find "$WORK/state" "$WORK/config" "$WORK/meta" -type f -exec sha256 {} \; \
            > "$WORK/meta/SHA256.txt" 2>/dev/null
    elif command -v sha256sum >/dev/null 2>&1; then
        find "$WORK/state" "$WORK/config" "$WORK/meta" -type f -exec sha256sum {} \; \
            > "$WORK/meta/SHA256.txt" 2>/dev/null
    fi
}

make_final_archive() {
    log "Creating final archive..."
    tar czf "$FINAL" -C "$WORK" . 2>/dev/null

    if [ ! -f "$FINAL" ]; then
        log "ERROR: final archive could not be created."
        exit 1
    fi

    SIZE=$(ls -lh "$FINAL" 2>/dev/null | awk '{print $5}')
    log "DONE: $FINAL ($SIZE)"
    echo
    echo "Download this single file:"
    echo "$FINAL"
}

# Automatic post-reboot run.
if [ -f "$STATEFILE" ]; then
    log "Post-reboot run detected."

    remove_runonce_hook
    pb_policy -d 2>/dev/null

    if [ -f "$PRE_ARCHIVE" ]; then
        mkdir -p "$WORK/pre-reboot"
        tar xzf "$PRE_ARCHIVE" -C "$WORK/pre-reboot" 2>/dev/null
    fi

    mkdir -p "$WORK/post-reboot"
    cp -p "$STATEFILE" "$WORK/post-reboot/nsppe-core-request.txt" 2>/dev/null

    POSTWORK="$WORK"
    WORK="$WORK/post-reboot"
    mkdir -p "$WORK/state" "$WORK/config" "$WORK/logs" "$WORK/cores" "$WORK/meta"

    collect_evidence "POST-REBOOT"

    WORK="$POSTWORK"

    {
        echo "NSPPE cores available after restart:"
        find /var/core -type f -name 'NSPPE-*' -exec ls -lT {} + 2>/dev/null
    } > "$WORK/post-reboot/nsppe-cores.txt"

    rm -f "$STATEFILE" "$PRE_ARCHIVE" "$RUNONCE_SCRIPT"

    make_final_archive
    exit 0
fi

# Normal interactive run.
collect_evidence "PRE-REBOOT"

echo
echo "NetScaler evidence has been collected without changing the running system."
echo
printf "Generate an NSPPE core dump as well? This will trigger a warm restart. [y/N]: "

ANSWER=""
if [ -r /dev/tty ]; then
    read -r ANSWER < /dev/tty
else
    read -r ANSWER
fi

case "$ANSWER" in
    y|Y|yes|YES|Yes) WANT_CORE="YES" ;;
    *)                WANT_CORE="NO" ;;
esac

if [ "$WANT_CORE" != "YES" ]; then
    make_final_archive
    exit 0
fi

PPE_PID=$(ps auxww 2>/dev/null | awk '/[N]SPPE-/ {print $2; exit}')

if [ -z "$PPE_PID" ]; then
    log "WARNING: no NSPPE process was found. No core dump will be generated."
    make_final_archive
    exit 0
fi

tar czf "$PRE_ARCHIVE" -C "$WORK" . 2>/dev/null

if [ ! -f "$PRE_ARCHIVE" ]; then
    log "ERROR: pre-reboot archive could not be created. Core dump aborted."
    make_final_archive
    exit 1
fi

{
    echo "Requested: $(date)"
    echo "Hostname: $(hostname 2>/dev/null)"
    echo "NSPPE PID: $PPE_PID"
    echo
    echo "Existing NSPPE cores before restart:"
    find /var/core -type f -name 'NSPPE-*' -exec ls -lT {} + 2>/dev/null
} > "$STATEFILE"

mkdir -p /nsconfig/scripts
cp -p "$0" "$RUNONCE_SCRIPT"
chmod 700 "$RUNONCE_SCRIPT"

RC="/nsconfig/rc.netscaler"
[ -f "$RC" ] || touch "$RC"

remove_runonce_hook
echo "/usr/bin/nohup /usr/bin/bash $RUNONCE_SCRIPT >/var/tmp/NetScalerEvidence-RunOnce.log 2>&1 & $RUNONCE_MARKER" >> "$RC"

sync

log "Pre-reboot evidence has been preserved."
log "Temporary one-shot boot hook installed."
log "Generating NSPPE core now. The appliance will warm restart."
log "After restart the evidence collection will resume automatically."
echo

pb_policy -o abort
sync
kill -6 "$PPE_PID"

exit 0
