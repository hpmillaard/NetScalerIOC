#!/usr/bin/bash
# ioc.sh - IOC scanner for NetScaler / NetScaler Console (production)
# add audit messageaction IOC WARNING "\"[IOC]\""

LOGFILE="/nsconfig/scripts/ioc.log"
HUNT_LOGFILE="/nsconfig/scripts/ioc-hunt.log"

# Optional incident-specific cutoff.
# Empty ("") = use only the last firmware update + 30 minutes.
# For a new incident, only this line needs to be changed.
# The effective cutoff is always the LATEST of the firmware cutoff and this date.
SPECIAL_CUTOFF_DATE="2026-09-01 00:00:00"

# ---- build IOC tag without literal "[IOC]" in source ----
IOC_START='['
IOC_MID='IOC'
IOC_END=']'
IOC="${IOC_START}${IOC_MID}${IOC_END}"

# ---- Step 1: determine cutoff date ----
CUTOFF_TS=""
CUTOFF_DATE=""
NOW_TS=$(date "+%s")
CURRENT_YEAR=$(date "+%Y")

ADC_VER="/var/nsinstall/adc.version"
if [ -f "$ADC_VER" ]; then
    # adc.version exists -> use timestamp + 30 minutes
    RAW_TS=$(ls -lT "$ADC_VER" 2>/dev/null | awk '{print $6" "$7" "$8" "$9}')
    INSTALL_TS=$(date -j -f "%b %d %H:%M:%S %Y" "$RAW_TS" "+%s" 2>/dev/null || echo "")
    if [ -n "$INSTALL_TS" ]; then
        CUTOFF_TS=$((INSTALL_TS + 1800))
        CUTOFF_DATE=$(date -j -r "$CUTOFF_TS" "+%Y-%m-%d %H:%M:%S" 2>/dev/null)
    fi
fi

# ---- fallback to 30 days ago if adc.version does not exist or parsing fails ----
if [ -z "$CUTOFF_DATE" ] || [ -z "$CUTOFF_TS" ]; then
    CUTOFF_TS=$(date -v -30d "+%s" 2>/dev/null)
    CUTOFF_DATE=$(date -r "$CUTOFF_TS" "+%Y-%m-%d %H:%M:%S" 2>/dev/null)
fi

# ---- optional incident cutoff ----
# Never scan further back than necessary: the LATEST date wins.
if [ -n "$SPECIAL_CUTOFF_DATE" ]; then
    SPECIAL_CUTOFF_TS=$(date -j -f "%Y-%m-%d %H:%M:%S" "$SPECIAL_CUTOFF_DATE" "+%s" 2>/dev/null)
    if [ -n "$SPECIAL_CUTOFF_TS" ] && [ "$SPECIAL_CUTOFF_TS" -gt "$CUTOFF_TS" ]; then
        CUTOFF_TS="$SPECIAL_CUTOFF_TS"
        CUTOFF_DATE="$SPECIAL_CUTOFF_DATE"
    fi
fi

RUN_SEEN_IOC="/tmp/.ioc-seen-ioc.$"
RUN_SEEN_HUNT="/tmp/.ioc-seen-hunt.$"
: > "$RUN_SEEN_IOC"
: > "$RUN_SEEN_HUNT"
trap 'rm -f "$RUN_SEEN_IOC" "$RUN_SEEN_HUNT"' EXIT

trim_log() {
    FILE="$1"
    [ -f "$FILE" ] || return 0
    SIZE=$(wc -c < "$FILE" 2>/dev/null | tr -d ' ')
    [ -z "$SIZE" ] && return 0
    [ "$SIZE" -le 1048576 ] && return 0
    tail -c 786432 "$FILE" > "$FILE.tmp.$" 2>/dev/null && mv "$FILE.tmp.$" "$FILE"
}

log_ioc() {
    RAW="$1"
    grep -Fqx "$RAW" "$RUN_SEEN_IOC" 2>/dev/null && return 0
    echo "$RAW" >> "$RUN_SEEN_IOC"

    MSG="$(date '+%Y-%m-%d %H:%M:%S') - $RAW - Please forward to Harm Peter Millaard for further investigation!"
    logger "$IOC - $MSG"
    echo "$MSG" >> "$LOGFILE"
}

# Lower-confidence hunting output. Never sent to logger/syslog.
log_hunt() {
    RAW="$1"
    grep -Fqx "$RAW" "$RUN_SEEN_HUNT" 2>/dev/null && return 0
    echo "$RAW" >> "$RUN_SEEN_HUNT"

    echo "$(date '+%Y-%m-%d %H:%M:%S') - [HUNT] $RAW" >> "$HUNT_LOGFILE"
}

trim_log "$LOGFILE"
trim_log "$HUNT_LOGFILE"

# ---- IOC TESTS 1–50 ----

# [1] PHP files in multiple paths
for p in "/var/nsinstall" "/var/nsproflog" "/var/vpn" "/var/netscaler/logon" "/netscaler/portal"; do
    find "$p" -type f -iname '*.php' 2>/dev/null | while read -r F; do
        [ -z "$F" ] && continue
        log_ioc "[1] PHP file found: $F"
    done
done

# [2] PHP files excluding admin_ui
for p in "/netscaler/ns_gui" "/netscaler/gui" "/var/netscaler"; do
    find "$p" -type f -iname '*.php' -not -path '*/admin_ui/*' 2>/dev/null | while read -r F; do
        [ -z "$F" ] && continue
        log_ioc "[2] PHP file found (excluding admin_ui): $F"
    done
done

# [3] modified files in /var/netscaler/logon/
find /var/netscaler/logon/ -type f -newermt "$CUTOFF_DATE" \
  ! -iname '*.png' ! -iname '*.jpg' ! -iname '*.jpeg' ! -iname '*.js' ! -iname '*.json' ! -iname '*.css' \
  ! -iname '*.gif' ! -iname '*.ico' ! -iname '*.html' ! -iname '*.htm' ! -iname '*.xml' ! -iname '*.tar' \
  ! -iname '*.pl' ! -iname '*.list' ! -iname '*.ttf' ! -iname '*.woff' ! -iname '*.woff2' ! -iname '*.eot' \
  ! -iname '*.otf' ! -iname '*.svg' 2>/dev/null | while read -r F; do
    [ -z "$F" ] && continue
    log_ioc "[3] Modified file in /var/netscaler/logon: $F"
done

# [4] modified files in /var/python/ (local hunting only, max 10)
# Ignore interpreter bytecode/cache churn; retain real source/executable changes.
COUNT=0
find /var/python -newermt "$CUTOFF_DATE" -type f 2>/dev/null | \
grep -Ev '/__pycache__/|\.pyc$|\.pyo$' | \
while read -r F; do
    [ -z "$F" ] && continue
    DETAILS=$(ls -lT "$F" 2>/dev/null)
    [ -z "$DETAILS" ] && DETAILS="$F"
    log_hunt "[4] Modified file in /var/python: $DETAILS"
    COUNT=$((COUNT+1))
    [ "$COUNT" -ge 10 ] && break
done

# [5] Graceful entries in httperror.log
grep -H 'Graceful' /var/log/httperror.log 2>/dev/null | \
grep -v ':00:' | \
grep -v 'mpm_prefork:notice.*Graceful restart requested, doing restart' | \
while read -r L; do
    [ -z "$L" ] && continue
    log_hunt "[5] Graceful log entry found: $L"
done

# [6] Graceful entries in gzipped httperror logs
zgrep -h 'Graceful' /var/log/httperror.log.*.gz 2>/dev/null | \
grep -v ':00:' | \
grep -v 'mpm_prefork:notice.*Graceful restart requested, doing restart' | \
while read -r L; do
    [ -z "$L" ] && continue
    log_hunt "[6] Graceful entry in gzipped log: $L"
done

# [7] NSPPE cores
ls -al /var/core/NSPPE* 2>/dev/null | while read -r L; do
    [ -z "$L" ] && continue
    log_hunt "[7] NSPPE core found: $L"
done

# [8] .sh references in httperror.log*
zgrep -h --line-number '\.sh' /var/log/httperror.log* 2>/dev/null | while read -r L; do
    [ -z "$L" ] && continue
    log_hunt "[8] Shell reference in httperror.log: $L"
done

# [9] .pl references
zgrep -h --line-number '\.pl' /var/log/httperror.log* 2>/dev/null | while read -r L; do
    [ -z "$L" ] && continue
    log_hunt "[9] Perl reference in httperror.log: $L"
done

# [10] keywords in sh.log* with cutoff time
zgrep -h -E 'database.php|/flash/nsconfig/keys|/ns_gui/vpn|LDAPTLS_REQCERT|ldapsearch|openssl' /var/log/sh.log* 2>/dev/null | while read -r L; do
    [ -z "$L" ] && continue

    LOG_DATE=$(echo "$L" | awk '{print $1" "$2" "$3}')
    LOG_TS=$(date -j -f "%b %d %T %Y" "$LOG_DATE $CURRENT_YEAR" "+%s" 2>/dev/null)

    if [ -n "$LOG_TS" ] && [ "$LOG_TS" -gt "$NOW_TS" ]; then
        PREV_YEAR=$((CURRENT_YEAR - 1))
        LOG_TS=$(date -j -f "%b %d %T %Y" "$LOG_DATE $PREV_YEAR" "+%s" 2>/dev/null)
    fi

    [ -z "$LOG_TS" ] && continue
    [ "$LOG_TS" -le "$CUTOFF_TS" ] && continue
    log_ioc "[10] Keyword sh.log: $L"
done

# [11] keywords in bash.log*
for f in /var/log/bash.log /var/log/bash.log.*; do
    [ -f "$f" ] || continue
    case "$f" in
        *.gz)
            zgrep -h -E 'database.php|/flash/nsconfig/keys|/ns_gui/vpn|LDAPTLS_REQCERT|ldapsearch|openssl' "$f" 2>/dev/null
            ;;
        *)
            grep -h -E 'database.php|/flash/nsconfig/keys|/ns_gui/vpn|LDAPTLS_REQCERT|ldapsearch|openssl' "$f" 2>/dev/null
            ;;
    esac | grep -v 'shell_command' | head -200 | while read -r L; do
        [ -z "$L" ] && continue
        log_ioc "[11] Keyword bash.log: $L"
    done
done

# [12] processes running as nobody, excluding normal httpd workers
ps auxww 2>/dev/null | awk '$1=="nobody" && $11!="/bin/httpd"{print $0}' | while read -r L; do
    [ -z "$L" ] && continue
    log_ioc "[12] Process nobody: $L"
done

# [13] filtered crontab entries
grep -vE '^(#|SHELL=|PATH=|HOME=|^$)' /etc/crontab 2>/dev/null | \
grep -vE 'newsyslog|nslog.sh|iprep|custom_snmpd|pgrep -f /netscaler/appfw_dynamic_profiles|curl http://localhost|do_logexport|aslearn_health_monitor|auto_update_signatures|/netscaler/adss-licexp.sh|purge_tickets.sh|adjkerntz -a|nsfsyncd|scriptA.sh|scriptB.sh|scriptC.sh|/var/python/bin/python /netscaler/appfw_dynamic_profiles/appfw_dynamic_profiles.py|/netscaler/ns_cleanup.sh' | \
while read -r L; do
    [ -z "$L" ] && continue
    log_ioc "[13] Crontab entry: $L"
done

# [14] Python processes (filtered)
ps auxww 2>/dev/null | grep python | grep -v grep | \
grep -vF '/var/python/bin/python /var/python/bin/customsnmpd' | \
grep -vF '/var/mastools/scripts/' | \
grep -vF '/netscaler/do_logexport.py' | \
grep -vF '/netscaler/appfw_dynamic_profiles/appfw_dynamic_profiles.py' | \
grep -vE '/var/python/bin/python([0-9.]*)?[[:space:]]+-m[[:space:]]+pip[[:space:]]+install[[:space:]]+--no-deps[[:space:]]+/var/nextgen/infra/packages/' | \
while read -r L; do
    [ -z "$L" ] && continue
    log_hunt "[14] Python process: $L"
done

# [15] Perl processes
ps auxww 2>/dev/null | grep perl | grep -v grep | while read -r L; do
    [ -z "$L" ] && continue
    echo "$L" | grep -qE "/usr/bin/perl +/netscaler/auto_update_signatures( |$)" && continue
    echo "$L" | grep -qE "/usr/bin/perl +-w +/netscaler/monitors/(nssf|nsldap|nssmtp)\.pl( |$)" && continue
    log_hunt "[15] Perl process: $L"
done

# [16] suspicious shell/admin command traces in logs
# Do not treat arbitrary HTTP request paths ending in .php as a NetScaler IOC.
for f in /var/log/sh.log /var/log/bash.log /var/log/notice.log; do
    [ -f "$f" ] || continue
    grep -v '127\.0\.0\.1' "$f" 2>/dev/null | \
    grep -Ei '(^|[;&|[:space:]])nc[[:space:]].*-l|/etc/passwd|python[0-9.]*[[:space:]]+-c|(^|[;&|[:space:]])(curl|fetch|wget)[[:space:]].*https?://.*\|[[:space:]]*(sh|bash)|/dev/tcp/' | \
    grep -v 'iprep_curl_download' | \
    grep -v 'shell_command' | \
    grep -Ev '/nsconfig/scripts/(ioc|iocADM)\.sh' | \
    grep -v '\[IOC\]' | \
    while read -r L; do
        [ -z "$L" ] && continue
        log_ioc "[16] Suspicious shell/admin trace in $f: $L"
    done
done

# [17] setuid root files in /var since cutoff
find /var -perm -4000 -user root -not -path '/var/nslog/*' -newermt "$CUTOFF_DATE" 2>/dev/null | while read -r F; do
    [ -z "$F" ] && continue
    log_ioc "[17] Setuid root file: $F"
done

# [18] callhome_tmps files
find /var/tmp -type f -iname 'callhome_tmps*' 2>/dev/null | while read -r F; do
    [ -z "$F" ] && continue
    log_ioc "[18] callhome_tmps file: $F"
done

# [19] unexpected SUID files
find / -xdev -type f -perm -4000 -uid 0 2>/dev/null | while read -r F; do
    [ -z "$F" ] && continue
    case "$F" in
        /netscaler/ping|/netscaler/ping6|/netscaler/traceroute|/netscaler/traceroute6|/sbin/mksnap_ffs|/sbin/shutdown|/sbin/poweroff|/usr/bin/crontab|/usr/bin/lock|/usr/bin/login|/usr/bin/passwd|/usr/bin/su|/usr/libexec/ssh-keysign)
            :
            ;;
        *)
            log_ioc "[19] Unexpected SUID file: $F"
            ;;
    esac
done

# [20] rc.netscaler backdoor / reverse-shell check
grep -nE \
'nc[[:space:]].*-l|\
nc[[:space:]].*-e|\
ncat[[:space:]].*-l|\
ncat[[:space:]].*-e|\
netcat[[:space:]].*-l|\
netcat[[:space:]].*-e|\
socat[[:space:]].*(EXEC:|SYSTEM:|TCP-LISTEN:)|\
/dev/tcp/|\
bash[[:space:]]+-i|\
sh[[:space:]]+-i' \
/nsconfig/rc.netscaler 2>/dev/null | while read -r L; do
    [ -z "$L" ] && continue
    log_ioc "[20] rc.netscaler backdoor check: $L"
done

# [21] ProxyPass rules
grep -n "ProxyPass" /etc/httpd.conf 2>/dev/null | while read -r L; do
    [ -z "$L" ] && continue
    log_hunt "[21] ProxyPass rule: $L"
done

# [22] getAuthenticationRequirements modifications
grep -R --line-number "getAuthenticationRequirements" /netscaler/portal/templates/ 2>/dev/null | \
grep -v "expectedstring" | while read -r L; do
    [ -z "$L" ] && continue
    log_ioc "[22] getAuthenticationRequirements modification: $L"
done

# [23] suspicious headers in current and rotated httpaccess logs
for f in /var/log/httpaccess.log /var/log/httpaccess.log.*; do
    [ -f "$f" ] || continue
    case "$f" in
        *.gz) zgrep -h -E "X-Citrix-|X-Backdoor" "$f" 2>/dev/null ;;
        *)    grep -h -E "X-Citrix-|X-Backdoor" "$f" 2>/dev/null ;;
    esac | grep -v '127\.0\.0\.1' | while read -r L; do
        [ -z "$L" ] && continue
        log_ioc "[23] Suspicious header: $L"
    done
done

# [24] suspicious user-agents in current and rotated httpaccess logs
for f in /var/log/httpaccess.log /var/log/httpaccess.log.*; do
    [ -f "$f" ] || continue
    case "$f" in
        *.gz) zgrep -h -E "curl|wget|sqlmap|nmap" "$f" 2>/dev/null ;;
        *)    grep -h -E "curl|wget|sqlmap|nmap" "$f" 2>/dev/null ;;
    esac | grep -v '127\.0\.0\.1' | while read -r L; do
        [ -z "$L" ] && continue
        log_hunt "[24] Suspicious user-agent: $L"
    done
done

# [25] suspicious POST requests in current and rotated httpaccess logs
for f in /var/log/httpaccess.log /var/log/httpaccess.log.*; do
    [ -f "$f" ] || continue
    case "$f" in
        *.gz) zgrep -h "POST" "$f" 2>/dev/null ;;
        *)    grep -h "POST" "$f" 2>/dev/null ;;
    esac | grep -E "(/scripts/|/cgi-bin/|/vpn/\.\./)" | while read -r L; do
        [ -z "$L" ] && continue
        log_ioc "[25] Suspicious POST request: $L"
    done
done

# [26] additional PHP checks
for p in "/var/nsproflog" "/var/vpn" "/var/netscaler/logon"; do
    find "$p" -type f -iname '*.php' 2>/dev/null | while read -r F; do
        [ -z "$F" ] && continue
        log_ioc "[26] Additional PHP file found: $F"
    done
done

# [27] suspicious child processes started directly by httpd
HTTPD_PIDS=$(ps -axo pid=,command= 2>/dev/null | awk '$2=="/bin/httpd"{print $1}')

for PID in $HTTPD_PIDS; do
    ps -axo user=,pid=,ppid=,command= 2>/dev/null | awk -v P="$PID" '
        $3==P &&
        (
            $4=="/bin/sh" ||
            $4=="/bin/bash" ||
            $4=="/usr/bin/sh" ||
            $4=="/usr/bin/bash" ||
            $4=="/usr/bin/perl" ||
            $4=="/usr/local/bin/perl" ||
            $4=="/usr/bin/python" ||
            $4=="/usr/local/bin/python" ||
            $4=="/var/python/bin/python" ||
            $4=="/usr/bin/curl" ||
            $4=="/usr/local/bin/curl" ||
            $4=="/usr/bin/wget" ||
            $4=="/usr/local/bin/wget" ||
            $4=="/bin/nc" ||
            $4=="/usr/bin/nc" ||
            $4=="/usr/local/bin/nc" ||
            $4=="/usr/bin/ncat" ||
            $4=="/usr/local/bin/ncat" ||
            $4=="/usr/bin/socat" ||
            $4=="/usr/local/bin/socat"
        ) {
            print $0
        }
    '
done | while read -r L; do
    [ -z "$L" ] && continue
    log_ioc "[27] Suspicious child process of httpd: $L"
done

# [28] suspicious scripts/executables in writable temporary locations since cutoff
for p in "/tmp" "/var/tmp" "/var/nstmp"; do
    [ -d "$p" ] || continue
    find "$p" -xdev -type f -newermt "$CUTOFF_DATE" 2>/dev/null | while read -r F; do
        [ -z "$F" ] && continue
        case "$F" in
            /var/tmp/ns_system_backup.pl|\
            /var/tmp/support/*|\
            /var/tmp/nstrace/*|\
            /var/tmp/Mellanox/*|\
            /var/tmp/Fortville_Silicom_Intel/*|\
            /var/tmp/par-*/cache-*/*|\
            /var/tmp/.*)
                continue
                ;;
        esac
        case "$F" in
            *.php|*.pl|*.py|*.sh|*.cgi)
                log_hunt "[28] Script in temporary location since cutoff: $F"
                continue
                ;;
        esac
        [ -x "$F" ] && log_hunt "[28] Executable in temporary location since cutoff: $F"
    done
done

# [29] suspicious listening processes: shell/interpreter/netcat-like tools
if command -v sockstat >/dev/null 2>&1; then
    sockstat -46 -l 2>/dev/null | \
    grep -Ei '(^|[[:space:]])(sh|bash|perl|python|python[0-9.]*|nc|ncat|netcat|socat)([[:space:]]|$)' | \
    grep -Ev '127\.0\.0\.1[: ]|::1[: ]' | \
    while read -r L; do
        [ -z "$L" ] && continue
        log_hunt "[29] Suspicious listening process: $L"
    done
fi

# [30] additional persistence check on rc.netscaler
grep -nE \
'nc[[:space:]].*(-l|-e)|ncat[[:space:]].*(-l|-e)|netcat[[:space:]].*(-l|-e)|socat[[:space:]].*(EXEC:|SYSTEM:|TCP-LISTEN:)|/dev/tcp/|bash[[:space:]]+-i|sh[[:space:]]+-i|curl[[:space:]]+https?://|wget[[:space:]]+https?://' \
/nsconfig/rc.netscaler 2>/dev/null | while read -r L; do
    [ -z "$L" ] && continue
    log_ioc "[30] Suspicious persistence in rc.netscaler: $L"
done


# [31] recently introduced XHTML files in NetScaler web roots
for p in "/var/netscaler/logon" "/var/vpn" "/netscaler/ns_gui" "/var/netscaler/gui" "/netscaler/portal"; do
    [ -d "$p" ] || continue
    find "$p" -type f -iname '*.xhtml' -newermt "$CUTOFF_DATE" 2>/dev/null | while read -r F; do
        [ -z "$F" ] && continue
        case "$F" in
            */admin_ui/*) continue ;;
        esac
        log_hunt "[31] XHTML file created or modified since cutoff: $F"
    done
done

# [32] suspicious NetScaler GUI package/signature artifacts
for p in "/var/netscaler/gui" "/netscaler/ns_gui"; do
    [ -d "$p" ] || continue

    find "$p" -type f \( -iname 'nsginstaller.deb' -o -iname 'nsgclient18.deb' \) 2>/dev/null | while read -r F; do
        [ -z "$F" ] && continue
        log_ioc "[32] Suspicious GUI package artifact: $F"
    done

    find "$p" -type f -iname '*.sig' -newermt "$CUTOFF_DATE" 2>/dev/null | while read -r F; do
        [ -z "$F" ] && continue
        log_ioc "[32] Recently modified GUI signature file: $F"
    done
done

# [33] Apache configuration tampering related to PHP execution or disabled hardening
for CFG in /etc/httpd.conf /nsconfig/httpd.conf; do
    [ -f "$CFG" ] || continue

    awk '
        {
            raw=$0
            line=tolower($0)
        }
        line ~ /^[[:space:]]*#/ {
            sub(/^[[:space:]]*#[[:space:]]*/, "", line)
            if (line ~ /^require[[:space:]]+all[[:space:]]+denied([[:space:]]|$)/ ||
                line ~ /^php_flag[[:space:]]+engine[[:space:]]+off([[:space:]]|$)/) {
                print NR ":" raw
            }
            next
        }
        {
            if (line ~ /addhandler[[:space:]]+application\/x-httpd-php([[:space:]]|$)/) {
                print NR ":" raw
            }
        }
    ' "$CFG" 2>/dev/null | while read -r L; do
        [ -z "$L" ] && continue
        log_ioc "[33] Suspicious Apache configuration in $CFG: $L"
    done
done

# [34] targeted web-log artifacts associated with dropped payloads or encoded PHP
for f in /var/log/httpaccess.log /var/log/httpaccess.log.* /var/log/httperror.log /var/log/httperror.log.*; do
    [ -f "$f" ] || continue

    case "$f" in
        *.gz) READER="zcat" ;;
        *)    READER="cat" ;;
    esac

    $READER "$f" 2>/dev/null | awk '
        {
            low=tolower($0)
            if (low ~ /nsginstaller\.deb/ ||
                low ~ /nsgclient/ ||
                $0 ~ /PD9waHAg/ ||
                $0 ~ /PD9waHAK/ ||
                low ~ /[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]\.ico/ ||
                low ~ /[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]\/[^[:space:]]*\.sig/) {
                print
            }
        }
    ' | while read -r L; do
        [ -z "$L" ] && continue
        log_ioc "[34] Targeted web-log artifact in $f: $L"
    done
done

# [35] suspicious pitboss-related exploit attempts in NetScaler logs
# Alert once per unique malicious payload/source instead of every AAAD/AAA log line.
for f in /var/log/ns.log /var/log/ns.log.*; do
    [ -f "$f" ] || continue

    case "$f" in
        *.gz) READER="zcat" ;;
        *)    READER="cat" ;;
    esac

    $READER "$f" 2>/dev/null | awk '
        {
            low=tolower($0)

            if (low !~ /pitboss/ || low !~ /nsppe/) {
                next
            }

            if (low ~ /bash\$\{ifs\}|\/dev\/tcp\//) {
                type="reverse-shell"
            } else if (low ~ /nohup\$\{ifs\}fetch|fetch\$\{ifs\}-qo-|\|sh/) {
                type="fetch-pipe-shell"
            } else {
                next
            }

            ip=""
            if (match($0, /Client_ip[[:space:]]+[0-9.]+/)) {
                ip=substr($0, RSTART, RLENGTH)
                sub(/^Client_ip[[:space:]]+/, "", ip)
            }

            key=type "|" ip
            if (!seen[key]++) {
                print type "|" ip "|" $0
            }
        }
    ' | while IFS='|' read -r TYPE SRC L; do
        [ -z "$L" ] && continue
        if [ -n "$SRC" ]; then
            log_ioc "[35] Active exploit attempt detected ($TYPE) from $SRC in $f: $L"
        else
            log_ioc "[35] Active exploit attempt detected ($TYPE) in $f: $L"
        fi
    done
done

# [36] unexpected files opened by Packet Engine processes
if command -v lsof >/dev/null 2>&1; then
    lsof -VRPn 2>/dev/null | awk '
        /NSPPE/ &&
        ($0 ~ /\/var\/netscaler\// || tolower($0) ~ /callhome/) {
            print
        }
    ' | while read -r L; do
        [ -z "$L" ] && continue
        log_hunt "[36] Packet Engine has suspicious file open: $L"
    done
fi

# [37] evidence-removal attempts targeting core files
for f in /var/log/notice.log /var/log/notice.log.* /var/log/sh.log /var/log/sh.log.* /var/log/bash.log /var/log/bash.log.*; do
    [ -f "$f" ] || continue

    case "$f" in
        *.gz) READER="zcat" ;;
        *)    READER="cat" ;;
    esac

    $READER "$f" 2>/dev/null | awk '
        {
            low=tolower($0)
            if (low ~ /(^|[;&|[:space:]])rm([[:space:]]|$)/ &&
                low ~ /\/var\/core/ &&
                (low ~ /\*/ || low ~ /-[[:alnum:]]*r[[:alnum:]]*/)) {
                print
            }
        }
    ' | while read -r L; do
        [ -z "$L" ] && continue
        log_ioc "[37] Possible core-file evidence removal in $f: $L"
    done
done

# [38] malformed authentication/protocol log data suggesting memory disclosure/overread
# This intentionally uses generalized byte/content anomaly detection rather than exploit-specific signatures.
for f in /var/log/ns.log /var/log/ns.log.*; do
    [ -f "$f" ] || continue

    case "$f" in
        *.gz) READER="zcat" ;;
        *)    READER="cat" ;;
    esac

    $READER "$f" 2>/dev/null | perl -ne '
        next unless /(?:WSFed:\s*request_id|acs=)/i;

        $line = $_;
        $non_ascii = ($line =~ /[^\x09\x0a\x0d\x20-\x7e]/);

        $caret_count = () = ($line =~ /\^/g);
        $odd_delimiters = (/WSFed:\s*request_id/i && $caret_count >= 2);

        if ($non_ascii || $odd_delimiters) {
            print $_;
        }
    ' | while read -r L; do
        [ -z "$L" ] && continue
        log_hunt "[38] Malformed authentication/protocol data in $f: $L"
    done
done

# Extend the SUID search to flash storage for incident-era changes.
find /flash -type f -user root -newermt "$CUTOFF_DATE" \( -perm -4001 -o -perm -4010 \) 2>/dev/null | while read -r F; do
    [ -z "$F" ] && continue
    log_ioc "[17] Setuid root file in /flash since cutoff: $F"
done

# Extend persistence detection with interpreter execution from rc.netscaler.
for CFG in /nsconfig/rc.netscaler /flash/nsconfig/rc.netscaler; do
    [ -f "$CFG" ] || continue
    grep -nEi '(^|[;&|[:space:]])(python|python[0-9.]*)([[:space:]]|$)' "$CFG" 2>/dev/null | while read -r L; do
        [ -z "$L" ] && continue
        log_ioc "[30] Python persistence in $CFG: $L"
    done
done


# [39] campaign-specific command/control header indicators in web logs
for f in /var/log/httpaccess.log /var/log/httpaccess.log.* /var/log/httperror.log /var/log/httperror.log.*; do
    [ -f "$f" ] || continue
    case "$f" in
        *.gz) READER="zcat" ;;
        *)    READER="cat" ;;
    esac
    $READER "$f" 2>/dev/null | grep -Ei \
    'HTTP_NSC_LDAP|HTTP_NSC_CLIENTTYPE|HTTP_X_UX(_[0-9]+)?|NSC_LDAP|NSC_CLIENTTYPE|X_UX_[0-9]+' | \
    while read -r L; do
        [ -z "$L" ] && continue
        log_ioc "[39] NetScaler web-shell C2 header indicator in $f: $L"
    done
done

# [40] SLAPSHOT IPC artifacts and matching Python runtime
for F in /tmp/.uxdport /tmp/.uxdport.* /tmp/.uxdlock /tmp/.uxdlock.*; do
    [ -e "$F" ] || continue
    log_ioc "[40] SLAPSHOT IPC artifact found: $F"
done

ps auxww 2>/dev/null | grep -Ei 'python.*(\.uxdport|\.uxdlock|base64.*exec|exec.*base64)' | grep -v grep | while read -r L; do
    [ -z "$L" ] && continue
    log_ioc "[40] Suspicious Python proxy/loader process: $L"
done

# [41] Base64 exploit payloads staged in HTTP User-Agent / INDEX fields
for f in /var/log/httpaccess.log /var/log/httpaccess.log.*; do
    [ -f "$f" ] || continue
    case "$f" in
        *.gz) READER="zcat" ;;
        *)    READER="cat" ;;
    esac
    $READER "$f" 2>/dev/null | grep -E \
    'INDEX:[A-Za-z0-9+/]{20,}={0,2}|User-Agent:.*[A-Za-z0-9+/]{40,}={0,2}' | \
    while read -r L; do
        [ -z "$L" ] && continue
        log_ioc "[41] Base64 payload pattern in HTTP log $f: $L"
    done
done

# [42] unauthorized setuid shell persistence
for F in /bin/sh /var/tmp/sh; do
    [ -e "$F" ] || continue
    if [ -u "$F" ]; then
        DETAILS=$(ls -lT "$F" 2>/dev/null)
        log_ioc "[42] Setuid shell detected: $DETAILS"
    fi
done

# [43] Apache execution/persistence mappings that should not exist in a stock configuration
for CFG in /etc/httpd.conf /nsconfig/httpd.conf /flash/nsconfig/httpd.conf /nsconfig/https.conf; do
    [ -f "$CFG" ] || continue
    grep -nEi \
    '^[[:space:]]*php_flag[[:space:]]+engine[[:space:]]+on|^[[:space:]]*(Alias|AliasMatch|RewriteRule)[[:space:]].*(/tmp/|/var/tmp/|/var/nstmp/)|^[[:space:]]*SetEnvIf[[:space:]].*(X_UX|HTTP_X_UX)' \
    "$CFG" 2>/dev/null | while read -r L; do
        [ -z "$L" ] && continue
        log_ioc "[43] Suspicious Apache execution/persistence mapping in $CFG: $L"
    done
done

# [44] non-PHP extensions configured for PHP execution with matching web files
for CFG in /etc/httpd.conf /nsconfig/httpd.conf /flash/nsconfig/httpd.conf; do
    [ -f "$CFG" ] || continue
    grep -Ei '^[[:space:]]*(AddHandler|AddType)[[:space:]]+application/x-httpd-php' "$CFG" 2>/dev/null | \
    grep -oE '\.[A-Za-z0-9]+' | grep -Ev '^\.(php|phps)$' | sort -u | while read -r EXT; do
        [ -z "$EXT" ] && continue
        for ROOT in /var/netscaler /netscaler/ns_gui /netscaler/portal /var/vpn; do
            [ -d "$ROOT" ] || continue
            find "$ROOT" -type f -iname "*$EXT" 2>/dev/null | while read -r F; do
                [ -z "$F" ] && continue
                log_ioc "[44] File uses nonstandard PHP-enabled extension $EXT: $F"
            done
        done
    done
done

# [45] DTLS / Packet Engine crash indicators (local hunting only)
for f in /var/log/ns.log /var/log/ns.log.* /var/log/messages /var/log/messages.*; do
    [ -f "$f" ] || continue
    case "$f" in
        *.gz) READER="zcat" ;;
        *)    READER="cat" ;;
    esac
    $READER "$f" 2>/dev/null | grep -Ei 'SSL_HANDSHAKE_FAILURE.*DTLS|DTLS.*SSL_HANDSHAKE_FAILURE' | head -5 | while read -r L; do
        [ -z "$L" ] && continue
        log_hunt "[45] DTLS handshake failure in $f: $L"
    done
    $READER "$f" 2>/dev/null | grep -Ei 'NSPPE.*(terminated|abort|crash)|pitboss.*NOT restarting NSPPE|PPE NSPPE missed too many heartbeats' | head -10 | while read -r L; do
        [ -z "$L" ] && continue
        log_hunt "[45] Packet Engine failure/restart indicator in $f: $L"
    done
done

# [46] recently introduced campaign-like web artifacts (local hunting only)
for ROOT in /netscaler/ns_gui /var/netscaler /var/vpn /netscaler/portal; do
    [ -d "$ROOT" ] || continue
    find "$ROOT" -type f -newermt "$CUTOFF_DATE" \( \
        -iname '.ctxs.receiver' -o \
        -iname 'receiver.min*.css' -o \
        -iname 'insight-new.js' -o \
        -iname 'nsginstaller*.deb' -o \
        -iname 'nsgclient*.deb' -o \
        -iname 'nsgclient*.sig' \
    \) 2>/dev/null | while read -r F; do
        [ -z "$F" ] && continue
        case "$F" in
            /var/netscaler/gui/vpn/scripts/linux/nsginstaller*.deb|\
            /var/netscaler/gui/vpn/scripts/linux/nsgclient*.deb|\
            /var/netscaler/gui/vpn/scripts/linux/nsgclient*.sig)
                continue
                ;;
        esac
        log_hunt "[46] Recently introduced campaign-like web artifact: $F"
    done
done

# [47] obvious local logging anomalies (local hunting only)
for F in /var/log/httpaccess.log /var/log/httperror.log /var/log/ns.log; do
    if [ ! -e "$F" ]; then
        log_hunt "[47] Expected current log file is missing: $F"
        continue
    fi
    SIZE=$(wc -c < "$F" 2>/dev/null | tr -d ' ')
    [ -n "$SIZE" ] && [ "$SIZE" -eq 0 ] && log_hunt "[47] Expected current log file is empty: $F"
done

# [48] non-loopback sockets owned by interpreters/tunneling tools (local hunting only)
if command -v sockstat >/dev/null 2>&1; then
    sockstat -46 2>/dev/null | \
    grep -Ei '(^|[[:space:]])(python|python[0-9.]*|perl|sh|bash|nc|ncat|netcat|socat)([[:space:]]|$)' | \
    grep -Ev '127\.0\.0\.1[: ]|::1[: ]' | \
    while read -r L; do
        [ -z "$L" ] && continue
        log_hunt "[48] Interpreter/tunneling process has non-loopback socket: $L"
    done
fi

# [49] execution/persistence commands in shell and notice logs
# Prefilter aggressively before parsing shell_command so large logs do not get
# processed line-by-line with multiple subprocesses.
for f in /var/log/sh.log /var/log/sh.log.* /var/log/bash.log /var/log/bash.log.* /var/log/notice.log /var/log/notice.log.*; do
    [ -f "$f" ] || continue
    case "$f" in
        *.gz) READER="zcat" ;;
        *)    READER="cat" ;;
    esac

    $READER "$f" 2>/dev/null |     grep 'shell_command="' |     grep -Ei 'chmod[[:space:]]+u\+s[[:space:]]+/bin/sh|python[0-9.]*[[:space:]].*base64.*exec|/bin/httpd[[:space:]]+-k[[:space:]]+restart|nsshutdown[[:space:]]+-R|/etc/crontab|/nsconfig/rc\.netscaler' |     grep -Ev 'iocADM|log_ioc|log_hunt|custom_snmpd\.py|customsnmpd|ctrap\.sh|shell_command="(echo|printf)[[:space:]].*grep|shell_command=".*(grep|egrep|fgrep|zgrep)[[:space:]]+-' |     while read -r L; do
        [ -z "$L" ] && continue

        CMD=$(printf '%s\n' "$L" | sed -n 's/.*shell_command="\(.*\)"[[:space:]]*$/\1/p')
        [ -z "$CMD" ] && continue

        if printf '%s\n' "$CMD" | grep -Eqi '(^|[;&|[:space:]])chmod[[:space:]]+u\+s[[:space:]]+/bin/sh([;&|[:space:]]|$)|(^|[;&|[:space:]])python[0-9.]*[[:space:]].*base64.*exec'; then
            log_ioc "[49] High-confidence persistence/execution command in $f: $L"
            continue
        fi

        if printf '%s\n' "$CMD" | grep -Eqi '(^|[;&|[:space:]])/bin/httpd[[:space:]]+-k[[:space:]]+restart([;&|[:space:]]|$)|(^|[;&|[:space:]])nsshutdown[[:space:]]+-R([;&|[:space:]]|$)|(/etc/crontab|/nsconfig/rc\.netscaler).*(sed|perl|rm)'; then
            log_hunt "[49] Persistence-related administrative command in $f: $L"
        fi
    done
done

# [50] multi-signal web-shell behavior in small web-accessible files
# Standard NetScaler templates legitimately contain NSC_LDAP / NSC_CLIENTTYPE
# variables. Only campaign-specific markers escalate directly to IOC.
for ROOT in /netscaler/ns_gui /var/netscaler/logon /var/netscaler/gui /netscaler/portal /var/vpn; do
    [ -d "$ROOT" ] || continue
    find "$ROOT" -type f \( \
        -iname '*.php' -o -iname '*.sig' -o -iname '*.deb' -o -iname '*.css' -o \
        -iname '*.ico' -o -iname '*.js' -o -iname '*.xhtml' -o -iname '*.html' \
    \) 2>/dev/null | while read -r F; do
        [ -f "$F" ] || continue

        case "$F" in
            */admin_ui/*) continue ;;
        esac

        SIZE=$(wc -c < "$F" 2>/dev/null | tr -d ' ')
        [ -z "$SIZE" ] && continue
        [ "$SIZE" -gt 262144 ] && continue

        STRONG=$(grep -Eio \
        'HTTP_X_UX(_[0-9]+)?|X_UX_[0-9]+|/tmp/\.uxd(port|lock)|chmod[[:space:]]+u\+s[[:space:]]+/bin/sh' \
        "$F" 2>/dev/null | sort -u | head -10)

        WEAK=$(grep -Eio \
        'HTTP_NSC_LDAP|HTTP_NSC_CLIENTTYPE' \
        "$F" 2>/dev/null | sort -u | head -10)

        GENERIC=$(grep -Eio \
        'base64_decode[[:space:]]*\(|shell_exec[[:space:]]*\(|fsockopen[[:space:]]*\(|http_response_code[[:space:]]*\([[:space:]]*404[[:space:]]*\)' \
        "$F" 2>/dev/null | sort -u | head -10)

        STRONG_COUNT=$(printf '%s\n' "$STRONG" | grep -c . 2>/dev/null)
        WEAK_COUNT=$(printf '%s\n' "$WEAK" | grep -c . 2>/dev/null)
        GENERIC_COUNT=$(printf '%s\n' "$GENERIC" | grep -c . 2>/dev/null)

        if [ -n "$STRONG_COUNT" ] && [ "$STRONG_COUNT" -ge 1 ]; then
            log_ioc "[50] Campaign-specific web-shell marker in $F: $(printf '%s %s %s' "$STRONG" "$WEAK" "$GENERIC" | tr '\n' ' ')"
            continue
        fi

        if [ -n "$WEAK_COUNT" ] && [ "$WEAK_COUNT" -ge 1 ] && \
           [ -n "$GENERIC_COUNT" ] && [ "$GENERIC_COUNT" -ge 1 ] && \
           [ "$F" -nt "/var/nsinstall/adc.version" ]; then
            log_hunt "[50] Recently modified web file combines NetScaler header variables with web-shell-capable functions: $F: $(printf '%s %s' "$WEAK" "$GENERIC" | tr '\n' ' ')"
            continue
        fi

        if [ -n "$GENERIC_COUNT" ] && [ "$GENERIC_COUNT" -ge 2 ] && [ "$F" -nt "/var/nsinstall/adc.version" ]; then
            log_hunt "[50] Recently modified web file contains multiple generic web-shell-capable functions: $F: $(printf '%s' "$GENERIC" | tr '\n' ' ')"
        fi
    done
done


trim_log "$LOGFILE"
trim_log "$HUNT_LOGFILE"
exit 0
