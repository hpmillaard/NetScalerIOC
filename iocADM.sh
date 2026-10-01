#!/usr/bin/bash
# iocADM.sh - IOC scanner for NetScaler / NetScaler Console (production)
# add audit messageaction IOC WARNING "\"[IOC]\""

LOGFILE="/nsconfig/scripts/iocADM.log"

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

log_ioc() {
    MSG="$1"
    MSG="$(date '+%Y-%m-%d %H:%M:%S') - $MSG - Please forward to Harm Peter Millaard for further investigation!"
    logger "$IOC - $MSG"
    echo "$MSG" >> "$LOGFILE"
}


# ---- IOC TESTS 1–38 ----

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

# [4] modified files in /var/python/ (max 10)
COUNT=0
find /var/python -newermt "$CUTOFF_DATE" -type f -exec ls -lT {} + 2>/dev/null | while read -r F; do
    [ -z "$F" ] && continue
    log_ioc "[4] Modified file in /var/python: $F"
    COUNT=$((COUNT+1))
    [ "$COUNT" -ge 10 ] && break
done

# [5] Graceful entries in httperror.log
grep -H 'Graceful' /var/log/httperror.log 2>/dev/null | \
grep -v ':00:' | \
grep -v 'mpm_prefork:notice.*Graceful restart requested, doing restart' | \
while read -r L; do
    [ -z "$L" ] && continue
    log_ioc "[5] Graceful log entry found: $L"
done

# [6] Graceful entries in gzipped httperror logs
zgrep -h 'Graceful' /var/log/httperror.log.*.gz 2>/dev/null | \
grep -v ':00:' | \
grep -v 'mpm_prefork:notice.*Graceful restart requested, doing restart' | \
while read -r L; do
    [ -z "$L" ] && continue
    log_ioc "[6] Graceful entry in gzipped log: $L"
done

# [7] NSPPE cores
ls -al /var/core/NSPPE* 2>/dev/null | while read -r L; do
    [ -z "$L" ] && continue
    log_ioc "[7] NSPPE core found: $L"
done

# [8] .sh references in httperror.log*
zgrep -h --line-number '\.sh' /var/log/httperror.log* 2>/dev/null | while read -r L; do
    [ -z "$L" ] && continue
    log_ioc "[8] Shell reference in httperror.log: $L"
done

# [9] .pl references
zgrep -h --line-number '\.pl' /var/log/httperror.log* 2>/dev/null | while read -r L; do
    [ -z "$L" ] && continue
    log_ioc "[9] Perl reference in httperror.log: $L"
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
while read -r L; do
    [ -z "$L" ] && continue
    log_ioc "[14] Python process: $L"
done

# [15] Perl processes
ps auxww 2>/dev/null | grep perl | grep -v grep | while read -r L; do
    [ -z "$L" ] && continue
    echo "$L" | grep -qE "/usr/bin/perl +/netscaler/auto_update_signatures( |$)" && continue
    log_ioc "[15] Perl process: $L"
done

# [16] suspicious commands in logs
grep -v '127\.0\.0\.1' /var/log/*.log 2>/dev/null | \
grep -E 'nc -l|/etc/passwd|python -c|\.php' | \
grep -v 'iprep_curl_download' | \
grep -v 'shell_command' | \
grep -v '\[IOC\]' | \
while read -r L; do
    [ -z "$L" ] && continue
    log_ioc "[16] Suspicious command in log: $L"
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
    log_ioc "[21] ProxyPass rule: $L"
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
        log_ioc "[24] Suspicious user-agent: $L"
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
            /var/tmp/ns_system_backup.pl|/var/tmp/support/*|/var/tmp/nstrace/*|/var/tmp/.*) continue ;;
        esac
        case "$F" in
            *.php|*.pl|*.py|*.sh|*.cgi)
                log_ioc "[28] Script in temporary location since cutoff: $F"
                continue
                ;;
        esac
        [ -x "$F" ] && log_ioc "[28] Executable in temporary location since cutoff: $F"
    done
done

# [29] suspicious listening processes: shell/interpreter/netcat-like tools
if command -v sockstat >/dev/null 2>&1; then
    sockstat -46 -l 2>/dev/null | \
    grep -Ei '(^|[[:space:]])(sh|bash|perl|python|python[0-9.]*|nc|ncat|netcat|socat)([[:space:]]|$)' | \
    while read -r L; do
        [ -z "$L" ] && continue
        log_ioc "[29] Suspicious listening process: $L"
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
        log_ioc "[31] XHTML file created or modified since cutoff: $F"
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
        BEGIN { IGNORECASE=1 }
        /^[[:space:]]*#/ {
            line=$0
            sub(/^[[:space:]]*#[[:space:]]*/, "", line)
            if (line ~ /^Require[[:space:]]+all[[:space:]]+denied([[:space:]]|$)/ ||
                line ~ /^php_flag[[:space:]]+engine[[:space:]]+off([[:space:]]|$)/) {
                print NR ":" $0
            }
            next
        }
        {
            if ($0 ~ /AddHandler[[:space:]]+application\/x-httpd-php([[:space:]]|$)/) {
                print NR ":" $0
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
        BEGIN { IGNORECASE=1 }
        /nsginstaller\.deb/ ||
        /nsgclient/ ||
        /PD9waHAg/ ||
        /PD9waHAK/ ||
        /[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]\.ico/ ||
        /[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]\/[^[:space:]]*\.sig/ {
            print
        }
    ' | while read -r L; do
        [ -z "$L" ] && continue
        log_ioc "[34] Targeted web-log artifact in $f: $L"
    done
done

# [35] suspicious pitboss-related activity in NetScaler logs
for f in /var/log/ns.log /var/log/ns.log.*; do
    [ -f "$f" ] || continue

    case "$f" in
        *.gz) READER="zcat" ;;
        *)    READER="cat" ;;
    esac

    $READER "$f" 2>/dev/null | awk '
        BEGIN { IGNORECASE=1 }
        /pitboss/ && (/IFS/ || (/AAATM/ && /PPE/)) { print }
    ' | while read -r L; do
        [ -z "$L" ] && continue
        log_ioc "[35] Suspicious pitboss-related log entry in $f: $L"
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
        log_ioc "[36] Packet Engine has suspicious file open: $L"
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
        BEGIN { IGNORECASE=1 }
        /(^|[;&|[:space:]])rm([[:space:]]|$)/ &&
        /\/var\/core/ &&
        (/\*/ || /-[[:alnum:]]*r[[:alnum:]]*/) {
            print
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
        log_ioc "[38] Malformed authentication/protocol data in $f: $L"
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


exit 0
