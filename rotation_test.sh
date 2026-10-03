#!/bin/bash

# ==============================================================================
#  ___ _  _ ___   _   _  _ ___ _______   __  ___ ___ ___ _   _ ___ ___ _______   
# |_ _| \| / __| /_\ | \| |_ _|_   _\ \ / / / __| __/ __| | | | _ \_ _|_   _\ \ / /
#  | || .  \__ \/ _ \| .  || |  | |  \ V /  \__ \ _| (__| |_| |   /| |  | |  \ V / 
# |___|_|\_|___/_/   \_\_|\___| |_|   |_|   |___/___\___|\___/|_|_\___| |_|   |_|  
#                                                                                
#  Tool     : Proxy Rotation Tester v2 (IP + State only)
#  Author   : Anthony Abella https://github.com/ArchangelAzazil
#  Division : Insanity Security (Infrastructure & Offensive Research)
#  Features : SIGINT-safe summary, automated proxy classification (407/429/000)
# ==============================================================================


show_banner() {
    echo -e "\e[1;31m" # Switch to bold red
    echo "    ========================================================"
    echo "       ___ _  _ ___   _   _  _ ___ _______   __ "
    echo "      |_ _| \| / __| /_\ | \| |_ _|_   _\ \ / / "
    echo "       | || .  \__ \/ _ \| .  || |  | |  \ V /  "
    echo "      |___|_|\_|___/_/   \_\_|\___| |_|   |_|   "
    echo "                   S  E  C  U  R  I  T  Y"
    echo "    ========================================================"
    echo -e "    \e[0m" # Reset colors
    echo -e "    \e[1;30m   Author:\e[0m Anthony Abella"
    echo -e "    \e[1;30m   Target:\e[0m ${PROTOCOL^^} Proxy Infrastructure Pipeline"
    echo "    ========================================================"
    echo ""
}


# Usage
if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
    echo "Usage: ./test_rotation.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --once              Check IP once and exit"
    echo "  --sticky            Quick stickiness test (5 requests, 5 sec apart)"
    echo "  --duration MINUTES  Run for X minutes (default: 30)"
    echo "  --interval SECONDS  Check every X seconds (default: 60)"
    echo "  --help              Show this help message"
    echo ""
    echo "Example: ./test_rotation.sh --duration 60 --interval 30"
    exit 0
fi

# Defaults
DURATION=30  # minutes
INTERVAL=60  # seconds
ONCE_MODE=false
STICKY_MODE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --once)
            ONCE_MODE=true
            shift
            ;;
        --sticky)
            STICKY_MODE=true
            shift
            ;;
        --duration)
            DURATION="$2"
            shift 2
            ;;
        --interval)
            INTERVAL="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage."
            exit 1
            ;;
    esac
done

# Validate numeric args — bad input here breaks arithmetic mid-run, not at parse time
if ! [[ "$DURATION" =~ ^[0-9]+$ ]] || [ "$DURATION" -eq 0 ]; then
    echo "❌ --duration must be a positive integer (got: $DURATION)"
    exit 1
fi
if ! [[ "$INTERVAL" =~ ^[0-9]+$ ]] || [ "$INTERVAL" -eq 0 ]; then
    echo "❌ --interval must be a positive integer (got: $INTERVAL)"
    exit 1
fi

# Prompt for proxy details
echo "🔐 Enter proxy credentials and endpoint"
echo "Format: [protocol://]user:pass@host:port"
echo "Examples:"
echo "  http://user:pass@proxy.com:8080"
echo "  user:pass@proxy.com:8080  (defaults to HTTP)"
echo "  socks5://user:pass@proxy.com:1080"
read -p "Proxy: " PROXY_INPUT

# Auto-detect protocol
if [[ "$PROXY_INPUT" =~ ^(http|https|socks5|socks4):// ]]; then
    # Protocol already specified — extract and use as-is
    PROTOCOL=$(echo "$PROXY_INPUT" | cut -d':' -f1)
    PROXY_URL="$PROXY_INPUT"
    echo "✅ Detected protocol: ${PROTOCOL^^}"
else
    # No protocol — default to HTTP
    PROXY_URL="http://${PROXY_INPUT}"
    PROTOCOL="http"
    echo "✅ No protocol detected — defaulting to HTTP"
fi

LOG_FILE="rotation_test_$(date +%Y%m%d_%H%M%S).log"

# ============================================
# SHARED: request + classification
# ============================================
# Fires one check, populates globals: IP, STATE, HTTP_CODE, RESULT_CLASS
# RESULT_CLASS one of: OK, AUTH_FAIL, RATE_LIMITED, CONN_FAIL, HTTP_ERR
do_check() {
    local RAW
    RAW=$(curl -s -x "$PROXY_URL" \
        --connect-timeout 10 \
        --max-time 15 \
        -w '\n%{http_code}' \
        https://ipinfo.io/json 2>/dev/null)

    HTTP_CODE=$(echo "$RAW" | tail -n1)
    BODY=$(echo "$RAW" | sed '$d')

    case "$HTTP_CODE" in
        200)
            if [ -z "$BODY" ] || [ "$BODY" == "null" ]; then
                RESULT_CLASS="CONN_FAIL"
                IP="FAILED"; STATE="FAILED"
                return
            fi
            RESULT_CLASS="OK"
            if command -v jq &> /dev/null; then
                IP=$(echo "$BODY" | jq -r '.ip // "unknown"')
                STATE=$(echo "$BODY" | jq -r '.region // "unknown"')
            else
                IP=$(echo "$BODY" | grep -o '"ip":"[^"]*"' | cut -d'"' -f4)
                STATE=$(echo "$BODY" | grep -o '"region":"[^"]*"' | cut -d'"' -f4)
            fi
            ;;
        407)
            RESULT_CLASS="AUTH_FAIL"
            IP="AUTH_FAIL"; STATE="AUTH_FAIL"
            ;;
        429)
            RESULT_CLASS="RATE_LIMITED"
            IP="RATE_LIMITED"; STATE="RATE_LIMITED"
            ;;
        000)
            RESULT_CLASS="CONN_FAIL"
            IP="FAILED"; STATE="FAILED"
            ;;
        *)
            RESULT_CLASS="HTTP_ERR"
            IP="HTTP_$HTTP_CODE"; STATE="HTTP_$HTTP_CODE"
            ;;
    esac
}

# Human-readable line for a classified result
describe_result() {
    case "$RESULT_CLASS" in
        OK)            echo "$IP - $STATE" ;;
        AUTH_FAIL)     echo "🔒 407 AUTH FAILURE — bad/expired session string or creds" ;;
        RATE_LIMITED)  echo "⏳ 429 RATE LIMITED — check endpoint throttling, not proxy" ;;
        CONN_FAIL)     echo "❌ CONNECTION FAILED — proxy down, timeout, or unreachable" ;;
        HTTP_ERR)      echo "⚠️  HTTP $HTTP_CODE — unexpected upstream response" ;;
    esac
}

# ============================================
# ONCE MODE
# ============================================
if [ "$ONCE_MODE" = true ]; then
    echo ""
    echo "🔍 Checking IP once..."
    echo "========================================"

    do_check

    echo ""
    echo "📊 Proxy Info:"
    echo "  Protocol: ${PROTOCOL^^}"
    echo "  Status:  $HTTP_CODE ($RESULT_CLASS)"
    if [ "$RESULT_CLASS" == "OK" ]; then
        echo "  IP:      $IP"
        echo "  State:   $STATE"
    else
        echo "  Detail:  $(describe_result)"
    fi
    echo ""
    [ "$RESULT_CLASS" == "OK" ] && echo "✅ Done." || exit 1
    exit 0
fi

# ============================================
# STICKY MODE (quick 5-request test)
# ============================================
if [ "$STICKY_MODE" = true ]; then
    echo ""
    echo "🔍 Testing stickiness (5 requests, 5 sec apart)..."
    echo "========================================"

    REQUEST_IPS=()
    for i in {1..5}; do
        do_check
        if [ "$RESULT_CLASS" == "OK" ]; then
            echo "  Request $i: $IP - $STATE"
            REQUEST_IPS+=("$IP")
        else
            echo "  Request $i: $(describe_result)"
            REQUEST_IPS+=("FAILED")
        fi
        sleep 5
    done

    echo ""
    echo "📊 Summary:"
    UNIQUE_IPS=$(printf '%s\n' "${REQUEST_IPS[@]}" | grep -v "FAILED" | sort -u | wc -l)

    if [ "$UNIQUE_IPS" -eq 1 ] && [ "${REQUEST_IPS[0]}" != "FAILED" ]; then
        echo "✅ Sticky! All requests used the same IP: ${REQUEST_IPS[0]}"
    elif [ "$UNIQUE_IPS" -gt 1 ]; then
        echo "❌ Not sticky! IP changed during the test."
        echo "   Unique IPs seen:"
        printf '%s\n' "${REQUEST_IPS[@]}" | grep -v "FAILED" | sort -u | sed 's/^/     /'
    else
        echo "❌ All requests failed. Proxy may be down."
    fi
    exit 0
fi

# ============================================
# FULL ROTATION TEST (fire and forget)
# ============================================
TOTAL_SECONDS=$((DURATION * 60))
MAX_CHECKS=$((TOTAL_SECONDS / INTERVAL))

COUNT=0
LAST_IP=""
LAST_STATE=""
FIRST_IP=""
CHANGE_COUNT=0
FAIL_COUNT=0
AUTH_FAIL_COUNT=0
RATE_LIMIT_COUNT=0
START_TIME=$(date +%s)
INTERRUPTED=false

print_summary() {
    echo ""
    echo "========================================"
    if [ "$INTERRUPTED" = true ]; then
        echo "📊 SUMMARY REPORT (interrupted by user)"
    else
        echo "📊 SUMMARY REPORT"
    fi
    echo "========================================"
    echo "  Protocol:          ${PROTOCOL^^}"
    echo "  Duration:          ${DURATION} minutes"
    echo "  Total checks:      $COUNT"
    echo "  Failed (conn):     $FAIL_COUNT"
    echo "  Failed (auth 407): $AUTH_FAIL_COUNT"
    echo "  Rate limited 429:  $RATE_LIMIT_COUNT"
    echo "  IP changes:        $CHANGE_COUNT"
    echo "  First IP:          $FIRST_IP"
    echo "  Last IP:           $LAST_IP ($LAST_STATE)"
    echo ""
    echo "  Log file:          $LOG_FILE"
    echo "========================================"

    if [ $CHANGE_COUNT -gt 0 ]; then
        AVG_MINUTES=$(( (ELAPSED_FOR_SUMMARY / 60) / (CHANGE_COUNT + 1) ))
        echo "  📌 Avg time per IP: ~${AVG_MINUTES} minutes"

        if [ $AVG_MINUTES -ge 9 ] && [ $AVG_MINUTES -le 11 ]; then
            echo "  ✅ TTL 10 minutes: CONFIRMED (within expected range)"
        elif [ $AVG_MINUTES -lt 9 ]; then
            echo "  ⚠️  TTL 10 minutes: ROTATING TOO FAST (avg ${AVG_MINUTES}m)"
        else
            echo "  ⚠️  TTL 10 minutes: STICKING TOO LONG (avg ${AVG_MINUTES}m)"
        fi
    fi
    echo ""
    echo "✅ Test completed. Log saved to: $LOG_FILE"
}

# Catch Ctrl+C / kill so a 30-60min unattended run doesn't lose its report
on_interrupt() {
    INTERRUPTED=true
    CURRENT_TIME=$(date +%s)
    ELAPSED_FOR_SUMMARY=$((CURRENT_TIME - START_TIME))
    print_summary
    exit 130
}
trap on_interrupt SIGINT SIGTERM

echo ""
echo "🚀 Starting proxy rotation test (fire and forget)"
echo "📝 Logging to: $LOG_FILE"
echo "🔌 Protocol: ${PROTOCOL^^}"
echo "⏱️  Duration: ${DURATION} minutes (${MAX_CHECKS} checks)"
echo "📏 Interval: ${INTERVAL} seconds"
echo "========================================"

echo "Timestamp,Check#,IP,State,Changed,HTTPCode,Class" | tee -a "$LOG_FILE"

while true; do
    COUNT=$((COUNT + 1))
    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - START_TIME))
    ELAPSED_FOR_SUMMARY=$ELAPSED

    if [ $ELAPSED -ge $TOTAL_SECONDS ]; then
        echo ""
        echo "✅ Test complete! Duration reached."
        break
    fi

    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

    do_check

    case "$RESULT_CLASS" in
        OK)
            CHANGED="No"
            if [ -n "$LAST_IP" ] && [ "$LAST_IP" != "AUTH_FAIL" ] && [ "$LAST_IP" != "RATE_LIMITED" ] && [ "$IP" != "$LAST_IP" ]; then
                CHANGED="Yes"
                CHANGE_COUNT=$((CHANGE_COUNT + 1))
                echo "🔄 [${TIMESTAMP}] $LAST_IP ($LAST_STATE) → $IP ($STATE) [Change #$CHANGE_COUNT]" | tee -a "$LOG_FILE"
            fi
            [ -z "$FIRST_IP" ] && FIRST_IP="$IP"
            echo "$IP - $STATE - $TIMESTAMP" | tee -a "$LOG_FILE"
            LAST_IP="$IP"
            LAST_STATE="$STATE"
            ;;
        AUTH_FAIL)
            AUTH_FAIL_COUNT=$((AUTH_FAIL_COUNT + 1))
            echo "🔒 [$TIMESTAMP] Request #$COUNT — 407 AUTH FAILURE" | tee -a "$LOG_FILE"
            LAST_IP="AUTH_FAIL"; LAST_STATE="AUTH_FAIL"
            CHANGED="N/A"
            ;;
        RATE_LIMITED)
            RATE_LIMIT_COUNT=$((RATE_LIMIT_COUNT + 1))
            echo "⏳ [$TIMESTAMP] Request #$COUNT — 429 RATE LIMITED (check endpoint, not proxy)" | tee -a "$LOG_FILE"
            LAST_IP="RATE_LIMITED"; LAST_STATE="RATE_LIMITED"
            CHANGED="N/A"
            ;;
        CONN_FAIL|HTTP_ERR)
            FAIL_COUNT=$((FAIL_COUNT + 1))
            echo "⚠️  [$TIMESTAMP] Request #$COUNT — $(describe_result)" | tee -a "$LOG_FILE"
            CHANGED="N/A"
            ;;
    esac

    echo "$TIMESTAMP,$COUNT,$IP,$STATE,$CHANGED,$HTTP_CODE,$RESULT_CLASS" >> "$LOG_FILE"

    sleep $INTERVAL
done

print_summary
