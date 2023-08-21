#!/bin/env bash

# Set target directory for cleaning
TARGET_DIR="/var/log/healthcheck"

# Set log file name pattern
LOG_FILENAME_PATTERN="*\.log\.*"

# Set the maximum usage percentage and the target usage percentage
MAX_USAGE=80
TARGET_USAGE=40

# Set the minimum number of log files to keep
MIN_FILES=12

# Set the maximum number of files to delete in one run
MAX_DELETE=10000

OPTS=`getopt -o d:p:u:l:K:D:h --long \
log-directory:,filename-pattern:,disk-usage-high:,\
disk-usage-low:,min-files-kept:,max-deletions:,help,\
 -n "$0" -- "$@"`
eval set -- "$OPTS"
while true
do
    case "$1" in
    -d|--log-directory)
        TARGET_DIR="$2"
        shift 2
        ;;
    -p|--filename-pattern)
        LOG_FILENAME_PATTERN="$2"
        shift 2
        ;;
    -u|--disk-usage-high)
        MAX_USAGE="$2"
        shift 2
        ;;
    -l|--disk-usage-low)
        TARGET_USAGE="$2"
        shift 2
        ;;
    -K|--min-files-kept)
        MIN_FILES="$2"
        shift 2
        ;;
    -D|--max-deletions)
        MAX_DELETE="$2"
        shift 2
        ;;
    -h|--help)
        echo "[usage] $0 [ OPTS ]"
        echo "OPTS:"
        echo "  -d|--log-directory DIRECTORY"
        echo "  -p|--filename-pattern REGEXPR"
        echo "  -u|--disk-usage-high 0-100"
        echo "  -l|--disk-usage-low 0-100"
        echo "  -K|--min-files-kept NUM"
        echo "  -D|--max-deletions NUM"
        echo "  -h|--help"
        exit 0
        ;;
    --)
        shift
        break
        ;;
    *)
        echo "Param Error!"
        exit 1
        ;;
    esac
done

NotRecognized=$(for arg do printf "$arg " ; done)
[ ! -z "$NotRecognized" ] && echo "Unrecognized Opts: ${NotRecognized}" && exit 1

echo "CONFIGS:"
echo "  log-directory: ${TARGET_DIR}"
echo "  filename-pattern: ${LOG_FILENAME_PATTERN}"
echo "  disk-usage-high: ${MAX_USAGE}"
echo "  disk-usage-low: ${TARGET_USAGE}"
echo "  min-files-kept: ${MIN_FILES}"
echo "  max-deletions: ${MAX_DELETE}"

[ ! -d ${TARGET_DIR} ] && echo "invalid --log-directory \"${TARGET_DIR}\", not found!" && exit 1
echo ${MAX_USAGE} | egrep ^[0-9]+$ >/dev/null; [ $? -ne 0 ] && echo "invalid --disk-usage-high" && exit 1
echo ${TARGET_USAGE} | egrep ^[0-9]+$ >/dev/null; [ $? -ne 0 ] && echo "invalid --disk-usage-low" && exit 1
echo ${MIN_FILES} | egrep ^[0-9]+$ >/dev/null; [ $? -ne 0 ] && echo "invalid --min-files-kept" && exit 1
echo ${MAX_DELETE} | egrep ^[0-9]+$ >/dev/null; [ $? -ne 0 ] && echo "invalid --max-deletions" && exit 1
res=$(echo "${MAX_USAGE} < 100" | bc); [ "$res" -ne 1 ] && echo "--disk-usage-high must less than 100" && exit 1
res=$(echo "${MAX_USAGE} > ${TARGET_USAGE}" | bc); [ "$res" -ne 1 ] && echo "--disk-usage-high must greater than --disk-usage-low" && exit 1

# Get the current disk usage
CURRENT_USAGE=$(df -P ${TARGET_DIR} | awk 'NR==2 {printf "%d", $5}')

# Initialize a counter for deleted files
DELETED_FILES=0

# Start the cleaning process if the disk usage is higher than the defined MAX_USAGE
if [ "${CURRENT_USAGE}" -gt "${MAX_USAGE}" ]; then
    echo "Disk usage is ${CURRENT_USAGE}%, starting cleaning process."

    # Find and delete logs until disk usage reaches TARGET_USAGE or MAX_DELETE files are deleted
    while [ "${CURRENT_USAGE}" -gt "${TARGET_USAGE}" ] && [ "${DELETED_FILES}" -lt "${MAX_DELETE}" ]; do
        # Check the number of log files
        NUM_FILES=$(find ${TARGET_DIR} -type f -name ${LOG_FILENAME_PATTERN} | wc -l)

        # Ensure that at least MIN_FILES log files remain
        if [ "${NUM_FILES}" -le "${MIN_FILES}" ]; then
            echo "Reached minimum number of log files (${MIN_FILES}), aborting."
            exit 1
        fi

        # Find the oldest log file
        OLDEST_LOG=$(find ${TARGET_DIR} -type f -name ${LOG_FILENAME_PATTERN} -printf '%T+ %p\n' | sort | head -n1 | cut -d' ' -f2)

        echo "Deleting ${OLDEST_LOG}..."
        rm -f "${OLDEST_LOG}"
        DELETED_FILES=$((DELETED_FILES+1))

        # Update current disk usage
        CURRENT_USAGE=$(df -P ${TARGET_DIR} | awk 'NR==2 {printf "%d", $5}')
    done

    if [ "${DELETED_FILES}" -eq "${MAX_DELETE}" ]; then
        echo "Reached the maximum number of deletions (${MAX_DELETE}), aborting."
    else
        echo "Cleaning process completed. Disk usage is now ${CURRENT_USAGE}%."
    fi

else
    echo "Disk usage is ${CURRENT_USAGE}%, no cleaning needed."
fi

echo "Remaining Files in ${TARGET_DIR} (only show 30 entries):"
ls -lh ${TARGET_DIR} | head -n 30

exit 0
