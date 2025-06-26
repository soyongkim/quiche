#!/bin/bash

# for scan every SNI in the JSON files
# LIST_DIR="list_ipv4"

# for json_file in "$LIST_DIR"/split_*.json; do
#   # Extract all SNI values (assuming each line is a JSON object with an "sni" field)
#   jq -r '.[].sni' "$json_file" | while read -r sni; do
#     if [[ -n "$sni" ]]; then
#       echo "Running for SNI: $sni"
#       ./quic_client.sh "$sni"
#     fi
#   done
# done


#!/usr/bin/env bash
#
# Scan every SNI in the JSON files and keep a log
#

# LIST_DIR="list_ipv4"
# LOG_DIR="logs"                 # where logs will be written
# mkdir -p "$LOG_DIR"            # create if it doesn’t exist

# for json_file in "$LIST_DIR"/split_*.json; do
#     log_file="$LOG_DIR/$(basename "${json_file%.json}").log"

#     {
#         echo "===== START $(date '+%Y-%m-%d %H:%M:%S') → ${json_file} ====="

#         # Extract SNI values and run quic_client.sh for each
#         jq -r '.[].sni' "$json_file" | while read -r sni; do
#             [[ -z $sni ]] && continue        # skip empty lines

#             echo "Running for SNI: $sni"
#             ./quic_client.sh "$sni"
#         done

#         echo "===== END   $(date '+%Y-%m-%d %H:%M:%S') → ${json_file} ====="
#         echo                                                     # blank line
#     } >>"$log_file" 2>&1        # append stdout & stderr to the log
# done



# Check if the correct number of arguments is provided
# if [[ $# -ne 1 ]]; then
#   echo "Usage: $0 <json_file>"
#   exit 1
# fi

# json_file="$1"

# # Extract all SNI values and run the client for each
# jq -r '.[].sni' "$json_file" | while read -r sni; do
#   if [[ -n "$sni" ]]; then
#     echo "Running for SNI: $sni"
#     ./quic_client.sh "$sni"
#   fi
# done


#!/usr/bin/env bash
#
# Scan every SNI in the JSON files
# and keep only the latest-SNI line in each log.

LIST_DIR="list_ipv4"
LOG_DIR="logs"                    # where logs will be written
mkdir -p "$LOG_DIR"

for json_file in "$LIST_DIR"/split_*.json; do
    log_file="$LOG_DIR/$(basename "${json_file%.json}").log"

    # Read all SNI values, run the client, but remember only the last SNI.
    # Any output from quic_client.sh is suppressed (>/dev/null 2>&1).
    last_sni=""
    while read -r sni; do
        [[ -z $sni ]] && continue
        last_sni="$sni"
        ./quic_client.sh "$sni" >/dev/null 2>&1
    done < <(jq -r '.[].sni' "$json_file")

    # Overwrite the log file with a single line for the latest SNI.
    {
        printf 'LATEST SNI [%s] processed at %s\n' \
               "$last_sni" "$(date '+%Y-%m-%d %H:%M:%S')"
    } >"$log_file"
done
