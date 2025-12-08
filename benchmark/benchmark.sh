#!/bin/bash

# on server side:
# sudo apt install iperf3
# iperf3 -s -p {TARGET_PORT}

TARGET_SERVER=$1
TARGET_PORT=$2
TOTAL_SECONDS=$3
REPORT_INTERVAL=$4
CCA=$5
TRIAL=$6
echo $0 $1 $2 $3 $4 $5 $6
# loop for trials
sudo sysctl --write net.ipv4.tcp_congestion_control=$CCA
echo "Trial $TRIAL for $CCA Starting..."
touch "${CCA}_${TRIAL}.json"
nice -n 19 python3 cpu_bench.py "${CCA}_${TRIAL}_cpu_perf" $TOTAL_SECONDS &
iperf3 -c $TARGET_SERVER -p $TARGET_PORT \
--json --verbose --timestamps --interval $REPORT_INTERVAL \
--time $TOTAL_SECONDS --logfile "${CCA}_${TRIAL}.json"

echo "Trial $TRIAL for $CCA done, sleeping for 5 seconds"
sleep 5
