#!/bin/bash

# Start the honeypot in the background
timeout 5 ./honeypot &
HONEYPOT_PID=$!

# Give the server a moment to start
sleep 1

# Send a test probe
echo "Test probe from attacker" | nc -u 127.0.0.1 5353

# Wait for honeypot to finish
wait $HONEYPOT_PID 2>/dev/null
