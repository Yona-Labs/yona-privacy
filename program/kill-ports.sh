#!/bin/bash

# Script to kill processes on ports 3001, 8784, and 8899

ports=(3001 8784 8899)

for port in "${ports[@]}"; do
    echo "Checking port $port..."
    pid=$(lsof -ti:$port)
    
    if [ -n "$pid" ]; then
        echo "Killing process $pid on port $port"
        kill -9 $pid
        echo "Process on port $port killed"
    else
        echo "No process found on port $port"
    fi
done

echo "Done!"


