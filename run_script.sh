#!/bin/bash

max_retries=1000
delay=30

for ((attempt=1; attempt<=max_retries; attempt++)); do
    echo "Attempt $attempt..."
    
    # Your command here; replace the echo with your actual command
    if sudo python3 demo_server.py; then
        echo "Task completed successfully!"
        exit 0
    else
        echo "Attempt $attempt failed."
        if [ $attempt -lt $max_retries ]; then
            echo "Retrying in $delay seconds..."
            sleep $delay
        fi
    fi
done

echo "Max retries reached. Exiting."
exit 1
