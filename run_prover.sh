#!/bin/bash

counter=0
while true; do
    node_url=$(curl -s $NODE_SELECTOR | jq -r '.node_url')

    if [ -z "$node_url" ] || [ "$node_url" == "null" ]; then
        echo "Failed to get a valid node_url. Retrying in 5 seconds..."
    else
        
        node_url=${node_url#http://}
        echo "Running prover with node_url: $node_url"
        ./target/release/prover $node_url 7047
        
        if [ $? -eq 0 ]; then
            counter=$((counter + 1))
            mv simple_proof.json proof_$counter.json
            echo "Proof saved as proof_$counter.json"
        else 
            echo "Request failed"
        fi
    fi
    sleep 5
done
