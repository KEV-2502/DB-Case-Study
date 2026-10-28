#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="neo4j-case-study"
NEO4J_PASSWORD="password123"

# Check if container already exists
if docker ps -a --format '{{.Names}}' | grep -Eq "^${CONTAINER_NAME}\$"; then
    if docker ps --format '{{.Names}}' | grep -Eq "^${CONTAINER_NAME}\$"; then
        echo "Neo4j container '${CONTAINER_NAME}' is already running."
    else
        echo "Starting existing stopped container '${CONTAINER_NAME}'..."
        docker start "${CONTAINER_NAME}"
    fi
else
    echo "Creating and starting new container '${CONTAINER_NAME}'..."
    docker run -d \
        --name "${CONTAINER_NAME}" \
        -p 7474:7474 \
        -p 7687:7687 \
        -e NEO4J_AUTH="neo4j/${NEO4J_PASSWORD}" \
        -e NEO4J_server_memory_heap_initial__size=256M \
        -e NEO4J_server_memory_heap_max__size=512M \
        -e NEO4J_server_memory_pagecache_size=256M \
        neo4j:5-community
fi
