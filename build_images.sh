#!/bin/bash


podman build -t ghcr.io/ait-aecid/logdata-anomaly-miner_rest -f Containerfile.aminer .
podman build -t ghcr.io/ait-aecid/aminer-rest -f Containerfile .


