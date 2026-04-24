#!/bin/bash

sleep 5
uvicorn RemoteControlApi:app --host 0.0.0.0 --port 8000


