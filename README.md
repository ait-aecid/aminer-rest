# aminer-rest
REST-API for the logdata-anomaly-miner

sudo /usr/lib/logdata-anomaly-miner/.venv/bin/python3 -m pip install -r requirements.txt

/usr/lib/logdata-anomaly-miner/.venv/bin/uvicorn RemoteControlApi:app --reload
./runUnittests.sh
