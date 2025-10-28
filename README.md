# aminer-rest
REST-API for the logdata-anomaly-miner

**This software is WIP and not ready for production use. No security guarantees are given.**

sudo /usr/lib/logdata-anomaly-miner/.venv/bin/python3 -m pip install -r requirements.txt

/usr/lib/logdata-anomaly-miner/.venv/bin/uvicorn RemoteControlApi:app --reload
./runUnittests.sh

sudo cp -r /home/ernst/Documents/logdata-anomaly-miner/source/root/usr/lib/logdata-anomaly-miner/* /usr/lib/logdata-anomaly-miner/ && clear && ./runUnittests.sh
