# aminer-rest
REST-API for the logdata-anomaly-miner

**This software is WIP and not ready for production use. No security guarantees are given.**
```bash
sudo /usr/lib/logdata-anomaly-miner/.venv/bin/python3 -m pip install -r requirements.txt
/usr/lib/logdata-anomaly-miner/.venv/bin/uvicorn RemoteControlApi:app --reload
./runUnittests.sh
sudo cp -r /home/ernst/Documents/logdata-anomaly-miner/source/root/usr/lib/logdata-anomaly-miner/* /usr/lib/logdata-anomaly-miner/ && clear && ./runUnittests.sh
```

# Running Setup with Docker Compose

## Build Docker Containers Locally
```bash
cd logdata-anomaly-miner
sudo docker build --build-arg varbranch=development -f Dockerfile -t aminer .
cd ../aminer-rest
sudo docker build -f Dockerfile -t aminer-rest .
```

**Volumes must be removed to load changed files in logdata-anomaly-miner.<br>
No data is stored in this volume.**

```bash
sudo docker compose down -v
```

The testdata directory should not be changed. Use following lines to prevent tracking in git:
```bash
git update-index --skip-worktree testdata/aminer-rest-*
git update-index --skip-worktree testdata/aminer-run/aminer-remote.socket
```

To undo, simply run previous commands with `--no-skip-worktree` instead.
