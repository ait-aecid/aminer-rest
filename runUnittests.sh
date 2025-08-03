mkdir -p /tmp/lib/aminer/log
sudo chown -R aminer:aminer /tmp/lib
sudo cp ../logdata-anomaly-miner/aecid-testsuite/demo/aminerRemoteControl/demo-config.py /tmp
sudo aminer -c /tmp/demo-config.py &
sleep 2
sudo /usr/lib/logdata-anomaly-miner/.venv/bin/python3 -m unittest discover -s unit -p '*Test.py' #> /dev/null
exit_code=$?
sudo pkill aminer
sudo rm /tmp/demo-config.py
sudo rm -r /tmp/lib
exit $exit_code
