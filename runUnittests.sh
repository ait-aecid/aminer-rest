#!/bin/bash

# demo-config.py
mkdir -p /tmp/lib/aminer/log
sudo chown -R aminer:aminer /tmp/lib
sudo cp ../logdata-anomaly-miner/aecid-testsuite/demo/aminerRemoteControl/demo-config.py /tmp
sudo aminer -c /tmp/demo-config.py &
sleep 4
sudo /usr/lib/logdata-anomaly-miner/.venv/bin/python3 -m unittest discover -s unit -p '*Test.py' #> /dev/null
exit_code1=$?
sudo pkill aminer
sudo rm /tmp/demo-config.py
sudo rm -r /tmp/lib

# demo-config.yml
mkdir -p /tmp/lib/aminer/log
sudo chown -R aminer:aminer /tmp/lib
sudo cp ../logdata-anomaly-miner/aecid-testsuite/demo/aminerRemoteControl/demo-config.yml /tmp
sudo aminer -c /tmp/demo-config.yml &
sleep 4
sudo /usr/lib/logdata-anomaly-miner/.venv/bin/python3 -m unittest discover -s unit -p '*Test.py' #> /dev/null
exit_code2=$?
sudo pkill aminer
sudo rm /tmp/demo-config.yml
sudo rm -r /tmp/lib

if [[ $exit_code1 -ne 0 && $exit_code2 -ne 0 ]]; then
  echo "exit_code1 $exit_code1"
  echo "exit_code2 $exit_code2"
  exit 1
fi
exit 0
