mkdir /tmp/lib
mkdir /tmp/lib/aminer
sudo chown -R aminer:aminer /tmp/lib
cp logdata-anomaly-miner/aecid-testsuite/demo/AMinerRemoteControl/demo-config.py /tmp
sudo aminer --Config /tmp/demo-config.py &
sleep 2
sudo python3 -m unittest discover -s unit -p '*Test.py' #> /dev/null
exit_code=$?
sudo pkill aminer
sudo rm /tmp/AMinerRemoteLog.txt
rm /tmp/demo-config.py
sudo rm -r /tmp/lib
exit $exit_code
