sudo -u aminer AMiner --Foreground --Config aecid-testsuite/demo/AMinerRemoteControl/demo-config.py 2> /dev/null > /dev/null &
sudo python3 -m unittest discover -s unit -p '*Test.py' > /dev/null
exit_code=$?
sudo pkill AMiner
sudo rm /tmp/AMinerRemoteLog.txt
exit $exit_code
