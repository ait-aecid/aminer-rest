sudo AMiner --Foreground --Config /tmp/demo-config.py
sudo python3 -m unittest discover -s unit -p '*Test.py' > /dev/null
exit_code=$?
sudo pkill AMiner
sudo rm /tmp/AMinerRemoteLog.txt
exit $exit_code
