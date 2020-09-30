mkdir /tmp/lib
mkdir /tmp/lib/aminer
sudo chown -R aminer:aminer /tmp/lib
cp logdata-anomaly-miner/aecid-testsuite/demo/AMinerRemoteControl/demo-config.py /tmp
sudo AMiner --Foreground --Config /tmp/demo-config.py &
sleep 2
sudo coverage run --source=./ -m unittest discover -s unit -p '*Test.py' > /dev/null
exit_code1=$?
touch /tmp/report
echo 'Statement Coverage:' > /tmp/report
sudo coverage report >> /tmp/report
sudo pkill AMiner
sudo AMiner --Foreground --Config /tmp/demo-config.py &
sleep 2
sudo coverage run --source=./ --branch -m unittest discover -s unit -p '*Test.py' > /dev/null
exit_code2=$?
echo 'Branch Coverage:' >> /tmp/report
sudo coverage report >> /tmp/report
cat /tmp/report
rm /tmp/report
test -e /var/mail/mail && sudo rm -f /var/mail/mail
sudo rm /tmp/AMinerRemoteLog.txt
rm /tmp/demo-config.py
sudo pkill AMiner
sudo rm -r /tmp/lib
if [[ "$exit_code1" -ne 0 || "$exit_code2" -ne 0 ]]; then
	exit 1
fi
exit 0
