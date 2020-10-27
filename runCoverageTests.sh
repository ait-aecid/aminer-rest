sudo coverage run --source=./ -m unittest discover -s unit -p '*Test.py' > /dev/null
exit_code1=$?
echo 'Statement Coverage:' > /tmp/report
sudo coverage report >> /tmp/report
sudo coverage run --source=./ --branch -m unittest discover -s unit -p '*Test.py' > /dev/null
exit_code2=$?
echo 'Branch Coverage:' >> /tmp/report
sudo coverage report >> /tmp/report
cat /tmp/report
rm /tmp/report
if [[ "$exit_code1" -ne 0 || "$exit_code2" -ne 0 ]]; then
	exit 1
fi
exit 0
