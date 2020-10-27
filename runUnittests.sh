sudo python3 -m unittest discover -s unit -p '*Test.py' > /dev/null
exit_code=$?
exit $exit_code
