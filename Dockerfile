from ubuntu:18.04

run dpkg --add-architecture i386
run apt update && apt -y upgrade
run apt install -y python3-dev python3-pip build-essential
run pip3 install angr python-json-logger
run useradd -s /bin/bash -m test
user test
copy arbiter /home/test/arbiter
copy test_scripts /home/test/test_scripts
copy setup.py /home/test/setup.py
copy README.md /home/test/
run mkdir /home/test/logs
run mkdir /home/test/bins
user root
run python3 /home/test/setup.py install
user test
workdir /home/test
cmd ["/bin/bash"]
