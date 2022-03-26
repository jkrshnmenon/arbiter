FROM ubuntu:18.04

RUN dpkg --add-architecture i386
RUN apt update && apt -y upgrade
RUN apt install -y python3-dev python3-pip build-essential
RUN useradd -s /bin/bash -m test
COPY arbiter /home/test/arbiter
COPY vuln_templates /home/test/vuln_templates
COPY setup.py /home/test/setup.py
COPY README.md /home/test/
RUN chown -R test:test /home/test/
USER test
RUN pip3 install --user angr python-json-logger
RUN mkdir /home/test/logs
RUN mkdir /home/test/bins
WORKDIR /home/test
RUN python3 /home/test/setup.py install --user
CMD ["/bin/bash"]
