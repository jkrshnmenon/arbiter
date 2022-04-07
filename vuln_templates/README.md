This is where all the VD's used during the Arbiter evaluation reside.


The files CWE131.py, CWE134.py, CWE252.py and CWE337.py correspond to CWE types CWE-131, CWE-134, CWE-252 and CWE-337 respectively.


The CWE680_juliet.py is the template that was used to evaluate the Juliet Test Suite for CWE680.


The files CWE190_juliet_signed.py and CWE190_juliet_unsigned.py are the two templates used to evaluate the Juliet Test Suite for CWE190.

Please refer to the Arbiter paper for explanation on why we had to split the Juliet Test Suite for CWE190 into signed and unsigned.


# How to run

The `run_arbiter.py` is a handy entry point that calls the Arbiter API's, sets up logging and other miscellaneous tasks.

The arguments that can be passed to `run_arbiter.py` are as follows

```
$ run_arbiter.py -h
usage: run_arbiter.py [-h] -f VD -t TARGET [-r LEVEL] [-l LOG_DIR] [-j JSON_DIR] [-s]

Use Arbiter to run a template against a specific binary

optional arguments:
  -h, --help   show this help message and exit
  -f VD        The VD template to use
  -t TARGET    The target binary to analyze
  -r LEVEL     Number of levels for Adaptive False Positive Reduction
  -l LOG_DIR   Enable logging to LOG_DIR
  -j JSON_DIR  Enable verbose statistics dumps to JSON_DIR
  -s           Enable strict mode (stricter static data-flow based filtering)

```

The parameters `-f` and `-t` are required while the others are optional.


An example of running the VD for CWE-131 for the `ls` binary would be as follows

```
mkdir <log_dir>
mkdir <json_dir>
cd <path/to/arbiter>/vuln_templates/
./run_arbiter.py -f ./CWE131.py -t /bin/ls -l <log_dir> -j <json_dir>
```

# Writing your own VD

In order to write a new VD, all you need to do is to implement 4 functions, namely
`apply_constraint`, `specify_sources`, `specify_sinks` and `save_results`.

Please refer to the `examples` directory for more information about each of these functions.


Once you have this VD ready, invoke the `run_arbiter` with the `-f` parameter pointing to this VD and the `-t` parameter pointing to the target binary.

