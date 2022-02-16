# Arbiter

Arbiter is a combination of static and dynamic analyses, built on top of angr, that can be used to detect some vulnerability classes.

All you need to use Arbiter is a sink that can be identified statically (like a call to a specific function), and a property that should not be violated at this sink.
Arbiter can then be used to detect if this property is violated at any of the corresponding sinks in the binary.


# Installation

`python setup.py build && python setup.py install`


# Docker image

`docker pull 4rbit3r/arbiter:latest`


# Arbiter examples

This repository contains some examples of using Arbiter to detect different CWE types in the `test_scripts` directory.
The argument to each of these scripts is the path to the binary that you want to test.

