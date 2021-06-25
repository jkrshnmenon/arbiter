#!/bin/bash

TAG=$1

if [ "$TAG" == "int_ovfl" ]; then
	IMG=131
elif [ "$TAG" == "fmt" ]; then
	IMG=134
elif [ "$TAG" == "syswalker" ]; then
	IMG=252
elif [ "$TAG" == "srand" ]; then
	IMG=337
else
	IMG="crap"
fi

sed -i "s/CWE=.*/CWE=CWE${IMG}/" test_scripts/get_bins.sh
