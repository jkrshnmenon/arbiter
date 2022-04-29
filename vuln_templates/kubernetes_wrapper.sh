#!/bin/bash

usage () {
	echo "Usage : $0 -f <VD> -t <TARGET> [ -r <LEVEL> ]"
	echo -e "  -f VD\t\t: The VD inside vuln_templates to use"
	echo -e "  -t TARGET\t: The path to the target binary"
	echo -e "  -r LEVEL\t: The level of Adaptive FP reduction"
	echo ""
	exit 0
}


VD=${VD:-}
TARGET=${TARGET:-}
LEVEL=${LEVEL:--1}
NFS_DIR=/shared/arbiter/dataset
TEMPLATE_DIR=$(realpath $(dirname $0))
RUNNER=$TEMPLATE_DIR/run_arbiter.py


while getopts "f:t:r:" OPTION; do
	case $OPTION in
		f)
			VD=$OPTARG
			;;
		t)
			TARGET=$OPTARG
			;;
		r)
			LEVEL=$OPTARG
			;;
		*|h)
			usage
			;;
	esac
done

if [ -z "$VD" ]; then
	echo "[!] Error : -f option has to be specified"
	usage
elif [ -z "$TARGET" ]; then
	echo "[!] Error : -t option has to be specified"
	usage
fi

VD_PATH=$TEMPLATE_DIR/$VD
BIN_PATH=$NFS_DIR/$TARGET

if [ ! -f "$VD_PATH" ]; then
	echo "[!] Error : $VD_PATH does not exist"
	exit 1
elif [ ! -f "$BIN_PATH" ]; then
	echo "[!] Error : $BIN_PATH does not exist"
	exit 1
fi

if [ -n "$LEVEL" ]; then
	$RUNNER -f $VD_PATH -t $BIN_PATH -l $HOME/logs -j $HOME/logs -r $LEVEL
else
	$RUNNER -f $VD_PATH -t $BIN_PATH -l $HOME/logs -j $HOME/logs
fi

