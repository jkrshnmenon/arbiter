#!/bin/bash

usage () {
	echo "Usage : $0 -f <VD> -t <TARGET>"
	echo -e "  -f VD\t\t: The VD inside vuln_templates to use"
	echo -e "  -t TARGET\t: The path to the target binary"
	echo ""
	exit 0
}


VD=${VD-}
TARGET=${TARGET-}
NFS_DIR=/shared/arbiter
TEMPLATE_DIR=$(realpath $(dirname $0))
RUNNER=$TEMPLATE_DIR/run_arbiter.py


if [ $# -lt 2 ]; then
	usage
fi


while getopts "f:t:" OPTION; do
	case $OPTION in
		f)
			VD=$OPTARG
			;;
		t)
			TARGET=$OPTARG
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

$RUNNER -f $VD_PATH -t $BIN_PATH -l $HOME/logs -j $HOME/logs