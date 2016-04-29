#!/bin/bash
set -e

APPENV=${APPENV:-hailcannonenv}
echo $APPENV

/opt/bin/s3kms -r us-west-1 get -b opsee-keys -o dev/$APPENV > /$APPENV

source /$APPENV && \
	/hailcannon
