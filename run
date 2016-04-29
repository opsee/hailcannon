#!/bin/bash
set -e

APPENV=${APPENV:-hailcannonenv}

/opt/bin/s3kms -r us-west-1 get -b opsee-keys -o dev/$APPENV > /$APPENV

source /$APPENV && \
  /opt/bin/s3kms -r us-west-1 get -b opsee-keys -o dev/vape.key > /vape.key && \
  /opt/bin/s3kms -r us-west-1 get -b opsee-keys -o dev/$HAILCANNON_CERT > /$HAILCANNON_CERT && \
  /opt/bin/s3kms -r us-west-1 get -b opsee-keys -o dev/$HAILCANNON_CERT_KEY > /$HAILCANNON_CERT_KEY && \
  chmod 600 /$HAILCANNON_CERT_KEY && \
	/hailcannon
