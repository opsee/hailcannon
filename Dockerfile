FROM gliderlabs/alpine:3.2

ENV AWS_ACCESS_KEY_ID=""
ENV AWS_SECRET_ACCESS_KEY=""
ENV AWS_DEFAULT_REGION=""

RUN apk add --update bash ca-certificates

COPY target/linux/amd64/bin/* /
