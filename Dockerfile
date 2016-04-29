FROM gliderlabs/alpine:3.2

RUN apk add --update bash ca-certificates curl
RUN mkdir -p /opt/bin && \
		curl -Lo /opt/bin/s3kms https://s3-us-west-2.amazonaws.com/opsee-releases/go/vinz-clortho/s3kms-linux-amd64 && \
    chmod 755 /opt/bin/s3kms

ENV AWS_ACCESS_KEY_ID=""
ENV AWS_SECRET_ACCESS_KEY=""
ENV AWS_DEFAULT_REGION=""

ENV HAILCANNON_ADDRESS=""
ENV HAILCANNON_SPANX_ADDRESS=""
ENV HAILCANNON_KEELHAUL_ADDRESS=""
ENV APPENV=""

COPY run.sh /
COPY target/linux/amd64/bin/* /

EXPOSE 9109
CMD ["/hailcannon"]
