ARG BUILDER=docker.io/library/golang:1.24.3
ARG DEBIAN_IMAGE=debian:stable-slim
ARG BASE=gcr.io/distroless/static-debian12:nonroot
FROM --platform=$BUILDPLATFORM ${BUILDER} AS builder
COPY . ./src
WORKDIR ./src
RUN git clean -fdx && go mod tidy
RUN CGO_ENABLED=0 GOOS=linux make

FROM --platform=$BUILDPLATFORM ${DEBIAN_IMAGE} AS build
SHELL [ "/bin/sh", "-ec" ]

RUN export DEBCONF_NONINTERACTIVE_SEEN=true \
           DEBIAN_FRONTEND=noninteractive \
           DEBIAN_PRIORITY=critical \
           TERM=linux ; \
    apt-get -qq update ; \
    apt-get -yyqq upgrade ; \
    apt-get -yyqq install ca-certificates libcap2-bin; \
    apt-get clean
COPY --from=builder /go/src/coredns /coredns
RUN setcap cap_net_bind_service=+ep /coredns

FROM --platform=$TARGETPLATFORM ${BASE}
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /coredns /coredns
USER nonroot:nonroot
WORKDIR /
EXPOSE 53 53/udp
ENTRYPOINT ["/coredns"]
