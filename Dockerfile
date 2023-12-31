# (first line comment needed for DOCKER_BUILDKIT use)
#
ARG GOLANG_IMAGE=docker.io/library/golang:1.20.2-alpine3.17@sha256:4e6bc0eafc261b6c8ba9bd9999b6698e8cefbe21e6d90fbc10c34599d75dc608
ARG BASE_IMAGE=scratch

FROM ${GOLANG_IMAGE} as builder
ADD . /go/src/github.com/khulnasoft/certgen
WORKDIR /go/src/github.com/khulnasoft/certgen
RUN CGO_ENABLED=0 go build -o shipyard-certgen main.go

FROM ${BASE_IMAGE}
LABEL maintainer="security@khulnasoft.com"
COPY --from=builder /go/src/github.com/khulnasoft/certgen/shipyard-certgen /usr/bin/shipyard-certgen
ENTRYPOINT ["/usr/bin/shipyard-certgen"]