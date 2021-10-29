
FROM arti.dev.cray.com/baseos-docker-master-local/golang:1.14.9-alpine3.12 AS builder

ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

COPY tests/opa/xname-enabled/run_tests src/run_tests

RUN cd src/run_tests && go mod download
RUN cd src/run_tests && go build .
RUN ls src/run_tests

#FROM arti.dev.cray.com/third-party-docker-stable-local/openpolicyagent/opa:0.33.1-envoy-4
FROM openpolicyagent/opa:0.33.1-envoy-4

COPY --from=builder /go/src/run_tests/run_tests .
COPY tests/opa/certificate_authority.crt /jwtValidationFetchTls/certificate_authority.crt
