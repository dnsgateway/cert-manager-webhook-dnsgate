# syntax = docker/dockerfile:1.22

FROM --platform=${TARGETARCH} scratch AS gorelease

COPY --from=gcr.io/distroless/static-debian13:nonroot . .
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/cert-manager-webhook-dnsgate /bin/cert-manager-webhook-dnsgate

USER 65532:65532
ENTRYPOINT ["/bin/cert-manager-webhook-dnsgate"]
