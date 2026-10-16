# Build the server into a static binary and drop it in a scratch image.
#
# No cgo, so the binary has no glibc dependency and the runtime stage needs no
# distribution at all. The image is the binary plus nothing, which is the whole
# appeal of the server being one small container.

FROM golang:1.27-alpine AS build
WORKDIR /src

# The module file first, so a dependency-only change reuses the build cache for
# the source copy. go.sum joins this line the first time a dependency is added.
COPY server/go.mod ./
RUN go mod download

COPY server/ ./
RUN CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags="-s -w" \
        -o /out/syncboxd \
        ./cmd/syncboxd

FROM scratch

# The nobody of most distributions. The container only ever needs to write inside
# the two mounts below.
COPY --from=build /out/syncboxd /usr/local/bin/syncboxd

USER 65534:65534

ENV SYNCBOX_LISTEN_ADDR=0.0.0.0:8080 \
    SYNCBOX_DATA_DIR=/data

EXPOSE 8080
VOLUME ["/data", "/backups"]

ENTRYPOINT ["/usr/local/bin/syncboxd"]
CMD ["serve"]
