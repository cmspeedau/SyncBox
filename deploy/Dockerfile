# Build the server into a static binary and drop it in a scratch image.
#
# No cgo, so the binary has no glibc dependency and the runtime stage needs no
# distribution at all. The SQLite driver is modernc's pure-Go port, which is what
# keeps CGO off; a mattn-style driver would drag in libc and break the scratch
# image. The image is the binary plus two empty, owned data directories.

FROM golang:1.27-alpine AS build
WORKDIR /src

# The module files first, so a dependency-only change reuses the build cache for
# the source copy. go.sum pins the dependency graph go.mod selects.
COPY server/go.mod server/go.sum ./
RUN go mod download

COPY server/ ./
RUN CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags="-s -w" \
        -o /out/syncboxd \
        ./cmd/syncboxd

# Stage the data directories with the owner the container runs as, so the next
# COPY lands them owned. Docker initialises a fresh named volume's ownership from
# the image's content at that path; without this, /data would be root-owned and
# the unprivileged server could not create chunks/ or the database inside it. The
# sentinel file guarantees the directories are non-empty and so survive COPY.
RUN mkdir -p /out/data /out/backups && touch /out/data/.keep /out/backups/.keep

FROM scratch

# The nobody of most distributions. The container only ever writes inside the two
# mounts below.
COPY --from=build /out/syncboxd /usr/local/bin/syncboxd
COPY --from=build --chown=65534:65534 /out/data /data
COPY --from=build --chown=65534:65534 /out/backups /backups

USER 65534:65534

ENV SYNCBOX_LISTEN_ADDR=0.0.0.0:8080 \
    SYNCBOX_DATA_DIR=/data \
    SYNCBOX_BACKUP_TARGET=/backups

EXPOSE 8080
VOLUME ["/data", "/backups"]

ENTRYPOINT ["/usr/local/bin/syncboxd"]
CMD ["serve"]
