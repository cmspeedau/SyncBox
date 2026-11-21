FROM node:22-alpine AS web-build
WORKDIR /app/web
COPY web/package*.json ./
RUN npm install
COPY web/ ./
RUN npm run build

FROM golang:1.23-alpine AS go-build
WORKDIR /app
COPY go.mod ./
COPY main.go ./
COPY --from=web-build /app/web/dist ./web/dist
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/syncbox .

FROM alpine:3.21 AS runtime
RUN apk add --no-cache ca-certificates && addgroup -S syncbox && adduser -S -G syncbox syncbox
WORKDIR /app
COPY --from=go-build /out/syncbox /usr/local/bin/syncbox
RUN mkdir -p /data && chown syncbox:syncbox /data
ENV SYNCBOX_ADDR=:8080 SYNCBOX_DATA_DIR=/data
EXPOSE 8080
VOLUME ["/data"]
USER syncbox
ENTRYPOINT ["/usr/local/bin/syncbox"]
