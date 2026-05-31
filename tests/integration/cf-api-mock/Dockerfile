FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY server.go .
RUN go mod init cf-api-mock && go build -o server .

FROM alpine:latest
COPY --from=builder /app/server /server
ENTRYPOINT ["/server"]
