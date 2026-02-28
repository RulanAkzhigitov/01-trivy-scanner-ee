# ---------- STAGE 1: build ----------
FROM golang:1.25.5-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o server ./cmd/server

# ---------- STAGE 2: runtime ----------
FROM alpine:3.19

RUN apk add --no-cache ca-certificates wget

# Устанавливаем Trivy CLI (официальный бинарник)
RUN wget -qO- https://github.com/aquasecurity/trivy/releases/download/v0.69.1/trivy_0.69.1_Linux-64bit.tar.gz | tar -xz -C /usr/local/bin trivy

WORKDIR /app

COPY --from=builder /app/server /app/server

EXPOSE 8080

CMD ["/app/server"]