# ---------- STAGE 1: build ----------
FROM golang:1.25.5-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o server ./cmd/server

# ---------- STAGE 2: trivy binary ----------
FROM aquasec/trivy:0.69.1 AS trivy

# ---------- STAGE 3: runtime ----------
FROM alpine:3.19

RUN apk add --no-cache ca-certificates

# Копируем trivy из официального образа
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

WORKDIR /app

# Копируем бинарник из builder (ВАЖНО: путь должен совпадать)
COPY --from=builder /app/server /app/server

EXPOSE 8080

CMD ["/app/server"]