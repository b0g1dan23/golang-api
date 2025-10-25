# Stage 1: Build the Go application
FROM golang:1.25-alpine3.22 AS builder

RUN apk add --no-cache tzdata

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build main application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /go-app ./main.go

# Build seed binary (build from /app, not /app/seed)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /seed-binary ./seed/main.go

# Stage 2: Create the final, lightweight image
FROM alpine:latest

RUN apk add --no-cache tzdata

WORKDIR /app

# Copy binaries from builder
COPY --from=builder /go-app .
COPY --from=builder /seed-binary ./seed

# Make binaries executable
RUN chmod +x ./go-app ./seed

EXPOSE 8080

CMD ["./go-app"]