# First stage: build the Go application
FROM golang:1.23.4 AS builder

# Set the Current Working Directory inside the container
WORKDIR /src

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy the source code into the container
COPY . .

# Run tests
RUN go test ./...

# Build the Go application
RUN go build -o /bin/vss cmd/vss/*.go

# Use distroless cc image which includes glibc for dynamic library support
FROM gcr.io/distroless/cc-debian12:nonroot as vss

WORKDIR /

COPY --from=builder /bin/vss /bin/vss

# Use nonroot user
USER nonroot:nonroot

# Command to run the executable
ENTRYPOINT [ "/bin/vss" ]
