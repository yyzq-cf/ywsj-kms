FROM alpine:latest AS builder

# Install build tools
RUN apk add --no-cache git build-base

# Clone and build vlmcsd
RUN git clone https://github.com/Wind4/vlmcsd.git /tmp/vlmcsd \
    && cd /tmp/vlmcsd \
    && make \
    && strip bin/vlmcsd

# ---
FROM alpine:latest

LABEL maintainer="ywsj <ywsj@ywsj365.com>"
LABEL description="KMS activation server (vlmcsd) - lightweight, multi-arch Docker image"

# Copy binary from builder
COPY --from=builder /tmp/vlmcsd/bin/vlmcsd /usr/local/bin/vlmcsd

# Install minimal runtime deps
RUN apk add --no-cache ca-certificates tzdata \
    && chmod +x /usr/local/bin/vlmcsd

# KMS port
EXPOSE 1688

# Timezone
ENV TZ=Asia/Shanghai

# Run as non-root
RUN adduser -D -H kms
USER kms

# Start vlmcsd in foreground
ENTRYPOINT ["vlmcsd", "-D", "-e"]
