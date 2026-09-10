FROM alpine:latest AS builder

RUN apk add --no-cache git build-base
# Pin to specific commit for reproducible builds (70e03572b254, 2023-07-28)
RUN git clone https://github.com/Wind4/vlmcsd.git /tmp/vlmcsd \
    && cd /tmp/vlmcsd \
    && git checkout 70e03572b254688b8c3557f898e7ebd765d29ae1 \
    && make \
    && strip bin/vlmcsd
RUN strip /tmp/vlmcsd/bin/vlmcs

# ── Final stage
FROM python:3.12-alpine

LABEL maintainer="ywsj <ywsj@ywsj365.com>"
LABEL description="KMS activation server with web monitoring dashboard"

# Copy vlmcsd binaries from builder
COPY --from=builder /tmp/vlmcsd/bin/vlmcsd /usr/local/bin/vlmcsd
COPY --from=builder /tmp/vlmcsd/bin/vlmcs /usr/local/bin/vlmcs

# Install runtime deps: su-exec for privilege drop, curl for healthcheck
RUN apk add --no-cache ca-certificates tzdata su-exec curl \
    && chmod +x /usr/local/bin/vlmcsd /usr/local/bin/vlmcs

# Create non-root user (UID 1000 to match volume permissions)
RUN addgroup -g 1000 -S appuser \
    && adduser -u 1000 -S -G appuser -h /app appuser

WORKDIR /app

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app (ensure appuser can read)
COPY --chown=appuser:appuser app.py .
COPY --chown=appuser:appuser templates/ templates/
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

# Data directory
RUN mkdir -p /data && chown appuser:appuser /data

ENV TZ=Asia/Shanghai
ENV PYTHONUNBUFFERED=1
ENV WEB_PORT=8080

# KMS port + Web port
EXPOSE 1688 8080

# Healthcheck: verify web panel responds
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:${WEB_PORT}/api/check || exit 1

# Root starts entrypoint, which fixes perms then drops to appuser
ENTRYPOINT ["./entrypoint.sh"]
