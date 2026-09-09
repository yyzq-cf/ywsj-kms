FROM alpine:latest AS builder

RUN apk add --no-cache git build-base
RUN git clone https://github.com/Wind4/vlmcsd.git /tmp/vlmcsd \
    && cd /tmp/vlmcsd \
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

# Install runtime deps
RUN apk add --no-cache ca-certificates tzdata \
    && chmod +x /usr/local/bin/vlmcsd /usr/local/bin/vlmcs

WORKDIR /app

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY app.py .
COPY templates/ templates/

# Data directory
RUN mkdir -p /data

ENV TZ=Asia/Shanghai
ENV PYTHONUNBUFFERED=1

# KMS port + Web port
EXPOSE 1688 8080

ENTRYPOINT ["python", "app.py"]
