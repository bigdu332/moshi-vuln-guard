FROM python:3.12-slim

# 只装 Docker 客户端。套接字由 compose 挂载，客户端用它列出并进入旧容器。
ARG TARGETARCH
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && arch="${TARGETARCH:-amd64}" \
    && case "$arch" in arm64) darch=aarch64 ;; *) darch=x86_64 ;; esac \
    && curl -fsSL -o /tmp/docker.tgz "https://download.docker.com/linux/static/stable/${darch}/docker-27.5.1.tgz" \
    && tar -C /tmp -xzf /tmp/docker.tgz docker/docker \
    && mv /tmp/docker/docker /usr/local/bin/docker \
    && chmod +x /usr/local/bin/docker \
    && rm -rf /tmp/docker /tmp/docker.tgz \
    && apt-get purge -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY vulnguard ./vulnguard
COPY demo ./demo
COPY ai-process ./ai-process
ENV PYTHONPATH=/app
EXPOSE 8000
# 明确使用 docker 来源。客户端连不上守护进程时进程会失败，而不是悄悄改扫 /scan/lab。
CMD ["python", "-m", "vulnguard", "serve", "--host", "0.0.0.0", "--port", "8000", "--source", "docker", "--path", "/scan/lab", "--scan-on-start"]
