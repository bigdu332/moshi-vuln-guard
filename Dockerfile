FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY vulnguard ./vulnguard
COPY demo ./demo
COPY ai-process ./ai-process
ENV PYTHONPATH=/app
EXPOSE 8000
CMD ["python", "-m", "vulnguard", "serve", "--host", "0.0.0.0", "--port", "8000", "--source", "auto", "--path", "/scan/lab", "--scan-on-start"]
