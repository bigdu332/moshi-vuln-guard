FROM python:3.12-slim
WORKDIR /opt/app
COPY app/ /opt/app/
EXPOSE 8081
CMD ["python", "-m", "http.server", "8081", "--bind", "0.0.0.0", "--directory", "/opt/app"]
