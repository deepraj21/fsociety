# INTENTIONALLY WEAK — demo target for hadolint / checkov / trivy.
FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
COPY . /app
WORKDIR /app
USER root
CMD ["python3", "app.py"]
