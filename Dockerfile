FROM python:3.12-slim
ARG VERSION=dev
LABEL org.opencontainers.image.title="mesh-ext-hello" org.opencontainers.image.version="${VERSION}"
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY hello ./hello
COPY mesh-extension.json icon.svg ./
RUN useradd -r -u 10001 hello && mkdir /data && chown hello /data
USER hello
ENV PORT=8080 HELLO_STATE_FILE=/data/state.json
EXPOSE 8080
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/healthz')"
CMD ["python", "-m", "hello"]
