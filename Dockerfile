FROM python:3.13-slim-trixie
WORKDIR /app
COPY pyproject.toml README.md ./
COPY gatekeep ./gatekeep
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir . \
    && useradd -m gatekeep
USER gatekeep
ENTRYPOINT ["gatekeep"]
CMD ["demo", "--out", "/tmp/runs/demo"]
