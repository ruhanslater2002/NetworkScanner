# NetScan is a normal user-land network client. The container carries no
# privileged helper and needs no NET_ADMIN capability.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY netscan ./netscan
COPY scanner.py ./

RUN pip install --upgrade pip \
    && pip install .

# Run as an unprivileged user; ICMP discovery uses the platform ping binary.
RUN useradd --create-home --uid 10001 netscan
USER netscan

ENTRYPOINT ["netscan"]
CMD ["--help"]
