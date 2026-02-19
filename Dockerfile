FROM python:3.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        wimtools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY extract_iso.py .

# Mount your ISO at /data/input.iso and the output directory at /data/rootfs
VOLUME ["/data"]

ENTRYPOINT ["python", "extract_iso.py"]
CMD ["--help"]
