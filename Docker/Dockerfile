# ODAT in thin mode: no Oracle Instant Client needed, works on amd64 and arm64.
FROM python:3-slim

RUN apt-get update \
	&& apt-get install -y --no-install-recommends git ca-certificates \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN git clone https://github.com/quentinhardy/odat.git
WORKDIR /opt/odat
RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["./odat.py"]
CMD ["-h"]
