You can use docker to rapidly deploy and use odat !

The image uses python-oracledb in thin mode, so no Oracle Instant Client is needed and it builds on
amd64 and arm64.

* Build it with the Dockerfile provided:
```bash
docker build -t odat .
```

* Run it:
```bash
docker run --rm -it odat -h
docker run --rm -it odat all -s 10.0.0.5 -p 1521
```

* Or get an interactive shell in the container:
```bash
docker run --rm -it --entrypoint bash odat
```
