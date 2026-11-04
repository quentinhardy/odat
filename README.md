# ODAT python-oracledb Port

A fork of [ODAT](https://github.com/quentinhardy/odat) (Oracle Database Attacking Tool) ported from `cx_Oracle` to `python-oracledb` with support for arm64 (Apple Silicon, arm64 Kali) and SOCKS proxy routing.

## What is ODAT?

ODAT is an open-source penetration testing tool that tests the security of Oracle Databases remotely. It can:
- Search for valid SIDs and service names
- Brute force database credentials
- Execute system commands on the database server
- Download and upload files
- Escalate privileges
- Exploit CVEs

## Why this port?

**The problem:** The original ODAT depends on `cx_Oracle`, which requires the Oracle Instant Client library. This library is only available for amd64, preventing ODAT from running on arm64 systems (Apple Silicon, arm64 Kali).

**The solution:** Port ODAT to `python-oracledb` in **thin mode**—a pure Python driver that:
- Needs no Oracle Instant Client
- Runs on Linux and macOS, including arm64
- Supports SOCKS proxy routing (e.g., through SSH tunnels)
- Still offers thick mode (Instant Client) when needed for older databases or encryption requirements

## Quick start

```bash
cd odat

# Install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Check if thin mode works against a target
./thincheck.py -s 10.0.0.5 -p 1521 -n ORCLPDB1

# Run ODAT
./odat.py -h
```

For full documentation and examples, see [`odat/README.md`](odat/README.md).

## Project structure

- **`odat/`** — ODAT source code (python-oracledb thin mode fork)
- **`analysis/`** — Testing analysis and notes
- **`notes/`** — Testing documentation and findings
- **`adb19/`, `adb26/`, `free23/`** — Test database configurations
- **`ODAT_PORT_NOTES.md`** — Detailed technical notes on the port (driver shim, error handling, SOCKS, etc.)

## Key changes from the original

1. **Driver shim** (`OracleDriver.py`) — Minimal compatibility layer from `cx_Oracle` to `oracledb`
2. **Error handling** — Thin-mode errors (DPY-xxxx) translated to equivalent ORA-xxxxx codes
3. **SOCKS proxy support** — Route connections through proxies with `--socks`
4. **Thick mode** — Optional `--thick` flag for Oracle Instant Client when needed
5. **Client driver name** — `--client-driver` option to control `V$SESSION_CONNECT_INFO`

## Compatibility

| Mode | Requirements | Use case |
|---|---|---|
| **Thin** (default) | Python 3 only | arm64, proxied access, modern databases (12.1+) |
| **Thick** (`--thick`) | Oracle Instant Client | Native Network Encryption, older databases, 10G password verifiers |

Use `./thincheck.py` to check which mode works against a target.

---

**For detailed technical information**, see [`ODAT_PORT_NOTES.md`](ODAT_PORT_NOTES.md).
