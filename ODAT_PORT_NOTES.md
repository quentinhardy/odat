# Porting ODAT from cx_Oracle to python-oracledb (thin mode)

Baseline: `quentinhardy/odat` branch `master-python3`, commit `11c5f25` (2026-03-31).
Checked against `oracledb` 26.0.1.

## Why

- `cx_Oracle` needs Oracle Instant Client. Kali's `odat` / `oracle-instantclient-*` packages are amd64-only,
  so they can't be used on arm64 (macOS, Kali VM).
- `oracledb` in **thin mode** is pure Python and needs no Instant Client. It runs on macOS arm64 from a venv
  and can be routed through a SOCKS proxy (see `nne_check.py`).
- Target check (`nne_check.py` probe) returned `ORA-01017`, so NNE is not required and the DB is 12.1 or newer.
  Thin mode works against it.

## Thin-mode limitations (keep a `--thick` fallback)

| Situation | Thin-mode error | Workaround |
|---|---|---|
| Server requires NNE / checksumming (`SQLNET.ENCRYPTION_SERVER=REQUIRED`, `CRYPTO_CHECKSUM_SERVER=REQUIRED`) | `DPY-3001` | thick mode |
| Database older than 12.1 | `DPY-3010` | thick mode |
| Account only has 10G password verifier | `DPY-3015` | thick mode |
| `CVE_2012_3137.py` (11g O5LOGON) | n/a | thick mode / old DB only |

The `oracledb` package does both modes: `oracledb.init_oracle_client()` switches it to thick mode
(Instant Client needed then). So one code base covers everything. Default to thin and add `--thick`.

## Step 1: driver shim (minimal diff)

13 files `import cx_Oracle`. Instead of editing each one's API usage, add `OracleDriver.py`:

```python
import oracledb as cx_Oracle   # same module-level API: connect, SYSDBA, SYSOPER, NUMBER, STRING, Cursor, Error
```

and replace `import cx_Oracle` with `from OracleDriver import cx_Oracle` everywhere.
Verified in `oracledb` 26: `STRING`, `NUMBER`, `SYSDBA`, `SYSOPER`, `Cursor(conn)` all exist.
Files: `odat.py`, `OracleDatabase.py`, `Utils.py`, `CVE_2012_3137.py`, `DbmsLob.py`, `DbmsXslprocessor.py`,
`DbmsScheduler.py`, `Ctxsys.py`, `UtlFile.py`, `UtlTcp.py`, `Oradbg.py`, `UsernameLikePassword.py`.

Later cleanup (optional): rename the alias to `oracledb` and use `conn.cursor()` instead of `cx_Oracle.Cursor(conn)`.

## Step 2: client initialisation (`odat.py:793-800`)

```python
cx_Oracle.init_oracle_client(config_dir=cfgPath, driver_name=args['client-driver'], error_url="")
logging.debug("Oracle Client Version: {0}".format(cx_Oracle.clientversion()))
```

- Call `init_oracle_client()` only if `--thick` is given. Otherwise it switches to thick mode and needs Instant Client.
- `clientversion()` raises `DPY-2021` in thin mode. Guard it with `oracledb.is_thin_mode()`.
- `conf/sqlnet.ora` (timeouts) is only read in thick mode. In thin mode pass `tcp_connect_timeout=60` to `connect()`.
- `--client-driver` → in thin mode pass `driver_name=` to `connect()` (`ConnectParams`), so the server-side
  `v$session_connect_info.client_driver` stays `SQL*PLUS` like before.

## Step 3: connect calls (breaking: these fail without changes)

`oracledb.connect()` no longer accepts `threaded=`, `encoding=` or `nencoding=` (`TypeError: unexpected keyword
argument`). It also does **not** accept `"user/pass@dsn"` as `user=` (`DPY-4001: no credentials specified`).

| Location | Change |
|---|---|
| `OracleDatabase.py:63,70` `__generateConnectionString__` | keep the `(DESCRIPTION=...)` descriptor but store user, password and descriptor separately |
| `OracleDatabase.py:98-117` | `cx_Oracle.connect(user=u, password=p, dsn=desc, mode=..., tcp_connect_timeout=...)`; drop `threaded/encoding/nencoding` |
| `Utils.py:96-100` `getOracleConnection` | same: pass `user=`, `password=`, `dsn=` explicitly |
| `CVE_2012_3137.py:117` | same (module only useful in thick mode anyway) |

Passing user and password separately also fixes passwords containing `/` or `@`, which the old
`user/pass@...` string broke.

Keep the `threaded` parameter of `OracleDatabase.connection()` so callers (`PasswordGuesser.py:174`, `Oradbg.py:41`)
don't change. Just don't forward it.

## Step 4: error matching (the real work)

ODAT decides almost everything with `if "ORA-xxxxx: " in str(e)`. Two problems in thin mode:

1. **Listener and network errors become `DPY-` codes.** The message sometimes contains `(Similar to ORA-12505)`,
   but **without the trailing `": "`** that ODAT's constants include. So checks fail silently and the guessers
   report wrong results.
2. **Message text is localized by the server.** In thin mode the server sends the message text, and this target
   answers in Polish (`ORA-01017: niepoprawna nazwa użytkownika/hasło`). Any match on English text breaks:
   - `PasswordGuesser.py:182` `"connection as SYS should be as SYSDBA or SYSOPER" in str(status)`.
     Replace it with a code check for `ORA-28009`. Without this, SYS/password is never retried as SYSDBA.

**Fix: match on error codes, not text.** Add one helper and use it everywhere:

```python
def oraCode(e):
    """Return 'ORA-01017' / 'DPY-6003' / ... from an oracledb exception or an error string."""
    if isinstance(e, cx_Oracle.Error) and e.args and hasattr(e.args[0], "full_code"):
        return e.args[0].full_code
    m = re.search(r"\b(ORA|DPY|TNS)-\d{4,5}", str(e))
    return m.group(0) if m else None
```

Then translate thin-mode codes to the ORA codes ODAT already handles:

| ODAT constant / list | ORA code (thick) | Thin-mode equivalent |
|---|---|---|
| `SIDGuesser` / service name guesser: unknown service | `ORA-12514` | `DPY-6001` |
| `SIDGuesser`: unknown SID | `ORA-12505`, `TNS-12505` | `DPY-6003` |
| `SIDGuesser`: `ORA-12516/12519/12520/12521` | same | `DPY-6000` ("Listener refused connection. (Similar to ORA-xxxxx)"); take the code from the text |
| `ERROR_CONN_IMPOSS` (no listener) `ORA-12541` | `ORA-12541` | `DPY-6005` + `ConnectionRefusedError` |
| `ORA-12545` (host not found) | `ORA-12545` | `DPY-6005` + `socket.gaierror` |
| `Http.ERROR_TIMEOUT` `ORA-12535` (connect timeout only) | `ORA-12535` | `DPY-6005` + `TimeoutError` |
| `ERROR_NOT_CONNECTED` `ORA-03114` / `ORA-03113` | same | `DPY-4011` |
| `ORA-12154` (cannot resolve connect identifier) | `ORA-12154` | `DPY-4000` / `DPY-4017` / `DPY-4018` |
| `ERROR_UNABLE_TO_ACQUIRE_ENV` | thick-only text | not applicable in thin; drop or keep for `--thick` |

Error codes raised **by the server** (`ORA-01017`, `ORA-28000`, `ORA-28001`, `ORA-28009`, `ORA-01031`,
`ORA-27101`, `ORA-29283`, `ORA-22288`, `ORA-24247`, `ORA-00904`, `ORA-24248`, `ORA-29xxx` from UTL_* /
external tables, `ORA-00905` in `Passwords.py:117`) stay the same in thin mode. Only the match style
(code rather than `"code: "` + text) has to change.

New thin-only cases worth reporting in the password guesser:

- `DPY-3015`: the account exists but only has a 10G verifier. Report "retry with `--thick`", not "wrong password".
- `DPY-3001` / `DPY-3010` on first connect: abort with "use `--thick`" instead of guessing on.

## Step 5: SOCKS proxy (`--socks`)

Reuse `enable_socks()` from `nne_check.py` (patches `socket.create_connection` and, for `socks5h`,
`socket.getaddrinfo`). Call it in `odat.py` right after argument parsing, before any connection.

- Covers all `oracledb` thin-mode connections.
- `Tnscmd.py:63-66` and `Tnspoison.py:282-283` use `socket.socket()` + `.connect()`. Change them to
  `socket.create_connection((host, port), timeout)` so the same patch covers them.
- Does **not** work: thick mode (OCI opens its own sockets; use `proxychains` there), scapy sniffing in
  `CVE_2012_3137.py`, and anything that needs the target to connect back to you (SMB capture, `MinHtppServer`,
  reverse shells). Those need a direct route or a reverse tunnel.

## Step 6: ship the thin-mode tester in the repo

Add `nne_check.py` to the repo root as `thincheck.py`. It's the first thing to run against a new target.
It answers "thin or `--thick`?" with one harmless login as a non-existent user. With `-u` it checks one credential pair.

- Move `enable_socks()` into a shared module (e.g. `SocksProxy.py`) and import it from both `odat.py` and `thincheck.py`,
  so there's one SOCKS implementation.
- Reuse the `oraCode()` helper and the DPY/ORA hint table from step 4 instead of the script's own `HINTS` dict.
- Change the shebang to `#!/usr/bin/env python3` (the local copy uses `python3.14`).
- Document it in `README.md` next to the install section:
  `python3 thincheck.py <host> <port> <service> [--socks socks5h://127.0.0.1:1080]`.
- Optional later: expose it as an ODAT module (`odat.py thincheck -s ... -p ... -d ...`) so it gets ODAT's standard
  connection options.

## Step 7: dependencies

Replace `cx_Oracle` with `oracledb` (+ `pysocks` for `--socks`). On macOS (MacPorts Python 3.14):

```bash
/opt/local/bin/python3.14 -m venv --system-site-packages ~/odat-venv
~/odat-venv/bin/pip install oracledb pysocks colorlog termcolor passlib python-libnmap pycryptodome scapy argcomplete
```

Python 3.12+ removed `asyncore`; if something still imports it, add `pyasyncore`.

## Step 8: testing

1. Local target: `docker run -d -p 1521:1521 -e ORACLE_PASSWORD=Passw0rd gvenzl/oracle-free`
   (arm64 image available). Gives a 23ai DB to test thin mode.
2. Run `testAllOdatModules.sh` from the repo against it, once in thin mode and once with `--thick`
   (on an amd64 box with Instant Client), and compare output.
3. Specifically check:
   - `sidguesser` / `snguesser`: finds the right SID/service, no false positives from DPY errors.
   - `passwordguesser`: valid creds found, locked accounts (`ORA-28000`) skipped, `SYS` retried as SYSDBA.
   - Polish/other server language: set `NLS_LANGUAGE` on the test DB or test against the real target.
   - `--socks` with a local `ssh -D` proxy.
4. Only then the real target. Password guessing can lock accounts, so agree on the policy with the client first.
