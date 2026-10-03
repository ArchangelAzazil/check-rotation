# check-rotation

> Your proxy says it rotates every 10 minutes. This script doesn't take its word for it.

**Proxy Rotation Tester v2**: polls `ipinfo.io` through your proxy, tracks exit IP and region over time, and tells you whether rotation is working, sticky, or just vibing on one IP.

By [Anthony Abella](https://github.com/ArchangelAzazil) · Insanity Security

---

## Features

- **Three modes:** one-shot check, 5-request stickiness test, or a full timed rotation run
- **Auto protocol detection:** `http`, `https`, `socks4`, `socks5` (defaults to HTTP if you don't specify)
- **Failure classification:** tells you *why* it failed instead of just "it broke":
  | Code | Class | Translation |
  |---|---|---|
  | `200` | OK | All good |
  | `407` | AUTH_FAIL | Bad or expired session string / creds |
  | `429` | RATE_LIMITED | The endpoint is throttling you, not the proxy |
  | `000` | CONN_FAIL | Proxy down, timeout, or unreachable |
  | other | HTTP_ERR | Unexpected upstream response |
- **Ctrl+C safe:** interrupt a 60-minute run and you still get the summary report
- **CSV-style logging:** every run writes `rotation_test_YYYYMMDD_HHMMSS.log`
- **TTL verdict:** calculates average time per IP and checks it against a 10-minute TTL

## Requirements

- `bash` 4+ (uses `${VAR^^}`)
- `curl`
- `jq` *(optional; falls back to grep/cut if missing)*

## Usage

```bash
chmod +x rotation_test.sh
./rotation_test.sh [OPTIONS]
```

| Flag | What it does | Default |
|---|---|---|
| `--once` | Check IP once and exit | - |
| `--sticky` | 5 requests, 5 sec apart, are we sticky or not | - |
| `--duration MINUTES` | How long to run | `30` |
| `--interval SECONDS` | Time between checks | `60` |
| `--help` | You're looking at it | - |

You'll be prompted for the proxy, so your credentials don't end up in shell history:

```
[protocol://]user:pass@host:port
```

### Examples

```bash
# Is this thing even alive?
./rotation_test.sh --once

# Quick "are you sticky?" test
./rotation_test.sh --sticky

# Full soak: 60 minutes, check every 30 seconds
./rotation_test.sh --duration 60 --interval 30
```

## Sample output

```
203.0.113.42 - California - 2026-10-03 05:35:01
203.0.113.42 - California - 2026-10-03 05:36:01
🔄 [2026-10-03 05:45:02] 203.0.113.42 (California) → 198.51.100.7 (Texas) [Change #1]
198.51.100.7 - Texas - 2026-10-03 05:45:02
```

## Reading the results

- **IP changes roughly every 10 min:** rotation is healthy ✅
- **Zero changes:** sticky session, or rotation is broken
- **Rotating too fast:** your session isn't as sticky as you paid for
- **Lots of 429s:** back off, the test endpoint is mad at you, not your proxy
- **Lots of 407s:** check your session string / credentials

## Disclaimer

Only test proxies you own or are authorized to use. No credentials are stored in this repo or in the logs. Don't commit yours. 😉

---

*Built on Arch, tested in anger. 🖤*
