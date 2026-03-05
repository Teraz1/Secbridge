# Contributing to SecBridge

Thank you for helping the community! Every integration kit you contribute saves other engineers hours of work.

---

## What Makes a Good Contribution

The best contributions come from **engineers who have already solved the integration problem themselves** and want to package it for others. You don't need to be an expert — you just need:

- Access to the source product (e.g. a Sangfor NGAF firewall)
- Real log samples from it
- A working Linux VM where you tested the kit

---

## Step-by-Step: Adding a New Integration Kit

### 1. Create Your Integration Folder

```bash
git clone https://github.com/YOUR_USERNAME/secbridge.git
cd secbridge

# Copy the template
cp -r templates/integration-template integrations/<source-product>-to-<destination>

# Example:
cp -r templates/integration-template integrations/fortinet-fortigate-to-sentinelone
```

### 2. Collect Real Log Samples

This is the most important step. Before writing a single line of code, collect at least 5 real log lines from the product. Add them to `docs/SAMPLE_LOGS.md`.

Without real samples, the parser will be guesswork.

**How to capture Sangfor-style logs:**
```bash
# On your collector VM, listen for raw syslog and capture it:
sudo tcpdump -i any udp port 514 -A -l 2>/dev/null | tee /tmp/raw-samples.txt
```

Then trigger events on the source product (login, block a connection, trigger an IPS rule) and capture the raw output.

### 3. Build the Parser

Your parser lives in `parser/<product>_parser.py`. It must:

- Accept raw log lines as input
- Extract all meaningful fields into a dict
- Output structured JSON
- Support a `--test` CLI flag that runs against built-in sample logs
- Return exit code 0 on success, non-zero on failure

Use `integrations/sangfor-ngaf-to-sentinelone/parser/sangfor_parser.py` as a reference implementation.

### 4. Build the Installer

Your `scripts/install.sh` must:

- Support Ubuntu 22.04 / 24.04 AND Rocky Linux 9
- Prompt for credentials (never hardcode)
- Be testable with `bash -n scripts/install.sh`
- Not use unsupported CLI flags for third-party installers
- Use `ip route get` for IP detection (not `hostname -I`)

### 5. Test Checklist

Before opening a PR, run through this checklist:

```bash
# Bash syntax
bash -n scripts/install.sh && echo "OK"
bash -n scripts/deploy-parser.sh && echo "OK"
bash -n scripts/test-syslog.sh && echo "OK"

# Python syntax
python3 -m py_compile parser/<product>_parser.py && echo "OK"

# Parser functional test
python3 parser/<product>_parser.py --test

# Verify all sample log types produce output
# Verify no field extracts a wrong value (check each field manually)
```

### 6. Document It

Your `docs/README.md` must include:
- Prerequisites
- Step-by-step install guide
- How to configure the source product to send syslog
- How to verify it's working (with exact commands)
- A troubleshooting table (at least 4 common issues)
- A table of all parsed fields with examples

### 7. Open a Pull Request

PR title format: `feat: add <source> → <destination> integration kit`

In your PR description, include:
- What products you tested on (versions matter)
- Screenshot or output of `python3 parser/<product>_parser.py --test`
- Confirmation of OS tested on

---

## Bug Reports & Fixes

If an existing kit has a bug:

1. Open an issue with the label `bug` and the integration kit name
2. Include: OS version, exact error message, and the log line that failed
3. Or better yet — fix it and open a PR

---

## Requesting a New Integration

If you need an integration that doesn't exist yet:

1. Open an issue with the label `integration-request`
2. Use the template in `.github/ISSUE_TEMPLATE/integration-request.md`
3. Include real sample log lines if you can — this makes it 10x easier for a contributor to build the kit

---

## Code of Conduct

- Be constructive, not critical
- Security engineers come from many backgrounds — be patient with questions
- Credit contributors in commit messages and the integration README

---

*Thanks for making SecBridge better for everyone.*
