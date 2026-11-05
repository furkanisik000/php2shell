import sys, re, urllib.request

URL = sys.argv[1] if len(sys.argv) > 1 else "https://attackit.co.il/files/php/info.php"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
req = urllib.request.Request(URL, headers={"User-Agent": UA})
html = urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "replace")

def find(label):
    # phpinfo rows: <td class="e">LABEL</td><td class="v p">VALUE</td>
    m = re.search(r'<td class="e">' + re.escape(label) + r'</td>\s*<td[^>]*>(.*?)</td>', html, re.S | re.I)
    if not m:
        return None
    val = re.sub(r"<[^>]+>", "", m.group(1))
    return val.strip()[:200]

for k in ["Server API", "Server", "SAPI", "Architecture",
          "max_input_vars", "memory_limit", "post_max_size", "upload_max_filesize",
          "session.use_strict_mode", "session.upload_progress.enabled", "session.use_cookies",
          "display_errors", "error_reporting", "PHP Version", "PHP SAPI"]:
    v = find(k)
    print(f"{k:32}: {v if v is not None else '--'}")

# extra raw hints
for token in ["mod_php", "php-fpm", "PHP-FPM", "fpm-fcgi", "prefork", "worker", "event",
              "Apache", "nginx", "SAPI Name", "Server API"]:
    hits = len(re.findall(re.escape(token), html, re.I))
    if hits:
        print(f"raw-token {token!r}: {hits}")
