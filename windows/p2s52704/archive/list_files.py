import re, urllib.request

h = urllib.request.urlopen("https://attackit.co.il/files/", timeout=30).read().decode("utf-8", "replace")
links = re.findall(r'<a href="([^"]+)">([^<]+)</a>', h)
files = [(href, name) for href, name in links if "icons/" not in href and href != "/"]
print(f"TOTAL: {len(files)}")
print()

sens_kw = [
    ".env", ".key", ".pem", ".p12", ".pfx", "passwd", "secret", "credential",
    "token", "session", "dump", ".sql", "bak", ".old", ".orig", ".git", ".svn",
    "docker", "jenkins", "gemfile", "cargo", "composer", "global.asax",
    "web.config", "phpunit", "artisan", "wp-config", "xmlrpc", "config",
    "settings", "database", "connection", "private", "cert", "id_rsa",
    "phpinfo", "phpunit", "composer", "package.json", "requirements",
    "pipfile", "pom.xml", "build.gradle", "rakefile", "gulpfile",
    "gruntfile", "vagrant", "ansible", "terraform", "vault", "k8s",
    "helm", "docker-compose", ".htaccess", "web.config", "nlog",
    "log4j", "log4net", "config.", "appsettings", "settings.",
]
for href, name in sorted(files, key=lambda x: x[1].lower()):
    nl = name.lower()
    is_dir = href.endswith("/")
    flags = []
    if any(k in nl for k in sens_kw):
        flags.append("SENSITIVE")
    if is_dir:
        flags.append("DIR")
    tag = "|".join(flags) if flags else ""
    if tag:
        print(f"  [{tag:12}] {name}")
