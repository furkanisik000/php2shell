#!/usr/bin/env python3
"""targets/flask_ssti.py — VULNERABLE Flask target (for authorized red-team PoC testing).

Reproduces the classic Server-Side Template Injection (CWE-94) that underlies
Jinja2/Flask CVE-2024-56201 / CVE-2024-5088 / CVE-2024-22194: user-controlled
input is passed straight into render_template_string(). An attacker can escape
the Jinja2 sandbox via the object-subclass chain and reach os.system() -> RCE.

This is a DELIBERATELY vulnerable lab target, run in Docker, to verify the P2S
native PoC produces a REAL RCE proof (id output).
"""
from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/greet")
def greet():
    # VULN (CWE-94): user input is concatenated into the template SOURCE, which
    # render_template_string() then compiles + executes -> SSTI -> RCE.
    # This is the exact flaw behind Jinja2/Flask CVE-2024-56201 / -5088 / -22194.
    name = request.args.get("name", "world")
    return render_template_string("Hello " + name + "!")


@app.route("/")
def index():
    return "<h1>Flask SSTI lab</h1><a href='/greet?name=world'>/greet</a>"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
