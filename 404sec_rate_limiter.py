#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
404sec Advanced Rate Limiter
Protection basique contre le flood de requêtes
Auteur : 404sec

Ceci reste une protection légère.
Pour une vraie protection anti-DDoS → utilise Cloudflare.
"""

from flask import Flask, request, jsonify
from collections import defaultdict, deque
from time import time
import threading
import logging

# ----------------- CONFIGURATION -----------------
MAX_REQUESTS = 40          # Requêtes max
TIME_WINDOW = 60           # Secondes
BLOCK_DURATION = 300       # Secondes de ban (5 min)
WHITELIST = {"127.0.0.1"}  # IPs qui ne sont jamais limitées
# -------------------------------------------------

app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("404sec_ratelimit.log"),
        logging.StreamHandler()
    ]
)

request_history = defaultdict(deque)
blocked_ips = {}
stats = {"total_requests": 0, "blocked_requests": 0}
lock = threading.Lock()

def clean_old_requests(ip, now):
    while request_history[ip] and now - request_history[ip][0] > TIME_WINDOW:
        request_history[ip].popleft()

def is_whitelisted(ip):
    return ip in WHITELIST

def is_currently_blocked(ip):
    with lock:
        expire = blocked_ips.get(ip)
        if expire and time() < expire:
            return True
        if expire:
            del blocked_ips[ip]
        return False

def check_and_record(ip):
    with lock:
        now = time()
        clean_old_requests(ip, now)

        if len(request_history[ip]) >= MAX_REQUESTS:
            blocked_ips[ip] = now + BLOCK_DURATION
            request_history[ip].clear()
            logging.warning(f"IP bloquée : {ip} pour {BLOCK_DURATION} secondes")
            return True

        request_history[ip].append(now)
        return False

@app.before_request
def rate_limit():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if ip:
        ip = ip.split(",")[0].strip()

    stats["total_requests"] += 1

    if is_whitelisted(ip):
        return

    if is_currently_blocked(ip):
        stats["blocked_requests"] += 1
        return jsonify({
            "error": "IP temporarily blocked",
            "retry_after": BLOCK_DURATION
        }), 429

    if check_and_record(ip):
        stats["blocked_requests"] += 1
        return jsonify({
            "error": "Rate limit exceeded",
            "message": "Trop de requêtes. Réessaie plus tard."
        }), 429

@app.route("/")
def home():
    return jsonify({
        "status": "online",
        "message": "404sec Advanced Rate Limiter",
        "author": "404sec"
    })

@app.route("/stats")
def show_stats():
    return jsonify({
        "total_requests": stats["total_requests"],
        "blocked_requests": stats["blocked_requests"],
        "currently_blocked": len(blocked_ips)
    })

if __name__ == "__main__":
    print("=" * 55)
    print("  404sec Advanced Rate Limiter")
    print(f"  Limite : {MAX_REQUESTS} req / {TIME_WINDOW}s")
    print(f"  Ban    : {BLOCK_DURATION}s")
    print("=" * 55)
    app.run(host="0.0.0.0", port=8080)