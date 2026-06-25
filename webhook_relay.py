#!/usr/bin/env python3
"""Webhook Relay Server."""
import json
import hmac
import hashlib
import argparse
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

class WebhookHandler(BaseHTTPRequestHandler):
    forward_urls = []
    secret = None
    log_entries = []
    
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        
        # Verify signature if secret is set
        if self.secret:
            sig = self.headers.get("X-Hub-Signature-256", "")
            expected = "sha256=" + hmac.new(
                self.secret.encode(), body, hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(sig, expected):
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"Invalid signature")
                return
        
        # Log
        entry = {
            "timestamp": datetime.now().isoformat(),
            "path": self.path,
            "headers": dict(self.headers),
            "body_size": len(body),
        }
        WebhookHandler.log_entries.append(entry)
        
        # Forward
        forwarded = 0
        for url in self.forward_urls:
            try:
                req = urllib.request.Request(
                    url, data=body, method="POST",
                    headers={"Content-Type": self.headers.get("Content-Type", "application/json")}
                )
                urllib.request.urlopen(req, timeout=10)
                forwarded += 1
            except Exception as e:
                print(f"  Forward error to {url}: {e}")
        
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"received": True, "forwarded": forwarded}).encode())
    
    def log_message(self, format, *args):
        print(f"[{datetime.now():%H:%M:%S}] {args[0]}")

def main():
    parser = argparse.ArgumentParser(description="Webhook Relay")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--forward", nargs="+", default=[])
    parser.add_argument("--secret")
    args = parser.parse_args()
    
    WebhookHandler.forward_urls = args.forward
    WebhookHandler.secret = args.secret
    
    server = HTTPServer(("0.0.0.0", args.port), WebhookHandler)
    print(f"Webhook relay on port {args.port}")
    print(f"Forwarding to: {args.forward}")
    server.serve_forever()

if __name__ == "__main__":
    main()
