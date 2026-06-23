#!/usr/bin/env python3
# tools/v2-classify-auth.py
"""Classify each captured flow: do credentials live in headers, body, or query?

Reads a mitmproxy save-file (.mitm) and prints a per-flow audit:
  host: api.foo.com
    headers contain credential pattern: <yes|no>
    body contains credential pattern:    <yes|no>
"""
import sys
import re
from pathlib import Path
from mitmproxy.io import FlowReader

CRED_PATTERNS = re.compile(
    r"\b("
    r"sk-[A-Za-z0-9_-]{20,}"
    r"|sk-ant-api03-[A-Za-z0-9_-]{20,}"
    r"|sk-or-v1-[a-f0-9]{20,}"
    r"|AIza[A-Za-z0-9_-]{20,}"
    r"|gh[poursa]_[A-Za-z0-9]{20,}"
    r"|Bearer\s+[A-Za-z0-9._-]+"
    r")"
)

def main():
    if len(sys.argv) != 2:
        sys.exit("usage: v2-classify-auth.py <capture-dir>")
    cap = Path(sys.argv[1])
    flow_file = cap / "flows.mitm"
    if not flow_file.exists():
        sys.exit(f"no flows file at {flow_file}")
    with open(flow_file, "rb") as fp:
        for flow in FlowReader(fp).stream():
            host = flow.request.host
            header_blob = "\n".join(f"{k}: {v}" for k, v in flow.request.headers.items())
            body_blob = (flow.request.content or b"").decode("utf-8", errors="replace")
            in_headers = bool(CRED_PATTERNS.search(header_blob))
            in_body = bool(CRED_PATTERNS.search(body_blob))
            print(f"host={host}")
            print(f"  cred-in-headers: {in_headers}")
            print(f"  cred-in-body:    {in_body}")
            if in_body:
                print("  ⚠ CREDENTIAL LEAK PATH — this agent puts credentials in the body.")

if __name__ == "__main__":
    main()
