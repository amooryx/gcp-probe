#!/usr/bin/env python3
"""
GCP Probe — Google Cloud Platform Security Reconnaissance Tool
Checks GCS bucket exposure, metadata server access, and IAM misconfigurations.
Author: Omar Khalid (amooryx) | github.com/amooryx/gcp-probe
AUTHORIZED USE ONLY — for authorized cloud pentests.
"""

import argparse
import json
import sys
import urllib.parse
import urllib.request
import urllib.error

METADATA_URL    = "http://metadata.google.internal/computeMetadata/v1/"
METADATA_FIELDS = [
    "project/project-id",
    "project/numeric-project-id",
    "instance/service-accounts/default/email",
    "instance/service-accounts/default/scopes",
    "instance/service-accounts/default/token",
    "instance/hostname",
    "instance/id",
    "instance/zone",
    "instance/tags",
    "instance/attributes/",
]

def fetch_metadata(field: str, timeout: float = 5) -> str | None:
    url = METADATA_URL + field
    req = urllib.request.Request(url)
    req.add_header("Metadata-Flavor", "Google")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(4096).decode(errors="ignore")
    except Exception:
        return None

def check_gcs_bucket(bucket_name: str) -> dict:
    """Check if a GCS bucket is publicly accessible."""
    url = f"https://storage.googleapis.com/{urllib.parse.quote(bucket_name)}"
    result = {"bucket": bucket_name, "url": url, "public": False, "listable": False}
    try:
        with urllib.request.urlopen(url + "?maxResults=10", timeout=10) as resp:
            body = resp.read(4096).decode(errors="ignore")
            result["public"]   = True
            result["listable"] = "items" in body or "kind" in body
            if result["listable"]:
                print(f"  [!!!] PUBLIC & LISTABLE: gs://{bucket_name}")
            else:
                print(f"  [+]   Accessible: gs://{bucket_name}")
    except urllib.error.HTTPError as e:
        result["status"] = e.code
        if e.code == 403:
            result["note"] = "Bucket exists but access denied"
    except Exception:
        pass
    return result

def probe_metadata() -> dict:
    """Try to access GCE instance metadata server (detects if running on GCE)."""
    results = {}
    print("[*] Probing GCE metadata server ...")
    for field in METADATA_FIELDS:
        val = fetch_metadata(field)
        if val:
            key = field.replace("/", "_").replace("?", "")
            results[key] = val.strip()
            sensitive = any(kw in field for kw in ["token", "scopes", "attributes"])
            flag = " [!!!] SENSITIVE" if sensitive else ""
            print(f"  [+] {field}: {val[:60]}{flag}")
    return results

def generate_bucket_names(keyword: str) -> list[str]:
    suffixes = ["", "-prod", "-dev", "-staging", "-backup", "-data", "-assets",
                "-static", "-public", "-logs", "-archive", "-storage"]
    prefixes = ["", f"{keyword}-"]
    names = []
    for p in prefixes:
        for s in suffixes:
            names.append(f"{p}{keyword}{s}".lstrip("-"))
    return list(set(names))

def main():
    parser = argparse.ArgumentParser(
        description="GCP Probe — GCP Security Reconnaissance (Authorized use only)",
    )
    parser.add_argument("--metadata",  action="store_true", help="Probe GCE metadata server (from inside GCE)")
    parser.add_argument("--buckets",   help="Target keyword for GCS bucket permutation testing")
    parser.add_argument("--bucket",    nargs="*", help="Specific bucket names to test")
    parser.add_argument("--out",       help="Output JSON file")
    args = parser.parse_args()

    if not (args.metadata or args.buckets or args.bucket):
        parser.print_help()
        sys.exit(1)

    results = {}

    if args.metadata:
        results["metadata"] = probe_metadata()

    bucket_names = []
    if args.buckets:
        bucket_names.extend(generate_bucket_names(args.buckets))
    if args.bucket:
        bucket_names.extend(args.bucket)

    if bucket_names:
        print(f"[*] Testing {len(bucket_names)} GCS bucket names ...")
        bucket_results = [check_gcs_bucket(b) for b in bucket_names]
        public = [b for b in bucket_results if b.get("public")]
        print(f"[+] {len(public)} public buckets found")
        results["buckets"] = bucket_results

    if args.out:
        with open(args.out, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[*] Results → {args.out}")

if __name__ == "__main__":
    main()
