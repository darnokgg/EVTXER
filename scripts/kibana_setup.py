#!/usr/bin/env python3
"""Create the Hayabusa data view and dashboard in Security Onion's Kibana.

Security Onion fronts Kibana with a Kratos-authenticated proxy, so requests need
BOTH a Kratos browser session (to get past the proxy) AND Elasticsearch basic
auth (which Kibana itself checks). This script establishes both, then uses
Kibana's own APIs so Kibana applies the correct saved-object migrations rather
than us hand-writing version metadata.

Only creates objects whose ids start with `hayabusa-`. It never touches Security
Onion's own saved objects, and --delete removes exactly what it created.

Usage:
  python scripts/kibana_setup.py --dry-run       # show what would happen
  python scripts/kibana_setup.py                 # create data view + dashboard
  python scripts/kibana_setup.py --delete        # remove what this created
"""
import argparse
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# stdlib-only HTTP so this runs offline with no pip packages installed
import so_http as requests

# Optional. Absent on a field machine - credentials then come from SO_ES_* env vars.
DEFAULT_ENV = os.environ.get("SO_ENV_FILE", "")
DATA_VIEW_ID = "hayabusa-evtx-dataview"
DASHBOARD_ID = "hayabusa-overview-dashboard"
INDEX_PATTERN = "hayabusa-evtx-*"
ID_PREFIX = "hayabusa-"


def load_env(path):
    """Read SO_ES_* settings from an env file if present, then the environment.

    The file is optional. On a field machine there is no .env, so everything
    comes from environment variables.
    Environment always wins over the file.
    """
    env = {}
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip()
    for key in ("SO_ES_HOST", "SO_ES_PORT", "SO_ES_USER",
                "SO_ES_PASSWORD", "SO_ES_INSECURE"):
        if os.environ.get(key):
            env[key] = os.environ[key]
    missing = [k for k in ("SO_ES_HOST", "SO_ES_USER", "SO_ES_PASSWORD") if not env.get(k)]
    if missing:
        sys.exit(f"missing credentials: {', '.join(missing)}. "
                 "Set them as environment variables or pass --env-file.")
    return env


class Kibana:
    def __init__(self, env):
        self.host = env["SO_ES_HOST"]
        self.auth = (env["SO_ES_USER"], env["SO_ES_PASSWORD"])
        self.base = f"https://{self.host}/kibana"
        self.s = requests.Session()
        # Certificates are checked unless SO_ES_INSECURE=1 (a lab with a
        # self-signed certificate): the login sends the password.
        self.s.verify = env.get("SO_ES_INSECURE", "").lower() not in ("1", "true", "yes")
        self._login()

    def _login(self):
        """Kratos self-service browser login -> session cookie for the proxy."""
        r = self.s.get(
            f"https://{self.host}/auth/self-service/login/browser",
            headers={"Accept": "application/json"}, timeout=25,
        )
        r.raise_for_status()
        flow = r.json()
        csrf = next(
            (n["attributes"]["value"] for n in flow["ui"]["nodes"]
             if n.get("attributes", {}).get("name") == "csrf_token"), None,
        )
        r = self.s.post(
            flow["ui"]["action"],
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            json={"method": "password", "identifier": self.auth[0],
                  "password": self.auth[1], "csrf_token": csrf},
            timeout=25,
        )
        if r.status_code != 200:
            sys.exit(f"Kratos login failed: HTTP {r.status_code}")
        if "ory_kratos_session" not in self.s.cookies:
            sys.exit("Kratos login did not return a session cookie")

    def call(self, method, path, **kw):
        kw.setdefault("timeout", 120)
        headers = {"kbn-xsrf": "true"}
        headers.update(kw.pop("headers", {}))
        return self.s.request(method, self.base + path, auth=self.auth,
                              headers=headers, **kw)


def ensure_data_view(kb, dry_run):
    r = kb.call("GET", f"/api/data_views/data_view/{DATA_VIEW_ID}")
    if r.status_code == 200:
        print(f"  data view '{DATA_VIEW_ID}' already exists")
        return True
    if dry_run:
        print(f"  WOULD create data view {DATA_VIEW_ID} -> {INDEX_PATTERN}")
        return True
    r = kb.call("POST", "/api/data_views/data_view", json={
        "data_view": {
            "id": DATA_VIEW_ID,
            "title": INDEX_PATTERN,
            "name": "Hayabusa EVTX detections",
            "timeFieldName": "@timestamp",
        }
    })
    if r.status_code in (200, 201):
        print(f"  created data view {DATA_VIEW_ID} -> {INDEX_PATTERN}")
        return True
    print(f"  FAILED to create data view: HTTP {r.status_code} {r.text[:400]}")
    return False


def import_objects(kb, ndjson_path, dry_run):
    if dry_run:
        n = sum(1 for line in open(ndjson_path, encoding="utf-8") if line.strip())
        print(f"  WOULD import {n} objects from {ndjson_path}")
        return True
    with open(ndjson_path, "rb") as f:
        r = kb.call(
            "POST", "/api/saved_objects/_import",
            params={"overwrite": "true"},
            files={"file": ("import.ndjson", f, "application/ndjson")},
        )
    if r.status_code != 200:
        print(f"  import HTTP {r.status_code}: {r.text[:600]}")
        return False
    body = r.json()
    print(f"  success={body.get('success')}  created={body.get('successCount')}")
    for err in body.get("errors", []) or []:
        e = err.get("error", {})
        print(f"    ERROR {err.get('type')}/{err.get('id')}: "
              f"{e.get('type')} {str(e.get('reason') or e)[:220]}")
    return bool(body.get("success"))


def delete_created(kb, dry_run):
    r = kb.call("GET", "/api/saved_objects/_find",
                params={"type": ["dashboard", "lens", "index-pattern"], "per_page": 200})
    if r.status_code != 200:
        sys.exit(f"could not list saved objects: HTTP {r.status_code}")
    targets = [o for o in r.json().get("saved_objects", [])
               if str(o.get("id", "")).startswith(ID_PREFIX)]
    if not targets:
        print("  nothing to delete")
        return
    for o in targets:
        print(f"  {'WOULD delete' if dry_run else 'deleting'} {o['type']}/{o['id']}")
        if not dry_run:
            kb.call("DELETE", f"/api/saved_objects/{o['type']}/{o['id']}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ndjson", default="output/hayabusa-panels.ndjson")
    ap.add_argument("--env-file", default=DEFAULT_ENV)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--delete", action="store_true",
                    help=f"Remove saved objects whose id starts with '{ID_PREFIX}'")
    args = ap.parse_args()

    kb = Kibana(load_env(args.env_file))
    print(f"connected to https://{kb.host}/kibana as {kb.auth[0]}")

    if args.delete:
        print("\nDELETE")
        delete_created(kb, args.dry_run)
        return

    print("\n1. data view")
    if not ensure_data_view(kb, args.dry_run):
        sys.exit(1)

    print("\n2. panels + dashboard")
    ok = import_objects(kb, args.ndjson, args.dry_run)

    if not args.dry_run and ok:
        print(f"\nOpen: https://{kb.host}/kibana/app/dashboards#/view/{DASHBOARD_ID}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
