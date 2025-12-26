import os
import requests

try:
    # Load .env from project root if available
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    # python-dotenv optional; skip if not installed
    pass

class OpnClient:
    def __init__(self, cfg):
        # Resolve credentials from environment first, then YAML config
        base = (os.getenv("OPNSENSE_HOST") or cfg["opnsense"].get("host", "")).rstrip("/")
        api_key = os.getenv("OPNSENSE_API_KEY") or cfg["opnsense"].get("api_key")
        api_secret = os.getenv("OPNSENSE_API_SECRET") or cfg["opnsense"].get("api_secret")

        if not base:
            raise ValueError("OPNsense host missing: set OPNSENSE_HOST or opnsense.host in YAML")
        if not api_key or not api_secret:
            raise ValueError("OPNsense API credentials missing: set OPNSENSE_API_KEY/OPNSENSE_API_SECRET or YAML api_key/api_secret")

        self.base = base
        self.auth = (api_key, api_secret)

    def post(self, path, payload=None):
        url = f"{self.base}{path}"
        r = requests.post(url, json=payload or {}, auth=self.auth, verify=False)
        r.raise_for_status()
        data = r.json()
        if isinstance(data, dict) and data.get("result") == "failed":
            raise ValueError(f"OPNsense API returned failure for {path}: {data}")
        return data

    def get(self, path):
        url = f"{self.base}{path}"
        r = requests.get(url, auth=self.auth, verify=False)
        r.raise_for_status()
        data = r.json()
        if isinstance(data, dict) and data.get("result") == "failed":
            raise ValueError(f"OPNsense API returned failure for {path}: {data}")
        return data
