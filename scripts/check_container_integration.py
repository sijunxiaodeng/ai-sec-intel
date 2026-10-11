"""Exercise the real container HTTP bridge using only seeded synthetic records.

The Compose integration job disables background work and public networking.
This validates deployment wiring; it is not independent accuracy or SLA evidence.
"""
import argparse
import json
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8023")
    args = parser.parse_args()
    base = args.base_url.rstrip("/")

    def request(path, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(base + path, data=data,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as response:
            return json.load(response)

    health = request("/api/intelligence/health")
    assert health.get("database_available") is True, health
    team = request("/api/intelligence/team?ai_only=true&limit=100")
    expected = {item.get("cve_id") or item.get("id") for item in team.get("items", [])}
    assert expected and all(cve.startswith("CVE-2099-") for cve in expected), team

    # Repeated collection must preserve all records without duplication.
    request("/api/collect", {"keyword": ""})
    request("/api/collect", {"keyword": ""})
    items = request("/api/items").get("items", [])
    identifiers = [item["cve_id"] for item in items]
    assert set(identifiers) == expected and len(identifiers) == len(expected), items

    synced = request("/api/library/team-sync", {"max_documents": 200})
    assert synced.get("status") == "ok" and synced.get("ok", 0) > 0, synced
    library = request("/api/library")
    count = library.get("overview", {}).get("documents", 0)
    assert count > 0, library
    request("/api/library/team-sync", {"max_documents": 200})
    assert request("/api/library").get("overview", {}).get("documents") == count
    print(json.dumps({"synthetic_integration": "passed", "cve_records": len(expected),
                      "library_documents": count, "sla_or_accuracy_claim": False}))


if __name__ == "__main__":
    main()
