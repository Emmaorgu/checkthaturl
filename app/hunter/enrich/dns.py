# app/hunter/enrich/dns.py
from __future__ import annotations
from typing import Any, Dict
import dns.resolver, dns.exception

def resolve(domain: str, timeout: float = 3.5) -> Dict[str, Any]:
    r = dns.resolver.Resolver(configure=True)
    r.lifetime = timeout
    r.timeout = timeout

    out: Dict[str, Any] = {"ok": 0, "nxdomain": False}
    a, aaaa, ns, mx = [], [], [], []

    try:
        for rr in r.resolve(domain, "A"):
            a.append(rr.address)
    except dns.resolver.NXDOMAIN:
        out["nxdomain"] = True
    except dns.exception.DNSException:
        pass

    if not out["nxdomain"]:
        try:
            for rr in r.resolve(domain, "AAAA"):
                aaaa.append(rr.address)
        except dns.exception.DNSException:
            pass
        try:
            for rr in r.resolve(domain, "NS"):
                ns.append(str(rr.target).rstrip("."))
        except dns.exception.DNSException:
            pass
        try:
            for rr in r.resolve(domain, "MX"):
                mx.append(str(rr.exchange).rstrip("."))
        except dns.exception.DNSException:
            pass

    # risk:
    risk = 0.0
    if out["nxdomain"]:
        risk = 1.0
    else:
        if not ns:
            risk += 0.40
        if not (a or aaaa):
            risk += 0.30
        # lack of MX is not inherently risky for non-mail sites, small bump:
        if not mx:
            risk += 0.05

    out.update({
        "ok": 1,
        "a": a, "aaaa": aaaa, "ns": ns, "mx": mx,
        "dns_risk": min(1.0, max(0.0, risk)),
    })
    return out
