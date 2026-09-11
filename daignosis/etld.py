from __future__ import annotations

MULTI = frozenset(
    {
        "co.uk",
        "com.pa",
        "com.gt",
        "com.sv",
        "com.co",
        "com.mx",
        "com.br",
        "com.ar",
        "com.pe",
        "com.ec",
        "co.jp",
        "com.au",
        "co.nz",
        "com.cn",
        "co.in",
        "com.sg",
        "com.hk",
        "co.kr",
        "com.tr",
        "azurewebsites.net",
        "cloudfront.net",
        "s3.amazonaws.com",
        "googleapis.com",
        "cloudapp.azure.com",
        "trafficmanager.net",
        "akadns.net",
        "edgekey.net",
        "akamaiedge.net",
        "aaplimg.com",
        "googleusercontent.com",
    }
)


def etld1(qname: str) -> tuple[str, str]:
    name = qname.lower().rstrip(".")
    if not name or name.endswith(".arpa"):
        return name, name
    labels = [p for p in name.split(".") if p]
    if len(labels) < 2:
        return name, name
    last2 = ".".join(labels[-2:])
    if last2 in MULTI and len(labels) >= 3:
        root = ".".join(labels[-3:])
        return root, labels[-3]
    last3 = ".".join(labels[-3:]) if len(labels) >= 3 else ""
    if last3 in MULTI and len(labels) >= 4:
        root = ".".join(labels[-4:])
        return root, labels[-4]
    return last2, labels[-2]
