import math, sqlite3, time
from collections import deque
from scapy.all import sniff, DNS, DNSQR

DB = "alerts.db"
COOLDOWN = 300       # seconds before the same alert can fire again
RATE_WINDOW = 10     # seconds
RATE_LIMIT = 50      # queries per window before a spike alert

ALLOWLIST = (
    "azure.com", "windows.net", "microsoft.com", "amazonaws.com",
    "apple.com", "icloud.com", "googleusercontent.com", "cloudfront.net",
)

RULES = {
    "DGA":  ("High-entropy domain (possible DGA)", "T1568.002", "medium"),
    "TXT":  ("TXT query (possible DNS tunneling)", "T1071.004", "low"),
    "LONG": ("Very long domain (possible DNS tunneling)", "T1071.004", "medium"),
    "RATE": ("DNS query rate spike", "T1071.004", "high"),
}

QTYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 65: "HTTPS"}

db = sqlite3.connect(DB)
db.execute("CREATE TABLE IF NOT EXISTS alerts (ts TEXT, domain TEXT, qtype TEXT, rule TEXT, description TEXT, mitre TEXT, severity TEXT)")
db.execute("CREATE TABLE IF NOT EXISTS queries (ts TEXT, domain TEXT, qtype TEXT)")
db.commit()

last_fired = {}
recent = deque()

def entropy(s):
    p = [s.count(c) / len(s) for c in set(s)]
    return -sum(x * math.log2(x) for x in p)

def allowed(domain):
    return any(domain == s or domain.endswith("." + s) for s in ALLOWLIST)

def fire(rule, domain, qtype, now):
    key = (rule, domain)
    if now - last_fired.get(key, 0) < COOLDOWN:
        return
    last_fired[key] = now
    desc, mitre, sev = RULES[rule]
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
    db.execute("INSERT INTO alerts VALUES (?,?,?,?,?,?,?)", (ts, domain, qtype, rule, desc, mitre, sev))
    db.commit()
    print(f"[{sev.upper():6}] {ts} {domain} -> {desc} ({mitre})")

def handle(pkt):
    if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)) or pkt[DNS].qr != 0:
        return
    now = time.time()
    domain = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".").lower()
    qtype = QTYPES.get(pkt[DNSQR].qtype, str(pkt[DNSQR].qtype))

    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
    db.execute("INSERT INTO queries VALUES (?,?,?)", (ts, domain, qtype))
    db.commit()

    recent.append(now)
    while recent and now - recent[0] > RATE_WINDOW:
        recent.popleft()
    if len(recent) > RATE_LIMIT:
        fire("RATE", "(many domains)", "-", now)

    if allowed(domain):
        return

    label = domain.split(".")[0]
    if len(label) > 12 and entropy(label) > 3.5:
        fire("DGA", domain, qtype, now)
    if qtype == "TXT":
        fire("TXT", domain, qtype, now)
    if len(domain) > 60:
        fire("LONG", domain, qtype, now)

print("Monitoring DNS traffic... press Ctrl+C to stop")
sniff(filter="udp port 53", prn=handle, store=False)
