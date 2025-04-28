import re
import time
from collections import defaultdict
from prometheus_client import start_http_server, Gauge

# ────────────────────────────────
# 🚧 Configuration
# ────────────────────────────────
LOG_FILE = "/var/log/nginx/access.log"     # Path (bind‑mounted) to Nginx access log
THRESHOLD_HITS = 10                        # at least 10 hits
WINDOW_SECONDS = 10.0                      # within 10 seconds
REFRESH_INTERVAL = 1.0                     # evaluate every second
PORT = 8000                                # /metrics port

# Mapping pour remplacer IP privées ➔ IP publiques simulées
PRIVATE_TO_PUBLIC_IP = {
    "10.": "104.26.10.",        # USA Cloudflare
    "172.16.": "5.135.1.",      # France OVH
    "172.17.": "5.135.2.",
    "172.18.": "5.135.3.",
    "172.19.": "5.135.4.",
    "192.168.": "185.60.216.",  # Facebook Ireland
    "127.": "8.8.8.",           # Google DNS
}

# ────────────────────────────────
# 📊 Prometheus metrics
# ────────────────────────────────
suspicious_ip_attempts = Gauge(
    "nginx_suspicious_ip_attempts",
    "Number of hits by an IP inside the 10‑second window when threshold breached",
    labelnames=("ip",),
)

geo_ip_attempts = Gauge(
    "nginx_geo_ip_attempts",
    "Number of hits by an IP with geographic information for Geomap",
    labelnames=("ip", "latitude", "longitude", "country", "region"),
)

# ────────────────────────────────
# 🌍 Base de données GeoIP simplifiée
# ────────────────────────────────
GEO_DATA = {
    "5.": ("France", "Europe", "46.2276", "2.2137"),
    "46.": ("Germany", "Europe", "51.1657", "10.4515"),
    "78.": ("UK", "Europe", "55.3781", "-3.4360"),
    "81.": ("Spain", "Europe", "40.4637", "-3.7492"),
    "94.": ("Italy", "Europe", "41.8719", "12.5674"),
    "104.": ("USA", "North America", "37.0902", "-95.7129"),
    "67.": ("Canada", "North America", "56.1304", "-106.3468"),
    "50.": ("Mexico", "North America", "23.6345", "-102.5528"),
    "103.": ("China", "Asia", "35.8617", "104.1954"),
    "116.": ("India", "Asia", "20.5937", "78.9629"),
    "122.": ("Japan", "Asia", "36.2048", "138.2529"),
    "124.": ("South Korea", "Asia", "35.9078", "127.7669"),
    "185.": ("Russia", "Asia", "61.5240", "105.3188"),
    "8.": ("USA", "North America", "37.7510", "-97.8220"),          # IP 8.x (Google DNS simulé)
    "185.60.216.": ("Ireland", "Europe", "53.3498", "-6.2603"),     # Facebook Dublin
}

# ────────────────────────────────
# 🛠 Utilities
# ────────────────────────────────
ip_re = re.compile(r"^(?P<ip>(?:\d{1,3}\.){3}\d{1,3})")

def get_ip(line: str) -> str | None:
    """Extract first IP from a log line if valid."""
    if not line:
        return None
    match = ip_re.match(line)
    return match.group("ip") if match else None

def map_private_ip(ip: str) -> str:
    """Replace private IP by a mapped public IP if needed."""
    for private_prefix, public_prefix in PRIVATE_TO_PUBLIC_IP.items():
        if ip.startswith(private_prefix):
            last_octet = ip.split(".")[-1]
            return f"{public_prefix}{last_octet}"
    return ip  # IP publique inchangée

def prune(ts_list: list[float], now: float):
    """Remove timestamps outside of the monitoring window."""
    cutoff = now - WINDOW_SECONDS
    while ts_list and ts_list[0] < cutoff:
        ts_list.pop(0)

def get_geo_data(ip: str) -> tuple:
    """Get geo info based on IP prefix."""
    for prefix, data in GEO_DATA.items():
        if ip.startswith(prefix):
            return data
    return ("Unknown", "Unknown", "0.0", "0.0")

# ────────────────────────────────
# 🔄 Main loop
# ────────────────────────────────
def tail_and_export(path: str):
    hits: defaultdict[str, list[float]] = defaultdict(list)

    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        fh.seek(0, 2)  # Seek end of file (tail -f style)
        last_tick = time.time()

        while True:
            line = fh.readline()
            if not line:
                time.sleep(0.05)
            else:
                now = time.time()
                ip = get_ip(line)
                if ip:
                    mapped_ip = map_private_ip(ip)
                    hits[mapped_ip].append(now)

            now = time.time()
            if now - last_tick >= REFRESH_INTERVAL:
                last_tick = now
                update_metrics(hits, now)

def update_metrics(hits: dict[str, list[float]], now: float):
    suspicious_ip_attempts.clear()
    geo_ip_attempts.clear()
    
    for ip, ts in list(hits.items()):
        prune(ts, now)
        if not ts:
            del hits[ip]
            continue
        
        if len(ts) >= THRESHOLD_HITS:
            suspicious_ip_attempts.labels(ip=ip).set(len(ts))
            
            country, region, lat, lon = get_geo_data(ip)
            geo_ip_attempts.labels(
                ip=ip,
                latitude=lat,
                longitude=lon,
                country=country,
                region=region
            ).set(len(ts))

# ────────────────────────────────
# 🚀 Entry point
# ────────────────────────────────
if __name__ == "__main__":
    print(f"[+] Exporting metric on :{PORT}/metrics – monitoring {LOG_FILE}")
    print(f"[+] Also exporting geographic data with metric: nginx_geo_ip_attempts")
    start_http_server(PORT)
    tail_and_export(LOG_FILE)
