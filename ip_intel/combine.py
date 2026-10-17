import argparse
import base64
import csv
import hashlib
import io
import ipaddress
import json
import time
import urllib.request
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

NAME = "ip-intel"
USER_AGENT = "ip-intel-combining/1.0"
VALID_FOR_DAYS = 7
GITHUB = "https://raw.githubusercontent.com"
X4B = f"{GITHUB}/X4BNet/lists_vpn/main/output"
GOOGLE_IPRANGES = "https://developers.google.com/static/search/apis/ipranges"
REZMOSS_CATEGORIES = {
    "cloud": (
        "alibaba",
        "aws",
        "azure",
        "baidu",
        "circleci",
        "cloudflare",
        "contabo",
        "digitalocean",
        "gabia",
        "gcore",
        "github",
        "googlecloud",
        "hetzner",
        "hostway",
        "huawei",
        "ibmcloud",
        "leaseweb",
        "linode",
        "nhncloud",
        "oracle",
        "ovhcloud",
        "play2go",
        "rackspace",
        "scaleway",
        "tencent",
        "upcloud",
        "vultr",
    ),
    "bot": (
        "amazonbot",
        "applebot",
        "bingbot",
        "claudebot",
        "commoncrawl",
        "duckduckbot",
        "googlebot",
        "gptbot",
        "internetarchive",
        "meta",
        "perplexitybot",
        "pingdom",
        "statuscake",
        "uptimerobot",
        "yandex",
    ),
    "relay": ("apple_private_relay",),
    "proxy": ("zscaler",),
}


class Source:
    def __init__(self, url: str, category: str, provider: str = ""):
        self.url = url
        self.category = category
        self.provider = provider

    def download(self) -> bytes:
        request = urllib.request.Request(self.url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=300) as response:
            return response.read()

    def lines(self) -> list[str]:
        return [
            line
            for line in (raw.strip() for raw in self.download().decode().splitlines())
            if line and not line.startswith(("#", "*"))
        ]

    def entries(self) -> list[tuple[str, str, str]]:
        return [(line, self.category, self.provider) for line in self.lines()]


class StaticSource(Source):
    def __init__(self, networks: tuple[str, ...], category: str, provider: str):
        super().__init__(", ".join(networks), category, provider)
        self.networks = networks

    def lines(self) -> list[str]:
        return list(self.networks)


class CsvColumnSource(Source):
    def __init__(self, url: str, category: str, provider: str = "", column: int = 0):
        super().__init__(url, category, provider)
        self.column = column

    def lines(self) -> list[str]:
        return [
            row[self.column]
            for row in csv.reader(super().lines())
            if len(row) > self.column
        ]


class ProxyUrlSource(Source):
    def lines(self) -> list[str]:
        return [
            line.partition("://")[2].rpartition(":")[0].strip("[]")
            for line in super().lines()
        ]


class ProxyExitSource(Source):
    def lines(self) -> list[str]:
        return [proxy["exit_ip"] for proxy in json.loads(self.download())]


class PrefixJsonSource(Source):
    def lines(self) -> list[str]:
        return [
            prefix.get("ipv4Prefix") or prefix["ipv6Prefix"]
            for prefix in json.loads(self.download())["prefixes"]
        ]


class IscThreatlistSource(Source):
    def lines(self) -> list[str]:
        return [row["ipv4"] for row in json.loads(self.download())]


class RezmossSource(Source):
    def __init__(self, url: str, categories: dict[str, tuple[str, ...]]):
        super().__init__(url, ",".join(categories))
        self.category_of = {
            provider: category
            for category, providers in categories.items()
            for provider in providers
        }

    def entries(self) -> list[tuple[str, str, str]]:
        return [
            (row["cidr"], self.category_of[row["provider"]], row["provider"])
            for row in csv.DictReader(self.download().decode().splitlines())
            if row["provider"] in self.category_of
        ]


SOURCES = [
    Source("https://check.torproject.org/torbulkexitlist", "tor", "tor"),
    Source(f"{X4B}/vpn/ipv4.txt", "vpn"),
    Source(f"{X4B}/vpn/ipv6.txt", "vpn"),
    # Proton advertises entry IPs only; exits are NATed within the same /24
    Source(
        f"{GITHUB}/tn3w/ProtonVPN-IPs/master/protonvpn_ip_ranges.txt",
        "vpn",
        "protonvpn",
    ),
    CsvColumnSource("https://www.vpngate.net/api/iphone/", "vpn", "vpngate", column=1),
    CsvColumnSource(
        "https://api.cloudflare.com/warp-egress-ip-ranges.csv",
        "relay",
        "cloudflare_warp",
    ),
    CsvColumnSource("https://www.gstatic.com/vpn/geofeed", "relay", "google_vpn"),
    ProxyUrlSource(
        f"{GITHUB}/proxifly/free-proxy-list/main/proxies/all/data.txt", "proxy"
    ),
    ProxyExitSource(f"{GITHUB}/monosans/proxy-list/main/proxies.json", "proxy"),
    RezmossSource(
        f"{GITHUB}/rezmoss/cloud-provider-ip-addresses/main/all_providers/all_providers.csv",
        REZMOSS_CATEGORIES,
    ),
    PrefixJsonSource(f"{GOOGLE_IPRANGES}/special-crawlers.json", "bot", "googlebot"),
    PrefixJsonSource(
        f"{GOOGLE_IPRANGES}/user-triggered-fetchers.json", "bot", "google_fetcher"
    ),
    PrefixJsonSource(
        f"{GOOGLE_IPRANGES}/user-triggered-fetchers-google.json",
        "bot",
        "google_fetcher",
    ),
    PrefixJsonSource("https://openai.com/searchbot.json", "bot", "gptbot"),
    PrefixJsonSource("https://openai.com/chatgpt-user.json", "bot", "gptbot"),
    PrefixJsonSource(
        "https://www.perplexity.ai/perplexity-user.json", "bot", "perplexitybot"
    ),
    # Published at https://platform.claude.com/docs/en/api/ip-addresses, no feed
    StaticSource(("160.79.104.0/21",), "bot", "claudebot"),
    IscThreatlistSource(
        "https://isc.sans.edu/api/threatlist/semrush?json", "bot", "semrush"
    ),
    Source(f"{X4B}/datacenter/ipv4.txt", "datacenter"),
    Source(f"{X4B}/datacenter/ipv6.txt", "datacenter"),
]


class RangeSet:
    """Splits overlapping labelled ranges into disjoint ones, as ip2geo returns a single match."""

    def __init__(self):
        self.events = {4: defaultdict(list), 6: defaultdict(list)}

    def add(self, network: str, label: tuple[str, str]):
        net = ipaddress.ip_network(network, strict=False)
        events = self.events[net.version]
        events[int(net.network_address)].append((label, 1))
        events[int(net.broadcast_address) + 1].append((label, -1))

    def disjoint(self, version: int) -> list[tuple[int, int, frozenset]]:
        events = self.events[version]
        active = Counter()
        ranges = []
        start = None
        for position in sorted(events):
            if active:
                labels = frozenset(active)
                if ranges and ranges[-1][1] == start - 1 and ranges[-1][2] == labels:
                    ranges[-1] = (ranges[-1][0], position - 1, labels)
                else:
                    ranges.append((start, position - 1, labels))
            for label, delta in events[position]:
                active[label] += delta
                if not active[label]:
                    del active[label]
            start = position
        return ranges

    def rows(self):
        for version, address in (
            (4, ipaddress.IPv4Address),
            (6, ipaddress.IPv6Address),
        ):
            for start, end, labels in self.disjoint(version):
                category = ",".join(sorted({c for c, _ in labels}))
                provider = ",".join(sorted({p for _, p in labels if p}))
                for net in ipaddress.summarize_address_range(
                    address(start), address(end)
                ):
                    yield str(net), category, provider


class Datasource:
    def __init__(self, out_dir: Path, base_url: str):
        self.out_dir = out_dir
        self.base_url = base_url.rstrip("/")

    def write(self, ranges: RangeSet) -> int:
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(["network", "category", "provider"])
        count = 0
        for row in ranges.rows():
            writer.writerow(row)
            count += 1
        self.out_dir.mkdir(parents=True, exist_ok=True)
        archive = self.out_dir / f"{NAME}.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(f"{NAME}.csv", buffer.getvalue())
        digest = hashlib.sha256(archive.read_bytes()).digest()
        manifest = {
            "url": f"{self.base_url}/{archive.name}",
            "db_name": f"{NAME}.csv",
            "sha256_hash": base64.b64encode(digest).decode(),
            "valid_for_in_days": VALID_FOR_DAYS,
            "updated_at_in_epoch_milli": int(time.time() * 1000),
            "provider": "honeypot-tagging",
        }
        (self.out_dir / "manifest.json").write_text(json.dumps(manifest))
        return count


def main():
    parser = argparse.ArgumentParser(
        description="Build an ip2geo datasource tagging Tor, VPN, relay, proxy, cloud, bot and datacenter IPs"
    )
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--base-url", required=True, help="Public URL the --out directory is served at"
    )
    args = parser.parse_args()

    ranges = RangeSet()
    for source in SOURCES:
        entries = source.entries()
        print(f"{len(entries):>8} {source.category:<8} {source.url}")
        for network, category, provider in entries:
            ranges.add(network, (category, provider))
    count = Datasource(args.out, args.base_url).write(ranges)
    print(f"{count} networks written to {args.out}")


if __name__ == "__main__":
    main()
