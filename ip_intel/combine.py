import argparse
import base64
import csv
import hashlib
import io
import ipaddress
import json
import os
import re
import time
import urllib.request
import zipfile
from collections import Counter
from collections.abc import Iterable, Iterator
from pathlib import Path
from uuid import uuid4

NAME = "ip-intel"
USER_AGENT = "ip-intel-combining/1.0 (+https://github.com/kam193/assemblyline-data-cleanup)"
VALID_FOR_DAYS = 7
GITHUB = "https://raw.githubusercontent.com"
X4B = f"{GITHUB}/X4BNet/lists_vpn/main/output"
GOOGLE_IPRANGES = "https://developers.google.com/static/search/apis/ipranges"
AZURE_DOWNLOAD_PAGE = "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
IP2PROXY_THREATS = {"SCANNER": "scanner", "BOTNET": "botnet", "SPAM": "spam"}
ISC_CATEGORY = "https://isc.sans.edu/api/threatcategory"
ISC_CATEGORY_OVERRIDES = {"semrush": "bot"}
Network = str | tuple[int, int, int]
PROVIDER_ALIASES = {
    "academyforinternetresarch": "academyforinternetresearch",
    "alphastrikelabs": "alphastrike",
    "anthropic": "claudebot",
    "arbor": "netscout",
    "bochum": "universities",
    "cybercasa": "driftnet",
    "expanse": "paloaltonetworks",
    "internetcensus": "bitsight",
    "internetmeasurement": "driftnet",
    "internetresearchproject": "bufferoverrun",
    "nokia": "deepfield",
    "openai": "gptbot",
    "other": "",
    "rapid7sonar": "rapid7",
    "strechoid": "stretchoid",
    "univmichigan": "universities",
    "univsydney": "universities",
}
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
    def __init__(
        self,
        url: str,
        category: str,
        provider: str = "",
        name: str = "",
        min_entries: int = 1,
    ):
        self.url = url
        self.category = category
        self.provider = provider
        self.name = name or f"{category}:{provider}:{url}"
        self.min_entries = min_entries

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

    def entries(self) -> Iterable[tuple[Network, str, str]]:
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


class AwsSource(Source):
    def __init__(self):
        super().__init__(
            "https://ip-ranges.amazonaws.com/ip-ranges.json",
            "cloud",
            "aws",
            "aws",
        )

    def entries(self) -> list[tuple[str, str, str]]:
        payload = json.loads(self.download())
        entries = [
            (prefix, self.category, self.provider)
            for entry in payload["prefixes"]
            for prefix in (entry["ip_prefix"],)
        ]
        entries.extend(
            (prefix, self.category, self.provider)
            for entry in payload.get("ipv6_prefixes", ())
            for prefix in (entry["ipv6_prefix"],)
        )
        return entries


class GoogleCloudSource(Source):
    def __init__(self):
        super().__init__(
            "https://www.gstatic.com/ipranges/cloud.json",
            "cloud",
            "googlecloud",
            "google-cloud",
        )

    def entries(self) -> list[tuple[str, str, str]]:
        return [
            (
                prefix.get("ipv4Prefix") or prefix["ipv6Prefix"],
                self.category,
                self.provider,
            )
            for prefix in json.loads(self.download())["prefixes"]
        ]


class OracleCloudSource(Source):
    def __init__(self):
        super().__init__(
            "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json",
            "cloud",
            "oracle",
            "oracle-cloud",
        )

    def entries(self) -> list[tuple[str, str, str]]:
        return [
            (cidr["cidr"], self.category, self.provider)
            for region in json.loads(self.download())["regions"]
            for cidr in region["cidrs"]
        ]


class AzureSource(Source):
    def __init__(self, url: str):
        super().__init__(url, "cloud", "azure", "azure")

    def download(self) -> bytes:
        page = super().download().decode()
        match = re.search(
            r"https://download\.microsoft\.com/[^\"']+ServiceTags_Public_[0-9]+\.json",
            page,
        )
        if not match:
            raise ValueError("Microsoft Azure Service Tags JSON link not found")
        request = urllib.request.Request(match.group(), headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=300) as response:
            return response.read()

    def entries(self) -> list[tuple[str, str, str]]:
        return [
            (prefix, self.category, self.provider)
            for tag in json.loads(self.download())["values"]
            for prefix in tag["properties"].get("addressPrefixes", ())
        ]


class GithubMetaSource(Source):
    SERVICE_KEYS = ("actions", "api", "copilot", "git", "hooks", "pages", "web")

    def __init__(self):
        super().__init__("https://api.github.com/meta", "cloud", "github", "github")

    def entries(self) -> list[tuple[str, str, str]]:
        payload = json.loads(self.download())
        return [
            (network, self.category, self.provider)
            for service in self.SERVICE_KEYS
            for network in payload.get(service, ())
        ]


def slug(value: str) -> str:
    result = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    if not result:
        raise ValueError(f"Cannot slug empty value: {value!r}")
    return result


class Microsoft365Source(Source):
    def __init__(self, instance: str, category: str):
        super().__init__(f"https://endpoints.office.com/endpoints/{instance}", category)

    def download(self) -> bytes:
        url = f"{self.url}?clientrequestid={uuid4()}"
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=300) as response:
            return response.read()

    def entries(self) -> list[tuple[str, str, str]]:
        entries = []
        for endpoint in json.loads(self.download()):
            provider = slug(endpoint["serviceAreaDisplayName"])
            entries.extend(
                (network, self.category, provider)
                for network in endpoint.get("ips", ())
            )
        return entries


class IscCategorySource(Source):
    def __init__(self, isc_category: str, category: str):
        super().__init__(f"{ISC_CATEGORY}/{isc_category}?json", category)

    def entries(self) -> list[tuple[str, str, str]]:
        return [
            (
                row["ipv4"],
                ISC_CATEGORY_OVERRIDES.get(row["type"], self.category),
                PROVIDER_ALIASES.get(row["type"]) or row["type"],
            )
            for row in json.loads(self.download())
        ]


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


class OpenFiltersSource(Source):
    def entries(self) -> list[tuple[str, str, str]]:
        entries = []
        with zipfile.ZipFile(io.BytesIO(self.download())) as zf:
            for name in zf.namelist():
                directory, _, filename = name.rpartition("/")
                if not directory.endswith("/cidr") or not filename.endswith(".txt"):
                    continue
                provider = filename.rpartition("_")[0]
                provider = PROVIDER_ALIASES.get(provider, provider)
                entries.extend(
                    (network, self.category, provider)
                    for network in zf.read(name).decode().split()
                )
        return entries


class Ip2ProxySource(Source):
    """IP2Proxy LITE ships IPv4 as IPv4-mapped ranges in the IPv6 file."""

    def __init__(self, database: str):
        super().__init__(
            f"https://www.ip2location.com/download?file={database}", "proxy,threat"
        )

    def download(self) -> bytes:
        token = os.environ["IP2LOCATIONTOKEN"]
        request = urllib.request.Request(
            f"{self.url}&token={token}", headers={"User-Agent": USER_AGENT}
        )
        with urllib.request.urlopen(request, timeout=600) as response:
            return response.read()

    def entries(self) -> Iterator[tuple[Network, str, str]]:
        with zipfile.ZipFile(io.BytesIO(self.download())) as zf:
            name = next(n for n in zf.namelist() if n.upper().endswith(".CSV"))
            with zf.open(name) as raw:
                for row in csv.reader(io.TextIOWrapper(raw, encoding="utf-8")):
                    network = self.network(int(row[0]), int(row[1]))
                    yield network, "proxy", ""
                    for threat in row[13].split("/"):
                        if threat in IP2PROXY_THREATS:
                            yield network, IP2PROXY_THREATS[threat], ""

    @staticmethod
    def network(start: int, end: int) -> tuple[int, int, int]:
        mapped = ipaddress.IPv6Address(start).ipv4_mapped
        if mapped is None:
            return 6, start, end
        mapped_end = ipaddress.IPv6Address(end).ipv4_mapped
        if mapped_end is None:
            raise ValueError("IPv4-mapped range ends in a non-mapped IPv6 address")
        return 4, int(mapped), int(mapped_end)


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
    AwsSource(),
    GoogleCloudSource(),
    OracleCloudSource(),
    AzureSource(AZURE_DOWNLOAD_PAGE),
    GithubMetaSource(),
    Source("https://www.cloudflare.com/ips-v4/", "cloud", "cloudflare"),
    Source("https://www.cloudflare.com/ips-v6/", "cloud", "cloudflare"),
    PrefixJsonSource(f"{GOOGLE_IPRANGES}/special-crawlers.json", "bot", "googlebot"),
    PrefixJsonSource(
        f"{GOOGLE_IPRANGES}/user-triggered-fetchers.json", "bot", "google_fetcher"
    ),
    PrefixJsonSource(
        f"{GOOGLE_IPRANGES}/user-triggered-fetchers-google.json",
        "bot",
        "google_fetcher",
    ),
    Microsoft365Source("Worldwide", "microsoft-365"),
    Microsoft365Source("China", "microsoft-365-vianet"),
    Microsoft365Source("USGovDoD", "microsoft-365-dod"),
    Microsoft365Source("USGovGCCHigh", "microsoft-365-gcchigh"),
    PrefixJsonSource("https://openai.com/searchbot.json", "bot", "gptbot"),
    PrefixJsonSource("https://openai.com/chatgpt-user.json", "bot", "gptbot"),
    PrefixJsonSource(
        "https://www.perplexity.ai/perplexity-user.json", "bot", "perplexitybot"
    ),
    # Published at https://platform.claude.com/docs/en/api/ip-addresses, no feed
    StaticSource(("160.79.104.0/21",), "bot", "claudebot"),
    IscCategorySource("ai", "bot"),
    IscCategorySource("research", "scanner"),
    Source(f"{X4B}/datacenter/ipv4.txt", "datacenter"),
    Source(f"{X4B}/datacenter/ipv6.txt", "datacenter"),
    OpenFiltersSource(
        "https://codeload.github.com/OpenFilters/internet-scanners/zip/refs/heads/main",
        "scanner",
    ),
    Ip2ProxySource("PX9LITECSVIPV6"),
]


class RangeSet:
    """Splits overlapping labelled ranges into disjoint ones, as ip2geo returns one match.

    Events are packed ints (position, is_end, label id) to keep memory flat."""

    LABEL_BITS = 16
    END = 1 << LABEL_BITS

    def __init__(self):
        self.events = {4: [], 6: []}
        self.labels: dict[tuple[str, str], int] = {}

    def add(self, network: str | tuple[int, int, int], label: tuple[str, str]):
        if isinstance(network, str):
            net = ipaddress.ip_network(network, strict=False)
            network = (
                net.version,
                int(net.network_address),
                int(net.broadcast_address),
            )
        version, start, end = network
        label_id = self.labels.setdefault(label, len(self.labels))
        if label_id >= self.END:
            raise ValueError("Too many distinct labels")
        events = self.events[version]
        events.append(start << (self.LABEL_BITS + 1) | label_id)
        events.append((end + 1) << (self.LABEL_BITS + 1) | self.END | label_id)

    def disjoint(self, version: int) -> Iterator[tuple[int, int, frozenset[int]]]:
        events = self.events[version]
        self.events[version] = []
        events.sort()
        active = Counter()
        pending: tuple[int, int, frozenset[int]] | None = None
        start: int | None = None
        index = 0
        while index < len(events):
            position = events[index] >> (self.LABEL_BITS + 1)
            if active and start is not None:
                labels = frozenset(active)
                if pending and pending[1] == start - 1 and pending[2] == labels:
                    pending = (pending[0], position - 1, labels)
                else:
                    if pending:
                        yield pending
                    pending = (start, position - 1, labels)
            while (
                index < len(events)
                and events[index] >> (self.LABEL_BITS + 1) == position
            ):
                label = events[index] & (self.END - 1)
                active[label] += -1 if events[index] & self.END else 1
                if not active[label]:
                    del active[label]
                index += 1
            start = position
        if pending:
            yield pending

    def rows(self) -> Iterator[tuple[str, str, str]]:
        labels = list(self.labels)
        columns = {}
        for version, address in (
            (4, ipaddress.IPv4Address),
            (6, ipaddress.IPv6Address),
        ):
            for start, end, label_ids in self.disjoint(version):
                if label_ids not in columns:
                    columns[label_ids] = (
                        ",".join(sorted({labels[i][0] for i in label_ids})),
                        ",".join(sorted({labels[i][1] for i in label_ids} - {""})),
                    )
                category, provider = columns[label_ids]
                for net in ipaddress.summarize_address_range(
                    address(start), address(end)
                ):
                    yield str(net), category, provider


class Datasource:
    def __init__(self, out_dir: Path, base_url: str):
        self.out_dir = out_dir
        self.base_url = base_url.rstrip("/")

    def write(
        self, ranges: RangeSet, source_report: dict | None = None
    ) -> int:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        archive = self.out_dir / f"{NAME}.zip"
        count = 0
        with (
            zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf,
            zf.open(f"{NAME}.csv", "w") as raw,
            io.TextIOWrapper(raw, encoding="utf-8", newline="") as text,
        ):
            writer = csv.writer(text, lineterminator="\n")
            writer.writerow(["network", "category", "provider"])
            for row in ranges.rows():
                writer.writerow(row)
                count += 1
        digest = hashlib.sha256(archive.read_bytes()).digest()
        manifest = {
            "url": f"{self.base_url}/{archive.name}",
            "db_name": f"{NAME}.csv",
            "sha256_hash": base64.b64encode(digest).decode(),
            "valid_for_in_days": VALID_FOR_DAYS,
            "updated_at_in_epoch_milli": int(time.time() * 1000),
            "provider": "honeypot-tagging",
        }
        if source_report is not None:
            report_path = self.out_dir / "source-report.json"
            report_path.write_text(json.dumps(source_report, sort_keys=True))
            manifest.update(
                source_report_url=f"{self.base_url}/{report_path.name}",
                source_count=len(source_report["sources"]),
                duplicate_entry_count=source_report["duplicate_entry_count"],
            )
        (self.out_dir / "manifest.json").write_text(json.dumps(manifest))
        return count


def network_key(network: str | tuple[int, int, int]) -> str:
    if isinstance(network, str):
        parsed = ipaddress.ip_network(network, strict=False)
        return f"{parsed.version}:{parsed.network_address}:{parsed.broadcast_address}"
    version, start, end = network
    return f"{version}:{start}:{end}"


def main():
    parser = argparse.ArgumentParser(
        description="Build an ip2geo datasource tagging Tor, VPN, relay, proxy, cloud, bot, datacenter, scanner, botnet and spam IPs"
    )
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--base-url", required=True, help="Public URL the --out directory is served at"
    )
    args = parser.parse_args()

    ranges = RangeSet()
    source_entries: dict[str, set[str]] = {}
    source_report = []
    key_sources: dict[str, set[str]] = {}
    for source in SOURCES:
        entries = list(source.entries())
        if len(entries) < source.min_entries:
            raise ValueError(
                f"{source.name} returned {len(entries)} entries; expected at least "
                f"{source.min_entries}"
            )
        keys = set()
        for network, category, provider in entries:
            ranges.add(network, (category, provider))
            key = network_key(network)
            keys.add(key)
            key_sources.setdefault(key, set()).add(source.name)
        source_entries[source.name] = keys
        source_report.append(
            {
                "name": source.name,
                "url": source.url,
                "category": source.category,
                "provider": source.provider,
                "entry_count": len(entries),
                "unique_entry_count": len(keys),
            }
        )
        print(f"{len(entries):>8} {source.category:<8} {source.url}")
    duplicate_entry_count = sum(1 for sources in key_sources.values() if len(sources) > 1)
    for report in source_report:
        shared = set()
        for key in source_entries[report["name"]]:
            shared.update(key_sources[key])
        shared.discard(report["name"])
        report["duplicate_with"] = sorted(shared)
    report = {
        "duplicate_entry_count": duplicate_entry_count,
        "sources": source_report,
    }
    count = Datasource(args.out, args.base_url).write(ranges, report)
    print(f"{count} networks written to {args.out}")


if __name__ == "__main__":
    main()
