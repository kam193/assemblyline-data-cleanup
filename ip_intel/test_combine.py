import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from combine import (
    AwsSource,
    AzureSource,
    CsvColumnSource,
    Datasource,
    GithubMetaSource,
    GoogleCloudSource,
    Ip2ProxySource,
    IscCategorySource,
    Microsoft365Source,
    OpenFiltersSource,
    OracleCloudSource,
    PrefixJsonSource,
    ProxyExitSource,
    ProxyUrlSource,
    RangeSet,
    RezmossSource,
    Source,
    StaticSource,
    slug,
)


class Response:
    def __init__(self, content: bytes):
        self.content = content

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self.content


class Microsoft365SourceTests(unittest.TestCase):
    def test_entries_parse_ips_and_labels(self):
        payload = [
            {
                "serviceAreaDisplayName": "Exchange Online",
                "ips": ["192.0.2.0/24", "2001:db8::/32"],
            },
            {"serviceAreaDisplayName": "Common and Office Online"},
        ]
        source = Microsoft365Source("China", "microsoft-365-vianet")

        with patch(
            "combine.urllib.request.urlopen",
            return_value=Response(json.dumps(payload).encode()),
        ) as urlopen:
            self.assertEqual(
                list(source.entries()),
                [
                    ("192.0.2.0/24", "microsoft-365-vianet", "exchange-online"),
                    ("2001:db8::/32", "microsoft-365-vianet", "exchange-online"),
                ],
            )

        request = urlopen.call_args.args[0]
        query = parse_qs(urlparse(request.full_url).query)
        self.assertEqual(urlparse(request.full_url).path, "/endpoints/China")
        self.assertEqual(len(query["clientrequestid"]), 1)

    def test_regional_categories(self):
        self.assertEqual(
            [
                Microsoft365Source("Worldwide", "microsoft-365").category,
                Microsoft365Source("China", "microsoft-365-vianet").category,
                Microsoft365Source("USGovDoD", "microsoft-365-dod").category,
                Microsoft365Source("USGovGCCHigh", "microsoft-365-gcchigh").category,
            ],
            [
                "microsoft-365",
                "microsoft-365-vianet",
                "microsoft-365-dod",
                "microsoft-365-gcchigh",
            ],
        )

    def test_slug_rejects_empty_values(self):
        with self.assertRaises(ValueError):
            slug("")


class SourceTests(unittest.TestCase):
    def test_aws_source_parses_both_ip_versions(self):
        source = AwsSource()
        payload = {
            "prefixes": [{"ip_prefix": "192.0.2.0/24"}],
            "ipv6_prefixes": [{"ipv6_prefix": "2001:db8::/32"}],
        }
        with patch.object(source, "download", return_value=json.dumps(payload).encode()):
            self.assertEqual(
                source.entries(),
                [
                    ("192.0.2.0/24", "cloud", "aws"),
                    ("2001:db8::/32", "cloud", "aws"),
                ],
            )

    def test_google_oracle_azure_and_github_sources_parse(self):
        fixtures = [
            (
                GoogleCloudSource(),
                {"prefixes": [{"ipv4Prefix": "192.0.2.0/24"}]},
            ),
            (
                OracleCloudSource(),
                {"regions": [{"cidrs": [{"cidr": "192.0.2.0/24"}]}]},
            ),
            (
                AzureSource("https://example.test/azure"),
                {"values": [{"properties": {"addressPrefixes": ["192.0.2.0/24"]}}]},
            ),
            (GithubMetaSource(), {"actions": ["192.0.2.0/24"]}),
        ]
        for source, payload in fixtures:
            with self.subTest(source=source.name), patch.object(
                source, "download", return_value=json.dumps(payload).encode()
            ):
                self.assertEqual(
                    source.entries(), [("192.0.2.0/24", "cloud", source.provider)]
                )

    def test_source_filters_comments_and_builds_entries(self):
        source = Source("https://example.test", "scanner", "example")
        with patch.object(
            source,
            "download",
            return_value=b"  192.0.2.1  \n# comment\n* comment\n192.0.2.2\n",
        ):
            self.assertEqual(source.lines(), ["192.0.2.1", "192.0.2.2"])
            self.assertEqual(
                source.entries(),
                [
                    ("192.0.2.1", "scanner", "example"),
                    ("192.0.2.2", "scanner", "example"),
                ],
            )

    def test_static_source(self):
        source = StaticSource(("192.0.2.0/24", "2001:db8::/32"), "cloud", "example")
        self.assertEqual(source.lines(), ["192.0.2.0/24", "2001:db8::/32"])

    def test_csv_column_source_skips_short_rows(self):
        source = CsvColumnSource("https://example.test", "vpn", column=1)
        with patch.object(source, "download", return_value=b"name,network\nshort\nnode,192.0.2.0/24\n"):
            self.assertEqual(source.lines(), ["network", "192.0.2.0/24"])

    def test_proxy_sources_transform_payloads(self):
        url_source = ProxyUrlSource("https://example.test", "proxy")
        with patch.object(
            url_source,
            "download",
            return_value=b"http://192.0.2.1:8080\nsocks5://[2001:db8::1]:1080\n",
        ):
            self.assertEqual(url_source.lines(), ["192.0.2.1", "2001:db8::1"])

        exit_source = ProxyExitSource("https://example.test", "proxy")
        with patch.object(
            exit_source,
            "download",
            return_value=b'[{"exit_ip": "192.0.2.1"}, {"exit_ip": "192.0.2.2"}]',
        ):
            self.assertEqual(exit_source.lines(), ["192.0.2.1", "192.0.2.2"])

    def test_prefix_json_source_supports_both_ip_versions(self):
        source = PrefixJsonSource("https://example.test", "bot", "example")
        payload = {"prefixes": [{"ipv4Prefix": "192.0.2.0/24"}, {"ipv6Prefix": "2001:db8::/32"}]}
        with patch.object(source, "download", return_value=json.dumps(payload).encode()):
            self.assertEqual(source.lines(), ["192.0.2.0/24", "2001:db8::/32"])

    def test_isc_source_applies_overrides_and_aliases(self):
        source = IscCategorySource("ai", "bot")
        payload = [
            {"ipv4": "192.0.2.1", "type": "semrush"},
            {"ipv4": "192.0.2.2", "type": "openai"},
            {"ipv4": "192.0.2.3", "type": "researcher"},
        ]
        with patch.object(source, "download", return_value=json.dumps(payload).encode()):
            self.assertEqual(
                source.entries(),
                [
                    ("192.0.2.1", "bot", "semrush"),
                    ("192.0.2.2", "bot", "gptbot"),
                    ("192.0.2.3", "bot", "researcher"),
                ],
            )

    def test_rezmoss_source_filters_unknown_providers(self):
        source = RezmossSource(
            "https://example.test",
            {"cloud": ("aws",), "bot": ("googlebot",)},
        )
        payload = b"cidr,provider\n192.0.2.0/24,aws\n192.0.2.1/32,unknown\n"
        with patch.object(source, "download", return_value=payload):
            self.assertEqual(source.entries(), [("192.0.2.0/24", "cloud", "aws")])

    def test_open_filters_source_reads_only_cidr_files_and_aliases(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("filters/cidr/openai_bot.txt", "192.0.2.0/24\n")
            zf.writestr("filters/cidr/other.txt", "192.0.2.1/32\n")
            zf.writestr("filters/domains/example.txt", "ignored\n")
        source = OpenFiltersSource("https://example.test", "scanner")
        with patch.object(source, "download", return_value=archive.getvalue()):
            self.assertEqual(
                source.entries(),
                [
                    ("192.0.2.0/24", "scanner", "gptbot"),
                    ("192.0.2.1/32", "scanner", ""),
                ],
            )

    def test_ip2proxy_network_handles_mapped_and_native_addresses(self):
        self.assertEqual(
            Ip2ProxySource.network(0x00000000000000000000FFFFC0000201, 0x00000000000000000000FFFFC0000201),
            (4, int.from_bytes(b"\xc0\x00\x02\x01", "big"), int.from_bytes(b"\xc0\x00\x02\x01", "big")),
        )
        start = int.from_bytes(b"\x20\x01\x0d\xb8" + b"\x00" * 12, "big")
        self.assertEqual(Ip2ProxySource.network(start, start), (6, start, start))


class RangeSetTests(unittest.TestCase):
    def test_overlapping_labels_are_preserved(self):
        ranges = RangeSet()
        ranges.add("192.0.2.0/24", ("microsoft-365", "exchange-online"))
        ranges.add("192.0.2.0/25", ("microsoft-365-vianet", "exchange-online"))

        self.assertEqual(
            list(ranges.rows()),
            [
                (
                    "192.0.2.0/25",
                    "microsoft-365,microsoft-365-vianet",
                    "exchange-online",
                ),
                ("192.0.2.128/25", "microsoft-365", "exchange-online"),
            ],
        )


class DatasourceTests(unittest.TestCase):
    def test_write_creates_archive_and_manifest(self):
        ranges = RangeSet()
        ranges.add("192.0.2.0/24", ("scanner", "example"))
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            count = Datasource(output, "https://data.example/ip_intel").write(ranges)

            self.assertEqual(count, 1)
            self.assertEqual(
                json.loads((output / "manifest.json").read_text()),
                {
                    "url": "https://data.example/ip_intel/ip-intel.zip",
                    "db_name": "ip-intel.csv",
                    "sha256_hash": json.loads((output / "manifest.json").read_text())["sha256_hash"],
                    "valid_for_in_days": 7,
                    "updated_at_in_epoch_milli": json.loads((output / "manifest.json").read_text())["updated_at_in_epoch_milli"],
                    "provider": "honeypot-tagging",
                },
            )
            with zipfile.ZipFile(output / "ip-intel.zip") as archive:
                self.assertEqual(
                    archive.read("ip-intel.csv").decode(),
                    "network,category,provider\n192.0.2.0/24,scanner,example\n",
                )

    def test_write_includes_source_report_when_provided(self):
        ranges = RangeSet()
        ranges.add("192.0.2.0/24", ("cloud", "aws"))
        report = {
            "duplicate_entry_count": 1,
            "sources": [{"name": "aws", "entry_count": 1}],
        }
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            Datasource(output, "https://data.example/ip_intel").write(ranges, report)

            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual(
                manifest["source_report_url"],
                "https://data.example/ip_intel/source-report.json",
            )
            self.assertEqual(
                json.loads((output / "source-report.json").read_text()), report
            )


if __name__ == "__main__":
    unittest.main()