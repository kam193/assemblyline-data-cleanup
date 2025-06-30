import plyara
import plyara.utils


CATEGORY_TO_KEYWORDS = {
    # PROXY, OBFUSCATOR, "SCANNER",
    "malware": [
        "adware",
        "backdoor",
        "banker",
        "bootkit",
        "bot",
        "browser-hijacker",
        "brootforcer",
        "clickfraud",
        "cryptominer",
        "ddos",
        "downloader",
        "dropper",
        "exploitkit",
        "fakeav",
        "hacktool",
        "infostealer",
        "keylogger",
        "loader",
        "_pos",  # lower FP
        "_rat",  # lower FP
        "ransomware",
        "ransom",
        "rootkit",
        "scareware",
        "spamer",
        "wiper",
        "webshell",
        "worm",
        # generic names at the end
        "apt",
        "malware",
        "malpedia",  # All there is malware
        "_malw",  # generic malware
        "_mal_",  # generic malware
        "_ran_",  # generic ransomware
    ],
    "exploit": ["exploit", "_exp_", "_cve_", "_expl_"],
    "tool": ["tool", "hktl", "hacktool"],
}
WORDS_TO_SKIP = [
    "auto",
    "exp",
    "mal",
    "malw",
    "ran",
    "expl",
    # parts of names
    "security",
    "solg",
    "point",
    "base",
    "synacltiv",
]


# Enrich YARA rules with categories and details based on rule names and metadata
# This attempts to comply with CCCS Yara rules categorization
def rules_enrichment(input_file, output_file):
    with open(input_file, "r") as in_stream:
        rules = plyara.Plyara().parse_string(in_stream.read())

    enrich_ruleset(rules)

    with open(output_file, "w") as out_stream:
        for rule in rules:
            out_stream.write(plyara.utils.rebuild_yara_rule(rule))


def enrich_ruleset(rules):
    for rule in rules:
        rule_category = None
        detail = None
        malware_type = None
        malware_family = None

        rule_name = rule.get("rule_name", "").lower()

        if "_susp_" in rule_name:
            # Skip suspicious rules, they are handled well by AL
            continue

        description = ""
        for meta in rule.get("metadata", []):
            description = meta.get("description", "").lower() or description
            malware_type = meta.get("malware_type", "").lower() or malware_type
            malware_family = meta.get("malware_family", "") or malware_family
            malware_family = meta.get("threat_name", "") or malware_family

        for category, keywords in CATEGORY_TO_KEYWORDS.items():
            for keyword in keywords:
                if keyword in rule_name or keyword in description:
                    rule_category = category
                    if category == "malware" and not malware_type:
                        malware_type = keyword.replace("_", "")
                    break

            if not rule_category and malware_family:
                rule_category = "malware"

            # Hacking tool names can be easily confused with malware
            if rule_category and "hktl" in rule_name:
                rule_category = "tool"

            # TODO: suspicious rule names
            if rule_category:
                # in yara-forge, the first part of the rule name is the name of the ruleset
                detail = malware_family or "_".join(
                    p
                    for p in rule.get("rule_name", "").split("_")[1:]
                    if p.lower() not in CATEGORY_TO_KEYWORDS[category]
                    and p.lower() not in WORDS_TO_SKIP
                )
                rule["metadata"].append({"category": rule_category})
                if detail:
                    rule["metadata"].append({rule_category: detail})
                if malware_type:
                    if malware_type in ["malpedia", "malw", "mal"]:
                        malware_type = "trojan"  # generic type if nothing more found
                    if malware_type in ["ran"]:
                        malware_type = "ransomware"
                    rule["metadata"].append({"malware_type": malware_type})
                break
