import os
import shutil
import zipfile

import plyara.utils
import yaml
import requests
import tempfile
import re
import plyara

GITHUB_RELEASE_API_TPL = "https://api.github.com/repos/{upstream}/releases/latest"


def load_config():
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)
    return config


def load_last_file_id():
    with open("last_file_id", "r") as f:
        last_file_id = f.read()
    return last_file_id.strip()


def get_file_info_from_github(config):
    url = GITHUB_RELEASE_API_TPL.format(upstream=config["upstream"])
    r = requests.get(url)
    if r.status_code != 200:
        raise Exception("Failed to get release info from github")

    release_info = r.json()
    for asset in release_info["assets"]:
        if config["set"] in asset["name"]:
            return asset["id"], asset["browser_download_url"]


def download_file(url, output_file):
    r = requests.get(url)
    if r.status_code != 200:
        raise Exception("Failed to download file")

    output_file.write(r.content)


def prepare_regexps(config, input_rxp: list[str]):
    regexps = []
    for regex in input_rxp:
        regexps.append(re.compile(regex))
    return regexps


def prepare_rules_to_remove(config):
    rules_to_remove = []
    for rule in config["remove_rules"]:
        rules_to_remove.append(f"rule {rule} ")
    return rules_to_remove


def clean_up_file(in_stream, out_path, config):
    regexps_sanitize = prepare_regexps(config, config["sanitize_lines"])
    regexps_remove = prepare_regexps(config, config["remove_lines"])
    rules_to_remove = prepare_rules_to_remove(config)

    with open(out_path, "w+") as out_stream:
        loop_until_rule_end = False
        for line in in_stream:
            save_line = True
            line = line.decode("utf-8")
            if loop_until_rule_end:
                if line.startswith("}"):
                    loop_until_rule_end = False
                continue

            for rule in rules_to_remove:
                if line.startswith(rule):
                    loop_until_rule_end = True
                    save_line = False
                    break

            if not loop_until_rule_end:
                for regex in regexps_sanitize:
                    if regex.match(line):
                        out_stream.write("#")
                        break
                else:
                    for regex in regexps_remove:
                        if regex.match(line):
                            save_line = False
                            break

            if save_line:
                out_stream.write(line)


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

    for rule in rules:
        rule_category = None
        detail = None
        malware_type = None
        malware_family = None

        rule_name = rule.get("rule_name", "").lower()
        description = ""
        for meta in rule.get("metadata", []):
            description = meta.get("description", "").lower() or description
            malware_type = meta.get("malware_type", "").lower() or malware_type
            malware_family = meta.get("malware_family", "").lower() or malware_family

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

    with open(output_file, "w") as out_stream:
        for rule in rules:
            out_stream.write(plyara.utils.rebuild_yara_rule(rule))


def process():
    config = load_config()
    last_file_id = load_last_file_id()
    remote_file_id, remote_file_url = get_file_info_from_github(config)
    os.makedirs(config["output_dir"], exist_ok=True)

    if str(remote_file_id) == last_file_id:
        print("No new file found")
        return

    with tempfile.NamedTemporaryFile("wb+") as f:
        download_file(remote_file_url, f)
        f.seek(0)

        with zipfile.ZipFile(f) as z:
            for file in z.namelist():
                if file.endswith(".yar"):
                    with z.open(file) as in_stream:
                        clean_up_file(
                            in_stream,
                            f"{config['output_dir']}/yara-forge-{config['set']}-unenriched.yar",
                            config,
                        )

    rules_enrichment(
        f"{config['output_dir']}/yara-forge-{config['set']}-unenriched.yar",
        f"{config['output_dir']}/yara-forge-{config['set']}-enriched.yar",
    )
    shutil.copy(
        f"{config['output_dir']}/yara-forge-{config['set']}-enriched.yar",
        f"{config['output_dir']}/cleaned-rules.yar",
    )


    with open("last_file_id", "w+") as f:
        f.write(str(remote_file_id))

    print(remote_file_id)


if __name__ == "__main__":
    process()
