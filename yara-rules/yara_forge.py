import os
import re
import shutil
import tempfile
import zipfile

import requests
import yaml
from utils import rules_enrichment

GITHUB_RELEASE_API_TPL = "https://api.github.com/repos/{upstream}/releases/latest"


def load_config():
    with open("config-yf.yaml", "r") as f:
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


def process():
    config = load_config()
    # last_file_id = load_last_file_id()
    remote_file_id, remote_file_url = get_file_info_from_github(config)
    os.makedirs(config["output_dir"], exist_ok=True)

    # if str(remote_file_id) == last_file_id:
    #     print("No new file found")
    #     return

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

    return remote_file_id


def has_new_data():
    config = load_config()
    last_file_id = load_last_file_id()
    remote_file_id, _ = get_file_info_from_github(config)
    return str(remote_file_id) != last_file_id


if __name__ == "__main__":
    if has_new_data():
        process()
