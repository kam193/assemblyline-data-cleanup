import os
import tempfile
import zipfile

import plyara
import plyara.utils
import requests
import utils


def get_last_commit_id():
    try:
        with open("elastic_commit_id.txt", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""  # Return empty string if file doesn't exist


def get_latest_commit_id():
    response = requests.get(
        "https://api.github.com/repos/elastic/protections-artifacts/commits"
    )
    if response.status_code == 200:
        return response.json()[0]["sha"]
    return None


def has_new_data():
    last_commit_id = get_last_commit_id()
    latest_commit_id = get_latest_commit_id()
    if latest_commit_id:
        if not last_commit_id:
            return True
        return last_commit_id != latest_commit_id
    return False


def download_and_process_repository_zip(commit_id):
    """Download and process the repository ZIP file in chunks to avoid memory issues."""
    url = f"https://github.com/elastic/protections-artifacts/archive/{commit_id}.zip"

    all_rules = []

    with requests.get(url, stream=True) as response:
        if response.status_code != 200:
            raise Exception(
                f"Failed to download repository ZIP: {response.status_code}"
            )

        with tempfile.NamedTemporaryFile(delete=False) as temp_zip:
            chunk_size = 8192
            for chunk in response.iter_content(chunk_size=chunk_size):
                if chunk:
                    temp_zip.write(chunk)

            temp_zip_path = temp_zip.name

    try:
        with zipfile.ZipFile(temp_zip_path, "r") as z:
            yara_files = [
                f
                for f in z.namelist()
                if f.endswith((".yar", ".yara")) and not f.endswith("/")
            ]

            for i, file_path in enumerate(yara_files, 1):
                try:
                    with z.open(file_path) as yara_file:
                        content = yara_file.read().decode("utf-8")

                        parser = plyara.Plyara()
                        rules = parser.parse_string(content)
                        all_rules.extend(rules)

                except Exception as e:
                    print(f"Error parsing {file_path}: {e}")
                    continue

    finally:
        try:
            os.unlink(temp_zip_path)
        except OSError:
            pass

    return all_rules


def save_enriched_rules(rules, output_path):
    utils.enrich_ruleset(rules)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, "w") as f:
        f.write(
            "// Elastic protections-artifacts YARA rules - enriched for AssemblyLine\n"
        )
        f.write("// Source: https://github.com/elastic/protections-artifacts/\n")
        f.write(
            "// License: https://github.com/elastic/protections-artifacts/blob/main/LICENSE.txt\n\n"
        )

        for rule in rules:
            try:
                rebuilt_rule = plyara.utils.rebuild_yara_rule(rule)
                f.write(rebuilt_rule)
                f.write("\n")
            except Exception as e:
                print(f"Error rebuilding rule {rule.get('rule_name', 'unknown')}: {e}")
                continue


def process():
    latest_commit_id = get_latest_commit_id()
    if not latest_commit_id:
        print("Failed to fetch the latest commit ID.")
        return

    with open("elastic_commit_id.txt", "w") as f:
        f.write(latest_commit_id)

    try:
        all_rules = download_and_process_repository_zip(latest_commit_id)

        if not all_rules:
            print("No YARA rules found in the repository")
            return

        output_path = "./tmp/elastic-protections-artifacts-enriched.yar"
        save_enriched_rules(all_rules, output_path)

    except Exception as e:
        print(f"Error during processing: {e}")
        return None

    return latest_commit_id


if __name__ == "__main__":
    if has_new_data():
        print(process())
    else:
        print("No new data available.")
