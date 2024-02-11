import argparse
import contextlib
import csv
import io
import os
import tarfile
import tempfile
import zipfile

import tlsh

HEADERS = ["tlsh", "file_type", "reference"]

EXCLUDE = [".git"]

PASSWORDS = [None, "zippy"]


def load_existing_data(path: str):
    with open(path, "r") as f:
        reader = csv.DictReader(f)
        return [row for row in reader]


@contextlib.contextmanager
def extracted_dir_targz(path: str):
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            with tarfile.open(path, "r:gz") as tar:
                tar.extractall(tmpdir)
            yield tmpdir
    except Exception as e:
        print(f"Failed to extract {path}: {e}")
        yield None


@contextlib.contextmanager
def extracted_dir_zip(path: str):
    with tempfile.TemporaryDirectory() as tmpdir:
        for pwd in PASSWORDS:
            try:
                with zipfile.ZipFile(path, "r") as zip:
                    zip.extractall(tmpdir, pwd=pwd.encode() if pwd else None)
                yield tmpdir
                return
            except RuntimeError:
                pass
    print(f"Failed to extract {path}")
    yield None


def get_file_type(path: str):
    if path.endswith(".py"):
        return "code/python"
    return "*"


def get_files(
    input_dir: str,
    extract: bool,
    reference: str = "",
    max_depth=8,
    extension=".bad",
) -> tuple[io.FileIO, str]:
    if max_depth == 0:
        return
    with os.scandir(input_dir) as it:
        for entry in it:
            if entry.is_file():
                if entry.name.endswith(extension):
                    with open(entry.path, "rb") as f:
                        name = entry.name
                        if extension:
                            name = entry.name[:-len(extension)]
                        yield (
                            f,
                            f"{reference}::{name}",
                        )

                if extract and entry.name.endswith(f"{extension}.tar.gz"):
                    with extracted_dir_targz(entry.path) as tmpdir:
                        for f, ref in get_files(
                            tmpdir,
                            extract,
                            f"{reference}/{entry.name.split(f'{extension}.tar.gz')[0]}",
                            max_depth=max_depth - 1,
                        ):
                            yield f, ref
                if extract and (entry.name.endswith(f"{extension}.zip")):
                    with extracted_dir_zip(entry.path) as tmpdir:
                        for f, ref in get_files(
                            tmpdir,
                            extract,
                            f"{reference}/{entry.name.split(f'{extension}.zip')[0]}",
                            max_depth=max_depth - 1,
                            extension="",
                        ):
                            yield f, ref
            elif entry.is_dir() and entry.name not in EXCLUDE:
                for f, ref in get_files(
                    entry.path,
                    extract,
                    f"{reference}/{entry.name}",
                    max_depth=max_depth - 1,
                ):
                    yield (
                        f,
                        ref,
                    )


def main(
    input_dir: str,
    extract: bool,
    existing_data_path: str = None,
    output_path: str = None,
    quiet: bool = False,
    extension: str = ".bad",
    dataset_id: str = "",
):
    if not output_path:
        output_path = f"tmp/{dataset_id}.csv"
    if existing_data_path:
        existing_data = load_existing_data(existing_data_path)
    all_data = existing_data if existing_data_path else []
    hashes = set([row["tlsh"] for row in all_data])

    for f, reference in get_files(
        input_dir, extract, reference=dataset_id, extension=extension
    ):
        new_hash = tlsh.Tlsh()
        for buf in iter(lambda: f.read(1024), b""):
            new_hash.update(buf)

        try:
            new_hash.final()
        except ValueError:
            continue  # Skip files that are too small

        if new_hash.hexdigest() in hashes:
            continue

        if not quiet:
            print(f"Adding {reference}")
        hashes.add(new_hash.hexdigest())
        all_data.append(
            {
                "tlsh": new_hash.hexdigest(),
                "reference": reference,
                "file_type": get_file_type(reference),
            }
        )

    with open(output_path, "w+") as f:
        writer = csv.DictWriter(f, fieldnames=HEADERS)
        writer.writeheader()
        writer.writerows(all_data)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Collect hashes from a directory of files"
    )
    parser.add_argument(
        "-i",
        "--input-dir",
        help="Directory of files to collect hashes from",
        required=True,
    )
    parser.add_argument(
        "-e",
        "--extract",
        help="Extract data from marked archives and process as marked files",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-d",
        "--existing-data-path",
        help="Path to existing data file to append to",
        default=None,
    )
    parser.add_argument(
        "-o",
        "--output-path",
        help="Path to output file",
        default=None,
    )
    parser.add_argument(
        "-x",
        "--include-extension",
        help="Extension marking files to include",
        default=".bad",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        help="Suppress output",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--dataset-id",
        help="ID of the dataset being processed",
        default="",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    main(
        args.input_dir,
        args.extract,
        args.existing_data_path,
        args.output_path,
        args.quiet,
        args.include_extension,
        args.dataset_id,
    )
