import argparse
import csv
import os

HEADERS = ["tlsh", "file_type", "reference"]


def main(output: str, input_dir: str):
    hashes = set()
    all_data = []
    for root, _, files in os.walk(input_dir):
        for filename in files:
            if not filename.endswith(".csv"):
                continue

            file = os.path.join(root, filename)
            print(f"Processing {file}")
            with open(file, "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row["tlsh"] not in hashes:
                        hashes.add(row["tlsh"])
                        all_data.append(row)
    with open(output, "w+") as f:
        writer = csv.DictWriter(f, fieldnames=HEADERS)
        writer.writeheader()
        writer.writerows(all_data)
    print(f"Saved {len(all_data)} hashes to {output}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Collect hashes from a directory of files"
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Path to output file",
        default="data/tlsh_hashes.csv",
    )
    parser.add_argument(
        "-i",
        "--input-dir",
        help="Directory of CSV files to collect hashes from",
        default="tmp/",
    )
    # parser.add_argument(
    #     "--exclude-similarity",
    #     help="Exclude files that are similar to the files in the exclude list with such similarity",
    #     type=int,
    #     default=10,
    # )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    main(args.output, args.input_dir)
