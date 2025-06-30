import yara_forge
import elastic

if __name__ == "__main__":
    if not yara_forge.has_new_data() and not elastic.has_new_data():
        print("No new file found")
        exit(0)

    yt_id = yara_forge.process()
    elastic_id = elastic.process()
    print(f"{yt_id}-{elastic_id[:10]}")
