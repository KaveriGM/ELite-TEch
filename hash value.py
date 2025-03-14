import hashlib
import os

def calculate_hash(file_path):
    hash_obj = hashlib.sha256()
    with open(file_path, 'rb') as file:
        while chunk := file.read(8192):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()

def monitor_files(file_paths):
    initial_hashes = {}
    for file_path in file_paths:
        if os.path.exists(file_path):
            initial_hashes[file_path] = calculate_hash(file_path)
        else:
            print(f"File not found: {file_path}")

    print("Monitoring files for changes...")
    try:
        while True:
            for file_path in file_paths:
                if os.path.exists(file_path):
                    current_hash = calculate_hash(file_path)
                    if file_path in initial_hashes:
                        if initial_hashes[file_path] != current_hash:
                            print(f"File changed: {file_path}")
                            initial_hashes[file_path] = current_hash
                    else:
                        initial_hashes[file_path] = current_hash
                        print(f"New file added: {file_path}")
                else:
                    if file_path in initial_hashes:
                        print(f"File deleted: {file_path}")
                        del initial_hashes[file_path]
            # Add a delay between checks if needed
    except KeyboardInterrupt:
        print("Monitoring stopped.")

if __name__ == "__main__":
    # List the file paths you want to monitor
    files_to_monitor = [
        "example1.txt",
        "example2.txt",
        "/path/to/another/file"
    ]
    monitor_files(files_to_monitor)
