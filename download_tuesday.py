import os
import requests
import hashlib
import time

URL = "https://huggingface.co/datasets/bvsam/cic-ids-2017/resolve/main/pcap/Tuesday-WorkingHours.pcap"
DEST = "data/raw/benign/source_B/Tuesday-WorkingHours.pcap"

def download_file_with_retry(url, dest, max_retries=100):
    retries = 0
    while retries < max_retries:
        headers = {}
        downloaded_bytes = 0
        if os.path.exists(dest):
            downloaded_bytes = os.path.getsize(dest)
            headers["Range"] = f"bytes={downloaded_bytes}-"
            print(f"\nResuming download from byte {downloaded_bytes}...")
        else:
            print(f"\nStarting download from byte 0...")

        try:
            response = requests.get(url, headers=headers, stream=True, timeout=15)
            
            if response.status_code == 416: # Range Not Satisfiable (already fully downloaded)
                print("File is already fully downloaded based on server response (416).")
                return True
                
            response.raise_for_status()

            total_size_header = response.headers.get('content-length')
            if total_size_header:
                total_size = int(total_size_header) + downloaded_bytes
                print(f"Server reported total file size: {total_size} bytes")
            else:
                total_size = None
                print("Server did not report content-length.")

            mode = 'ab' if downloaded_bytes > 0 else 'wb'
            
            with open(dest, mode) as f:
                last_print_time = time.time()
                for chunk in response.iter_content(chunk_size=1024*1024): # 1MB chunks
                    if chunk:
                        f.write(chunk)
                        downloaded_bytes += len(chunk)
                        
                        current_time = time.time()
                        if current_time - last_print_time >= 5.0: # Print progress every 5 seconds
                            if total_size:
                                pct = (downloaded_bytes / total_size) * 100
                                print(f"Progress: {downloaded_bytes} / {total_size} bytes ({pct:.2f}%)")
                            else:
                                print(f"Progress: {downloaded_bytes} bytes downloaded")
                            last_print_time = current_time
                            
            print("\nDownload stream completed successfully.")
            return True
            
        except requests.exceptions.RequestException as e:
            print(f"\nConnection interrupted: {e}")
            retries += 1
            print(f"Retrying in 10 seconds... (Attempt {retries}/{max_retries})")
            time.sleep(10)
        except Exception as e:
            print(f"\nUnexpected error: {e}")
            retries += 1
            print(f"Retrying in 10 seconds... (Attempt {retries}/{max_retries})")
            time.sleep(10)

    print("\nMax retries reached. Download failed.")
    return False

def main():
    print(f"Target URL: {URL}")
    print(f"Destination: {DEST}")
    
    success = download_file_with_retry(URL, DEST)
    
    if not success:
        return
        
    print("\nDownload complete. Calculating SHA-256 (this may take several minutes)...")
    sha256_hash = hashlib.sha256()
    with open(DEST, "rb") as f:
        bytes_read = 0
        last_print = time.time()
        for byte_block in iter(lambda: f.read(1024 * 1024 * 10), b""): # Read 10MB blocks
            sha256_hash.update(byte_block)
            bytes_read += len(byte_block)
            if time.time() - last_print > 10.0:
                print(f"Hashing progress: {bytes_read} bytes processed...")
                last_print = time.time()
            
    h = sha256_hash.hexdigest()
    print(f"\nSHA-256: {h}")
    print(f"Final Size: {os.path.getsize(DEST)} bytes")

if __name__ == "__main__":
    main()
