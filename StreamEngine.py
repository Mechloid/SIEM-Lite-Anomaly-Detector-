import time

def stream_logs(file_path):
    with open(file_path, 'r') as f:
        # Move pointer to end of file for live tailing
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line
