import struct
import time
import os

WTMP_FILE = "/var/log/wtmp"
UTMP_FORMAT = "hi32s4s32s256s256s64s"
UTMP_SIZE = struct.calcsize(UTMP_FORMAT)

# Vérifie si le fichier wtmp existe
if not os.path.exists(WTMP_FILE):
    print("Le fichier wtmp n'existe pas.")
    exit(1)

def read_wtmp(file_path):
    with open(file_path, "rb") as f:
        while chunk := f.read(UTMP_SIZE):
            entry = struct.unpack(UTMP_FORMAT, chunk)
            type_, pid, line, id_, user, host, exit_info = entry
            
            user = user.decode("utf-8", "ignore").strip('\x00')
            line = line.decode("utf-8", "ignore").strip('\x00')
            host = host.decode("utf-8", "ignore").strip('\x00')
            
            if user:
                print(f"User: {user}, Line: {line}, Host: {host}, PID: {pid}")

if __name__ == "__main__":
    read_wtmp(WTMP_FILE)
