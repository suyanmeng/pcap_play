import os
import sys
from pathlib import Path
from ehp2hdmap import load_file

directory = Path(__file__).resolve().parent
sys.path.append(str(directory.parent))

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 3:
        pcap_path = sys.argv[1]
        interval_path = sys.argv[2]
        interval = int(sys.argv[3])
        if os.path.isfile(pcap_path):
            load_file(pcap_path, interval_path,interval)
        else:
            print("pcap_path is not file")
    else:
        print("[usage]: ./pcap_path interval_path interval")