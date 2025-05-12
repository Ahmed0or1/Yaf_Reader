from collections import defaultdict
import subprocess
import argparse
import os

def process_yaf_file(yaf_file):
    try:
        result = subprocess.run(['yafscii', '-i', yaf_file], 
                                capture_output=True, text=True, check=True)
        flows = []
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            parts = line.split('|')
            if len(parts) < 10:
                continue
            flows.append({
                'srcaddr': parts[1],
                'dstaddr': parts[2],
                'srcport': parts[3],
                'dstport': parts[4]
            })
        return flows
    except subprocess.CalledProcessError as e:
        print(f"Error running yafscii: {e.stderr}")
        return None
    except FileNotFoundError:
        print("Error: 'yafscii' command not found. Install with: sudo apt install yaf")
        return None

def process_text_file(text_file):
    flows = []
    bad_lines = 0

    try:
        with open(text_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                if "=>" in line:
                    parts = line.split()
                    try:
                        arrow_index = parts.index("=>")
                        src_str = parts[arrow_index - 1]
                        dst_str = parts[arrow_index + 1]
                    except ValueError:
                        bad_lines += 1
                        continue
                else:
                    parts = line.split()
                    if len(parts) < 10:
                        bad_lines += 1
                        continue
                    try:
                        src_str = parts[7]
                        dst_str = parts[9]
                    except IndexError:
                        bad_lines += 1
                        continue

                try:
                    srcaddr, srcport = src_str.rsplit(':', 1)
                    dstaddr, dstport = dst_str.rsplit(':', 1)
                except ValueError:
                    bad_lines += 1
                    continue

                flows.append({
                    'srcaddr': srcaddr,
                    'dstaddr': dstaddr,
                    'srcport': srcport,
                    'dstport': dstport
                })

        if bad_lines:
            print(f"Skipped {bad_lines} malformed lines.")
    except FileNotFoundError:
        print(f"Error: File '{text_file}' not found.")
    except Exception as e:
        print(f"Unexpected error while reading file: {e}")
    
    return flows

def print_top(flows, top_n=5):
    src_count = defaultdict(int)
    dst_count = defaultdict(int)
    sport_count = defaultdict(int)
    dport_count = defaultdict(int)

    for flow in flows:
        src_count[flow['srcaddr']] += 1
        dst_count[flow['dstaddr']] += 1
        sport_count[flow['srcport']] += 1
        dport_count[flow['dstport']] += 1

    print(f"\nFound {len(flows)} flows")

    print(f"\nTop {top_n} Source Addresses:")
    for addr, count in sorted(src_count.items(), key=lambda x: x[1], reverse=True)[:top_n]:
        print(f"{addr}: {count} flows")

    print(f"\nTop {top_n} Destination Addresses:")
    for addr, count in sorted(dst_count.items(), key=lambda x: x[1], reverse=True)[:top_n]:
        print(f"{addr}: {count} flows")

    print(f"\nTop {top_n} Source Ports:")
    for port, count in sorted(sport_count.items(), key=lambda x: x[1], reverse=True)[:top_n]:
        print(f"{port}: {count} flows")

    print(f"\nTop {top_n} Destination Ports:")
    for port, count in sorted(dport_count.items(), key=lambda x: x[1], reverse=True)[:top_n]:
        print(f"{port}: {count} flows")

def print_all_flows(flows):
    print(f"\nFound {len(flows)} flows\n")
    for flow in flows:
        print(f"{flow['srcaddr']}:{flow['srcport']} -> {flow['dstaddr']}:{flow['dstport']}")

if __name__ == "__main__":
    print(r"""

 ___ ___         ___    ______                 __             
|   |   |.---.-.'  _|  |   __ \.-----.---.-.--|  |.-----.----.
 \     / |  _  |   _|  |      <|  -__|  _  |  _  ||  -__|   _|
  |___|  |___._|__|____|___|__||_____|___._|_____||_____|__|  
                 |______|                                     

https://github.com/ahmed0or1
    """)

    parser = argparse.ArgumentParser(description="Analyze network flows from a YAF or text file.")
    parser.add_argument("file", help="Path to input file (.yaf)")
    args = parser.parse_args()

    ext = os.path.splitext(args.file)[1].lower()
    if ext == ".yaf":
        flows = process_yaf_file(args.file)
        if flows:
            print_all_flows(flows)

        filename = os.path.splitext(os.path.basename(args.file))[0]
        txt_file = f"{filename}.yaf.txt"

        flows = process_text_file(txt_file)
        if flows:
            print_top(flows, top_n=5)
    else:
        print("Unsupported file type. Please use .yaf")



