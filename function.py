import re
import csv
from collections import Counter, defaultdict


LOG_FILE = 'sample.log'
OUTPUT_FILE = 'log_analysis_results.csv'
FAILED_LOGIN_THRESHOLD = 10

def parse_log(file_path):
    log_entries = []
    pattern = (
        r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>[^\]]+)\] '
        r'"(?P<method>\w+) (?P<endpoint>.*?) HTTP/1.1" (?P<status>\d+) (?P<size>\d+)(?: ".*?")?'
    )
    with open(file_path, 'r') as file:
        for line in file:
            match = re.match(pattern, line)
            if match:
                log_entries.append(match.groupdict())
    return log_entries

def count_requests_by_ip(log_entries):
    ip_counter = Counter(entry['ip'] for entry in log_entries)
    return ip_counter


def most_accessed_endpoint(log_entries):
    endpoint_counter = Counter(entry['endpoint'] for entry in log_entries)
    return endpoint_counter.most_common(1)[0]  # Returns tuple (endpoint, count)

def detect_suspicious_activity(log_entries, threshold):
    failed_attempts = Counter(
        entry['ip'] for entry in log_entries if entry['status'] == '401'
    )
    flagged_ips = {ip: count for ip, count in failed_attempts.items() if count > threshold}
    return flagged_ips

def save_results_to_csv(ip_counts, most_accessed, suspicious_ips, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        # Requests per IP
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])
        
        writer.writerow([])  # Blank row
        # Most Accessed Endpoint
        writer.writerow(['Most Accessed Endpoint', 'Access Count'])
        writer.writerow([most_accessed[0], most_accessed[1]])

        writer.writerow([])  # Blank row
        # Suspicious Activity
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

def main():
    print("Processing log file...")
    log_entries = parse_log(LOG_FILE)

    print("\nCounting requests per IP...")
    ip_counts = count_requests_by_ip(log_entries)
    print(f"{'IP Address':<20}{'Request Count':<15}")
    for ip, count in ip_counts.most_common():
        print(f"{ip:<20}{count:<15}")

    print("\nIdentifying the most accessed endpoint...")
    most_accessed = most_accessed_endpoint(log_entries)
    print(f"Most Frequently Accessed Endpoint: {most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nDetecting suspicious activity...")
    suspicious_ips = detect_suspicious_activity(log_entries, FAILED_LOGIN_THRESHOLD)
    if suspicious_ips:
        print(f"{'IP Address':<20}{'Failed Login Attempts':<20}")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20}{count:<20}")
    else:
        print("No suspicious activity detected.")

    print("\nSaving results to CSV...")
    save_results_to_csv(ip_counts, most_accessed, suspicious_ips, OUTPUT_FILE)
    print(f"Results saved to {OUTPUT_FILE}")

if __name__ == '__main__':
    main()
