import csv
import re

input_file = "snyk_results.txt"
output_file = "snyk_vuln_summary.csv"

# Regex patterns for parsing
pattern = re.compile(
    r"✗ \[(?P<severity>[A-Z]+)\]\s+(?P<vulnerability>.+?)\n\s+Path:\s+.+/(?P<js_file_name>[^/]+\.js), line (?P<line>\d+)",
    re.MULTILINE
)

with open(input_file, encoding='utf-8') as f:
    data = f.read()

# Find all matches
matches = pattern.findall(data)

# Write to CSV
with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["js_file_name", "vulnerability", "line", "severity"])  # Header

    for severity, vulnerability, js_file_name, line in matches:
        writer.writerow([js_file_name.strip(), vulnerability.strip(), line.strip(), severity.capitalize()])

print(f"✅ Done! Extracted {len(matches)} vulnerabilities into '{output_file}'")
