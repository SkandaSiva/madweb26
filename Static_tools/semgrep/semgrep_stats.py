import csv
from collections import Counter

# Path to your CSV file
csv_path = "Semgrep_Code_Findings_2025_10_16 (1).csv"

descriptions = []

with open(csv_path, newline='', encoding='utf-8') as f:
    reader = csv.reader(f)
    header = next(reader)  # skip header row

    for row in reader:
        if not row:
            continue
        last_col = row[-1].strip()
        # remove surrounding quotes (if any)
        if last_col.startswith('"') and last_col.endswith('"'):
            last_col = last_col[1:-1]
        descriptions.append(last_col)

# Count unique vulnerabilities
counts = Counter(descriptions)

# Print results
print("Unique vulnerabilities and counts:\n")
for desc, count in counts.items():
    print(f'"""{desc}""" , {count}')

print(f"\nTotal unique vulnerabilities: {len(counts)}")
