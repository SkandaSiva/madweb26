import csv
import re

input_file = "bearer_sw_scripts.txt"
output_file = "bearer_vulnerabilities.csv"

severity_keywords = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

data = []

with open(input_file, "r", encoding="utf-8") as f:
    lines = f.readlines()

i = 0
while i < len(lines):
    line = lines[i].strip()

    # Check if the line contains a severity keyword
    if any(line.startswith(keyword + ":") for keyword in severity_keywords):
        # Extract severity and vulnerability
        severity_match = re.match(r"(CRITICAL|HIGH|MEDIUM|LOW):\s*(.+?)\s*\[CWE-\d+\]", line)
        if severity_match:
            severity = severity_match.group(1)
            vulnerability = severity_match.group(2).strip()
        else:
            i += 1
            continue

        # Move to next lines to find the File line
        i += 1
        while i < len(lines) and not lines[i].strip().startswith("File:"):
            i += 1

        if i >= len(lines):
            break

        # Extract js_file_name and line number
        file_match = re.match(r"File: .*/([^/:]+\.js):(\d+)", lines[i].strip())
        if not file_match:
            i += 1
            continue

        js_file_name = file_match.group(1)
        line_number = file_match.group(2)

        # Move to next line for the snippet
        i += 1
        snippet = ""
        if i < len(lines):
            snippet_line = lines[i].strip()
            # Snippet usually starts with the line number
            snippet_match = re.match(rf"{line_number}\s+(.+)", snippet_line)
            if snippet_match:
                snippet = snippet_match.group(1).strip()

        # Append extracted info to data
        data.append({
            "js_file_name": js_file_name,
            "vulnerability": vulnerability,
            "line": line_number,
            "severity": severity,
            "snippet": snippet
        })

    i += 1

# Write to CSV
with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
    fieldnames = ["js_file_name", "vulnerability", "line", "severity", "snippet"]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for row in data:
        writer.writerow(row)

print(f"CSV file created: {output_file}")
