import pandas as pd
import re

# Load the CSV file
file_path = input()
data = pd.read_csv(file_path)

attacker = "NULL"
sql_count = 0
first_payload = "NULL"
last_payload = "NULL"
colon_count = 0
attempts = []

for _, row in data.iterrows():
    info = row.get("Info", "").strip()
    src = row.get("Source", "").strip()

    # Remove HTTP method and version if present
    info = re.sub(r"^(GET|POST|PUT|DELETE|HEAD)\s+", "", info)
    info = re.sub(r"\s+HTTP/\d\.\d$", "", info)

    if re.search(r"(?i)(\bunion\b|\bselect\b|\binsert\b|\bupdate\b|\bdelete\b|\bdrop\b|\bor\b|\band\b).*?=|\b(?:\'|\"|\%27|\%22|\`|\-\-)|\b(\;|\:\=|\:\:\:)\b", info):
        attempts.append((row.get("Time", ""), src, info))
        # Increment colon count only if the payload contains a colon
        if ":" in info:
            colon_count += 1

if attempts:
    attempts.sort()
    attacker = attempts[0][1]
    sql_count = len(attempts)
    first_payload = attempts[0][2]
    last_payload = attempts[-1][2]

print(f"1A: {attacker}")
print(f"2A: {sql_count}")
print(f"3A: {first_payload}")
print(f"4A: {last_payload}")
print(f"5A: {colon_count}")