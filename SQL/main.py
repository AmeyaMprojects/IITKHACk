import pandas as pd
import re
import requests

def is_sql_injection(payload):
    sql_patterns = [
        r"(?i)(\bunion\b|\bselect\b|\binsert\b|\bupdate\b|\bdelete\b|\bdrop\b)",
        r"\b(?:\'|\"|\%27|\%22|\`|\-\-)\b",
        r"(?i)(\bor\b|\band\b).*?=",
        r"\b(\;|\:\=|\:\:\:)\b"
    ]
    return any(re.search(pattern, payload) for pattern in sql_patterns)

file_url = input()
file_id = file_url.split("/d/")[1].split("/")[0]
download_url = f"https://drive.google.com/uc?id={file_id}&export=download"

response = requests.get(download_url)   
response.raise_for_status()

with open("temp.csv", "wb") as f:
    f.write(response.content)

try:
    data = pd.read_csv("temp.csv", sep=",", engine="python", on_bad_lines='skip')
except Exception as e:
    print(f"Error reading CSV: {e}")
    exit()

attacker_ip = "NULL"
sql_injection_count = 0
first_payload = "NULL"
last_payload = "NULL"
colon_payload_count = 0

sql_attempts = []

data["Info"] = data["Info"].fillna("")

for index, row in data.iterrows():
    info = row.get("Info", "")
    source_ip = row.get("Source", "")

    if is_sql_injection(info):
        sql_attempts.append((row.get("Time", ""), source_ip, info))

        if ":" in info:
            colon_payload_count += 1

if sql_attempts:
    sql_attempts.sort()
    attacker_ip = sql_attempts[0][1]
    sql_injection_count = len(sql_attempts)
    first_payload = sql_attempts[0][2]
    last_payload = sql_attempts[-1][2]

print(f"1A:-{attacker_ip}-;")
print(f"2A:-{sql_injection_count}-;")
print(f"3A:-{first_payload}-;")
print(f"4A:-{last_payload}-;")
print(f"5A:-{colon_payload_count}-;")
