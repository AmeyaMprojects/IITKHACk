import pandas as pd
import re

# Load the CSV file
file_path = input()
data = pd.read_csv(file_path)

# Function to detect SQL injection attempts
def detect_sql_injection(packet_info):
    sql_patterns = [
        r"(?i)(\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b)",  # SQL keywords
        r"(?i)\bOR\b.*=.*\bOR\b",  # Logical OR injection
        r"(?i)\bAND\b.*=.*\bAND\b",  # Logical AND injection
        r"['"].*?--",  # Comment-based injection
        r"['"].*?\bDROP\b",  # DROP keyword
        r"[;]",  # Statement termination
    ]
    for pattern in sql_patterns:
        if re.search(pattern, packet_info):
            return True
    return False

# Initialize variables
source_ip = "NULL"
sql_attempt_count = 0
first_payload = "NULL"
last_payload = "NULL"
payloads_with_colon = 0

# Filter rows with SQL injection attempts
sql_injection_rows = []

for _, row in data.iterrows():
    if row['Protocol'] == "HTTP" and detect_sql_injection(str(row['Info'])):
        sql_injection_rows.append(row)

if sql_injection_rows:
    # Convert to DataFrame for easier handling
    sql_df = pd.DataFrame(sql_injection_rows)

    # Determine source IP (attacker's IP)
    source_ip = sql_df.iloc[0]['Source']

    # Count SQL injection attempts
    sql_attempt_count = len(sql_df)

    # Extract first and last payloads
    sorted_sql_df = sql_df.sort_values(by="Time")
    first_info = sorted_sql_df.iloc[0]['Info']
    last_info = sorted_sql_df.iloc[-1]['Info']

    first_payload_match = re.search(r"(GET|POST)\s+(.*?)\s+HTTP", first_info)
    if first_payload_match:
        first_payload = first_payload_match.group(2)

    last_payload_match = re.search(r"(GET|POST)\s+(.*?)\s+HTTP", last_info)
    if last_payload_match:
        last_payload = last_payload_match.group(2)

    # Count payloads containing colons
    payloads_with_colon = sql_df['Info'].str.contains(r":").sum()

# Output results
print(f"1A:-{source_ip}-;")
print(f"2A:-{sql_attempt_count}-;")
print(f"3A:-{first_payload}-;")
print(f"4A:-{last_payload}-;")
print(f"5A:-{payloads_with_colon}-;")
