import hashlib

def sha256(data):
    """Compute the SHA-256 hash of the given data."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def merkle_root(txs):
    """Compute the Merkle root of a list of transactions."""
    if not txs:
        return None

    curr = [sha256(tx) for tx in txs]

    while len(curr) > 1:
        next_level = []
        for i in range(0, len(curr), 2):
            if i + 1 < len(curr):
                combined = curr[i] + curr[i + 1]
            else:
                combined = curr[i] + curr[i]
            next_level.append(sha256(combined))
        curr = next_level

    return curr[0]

def main():
    T = int(input())
    if not (1 <= T <= 10):
        print("Invalid number of test cases")
        return

    results = []

    for _ in range(T):
        N = int(input())
        if not (1 <= N <= 100):
            print(f"Invalid number of transactions: {N}")
            return

        txs = []
        for _ in range(N):
            tx = input().strip()
            if not (1 <= len(tx) <= 100):
                print(f"Invalid transaction length: {len(tx)}")
                return
            txs.append(tx)

        results.append(merkle_root(txs))

    for result in results:
        print(result)

if __name__ == "__main__":
    main()