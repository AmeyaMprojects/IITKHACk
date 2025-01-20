import hashlib

def sha256_hash(data):
    """Compute the SHA-256 hash of the given data."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def compute_merkle_root(transactions):
    """Compute the Merkle root of a list of transactions."""
    if not transactions:
        return None

    # Hash all transactions
    current_level = [sha256_hash(tx) for tx in transactions]

    # Continue hashing pairs until one hash remains
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            if i + 1 < len(current_level):
                # Hash the pair
                combined = current_level[i] + current_level[i + 1]
            else:
                # Duplicate the last transaction if odd
                combined = current_level[i] + current_level[i]
            next_level.append(sha256_hash(combined))
        current_level = next_level

    return current_level[0]

def main():
    T = int(input())
    results = []

    for _ in range(T):
        N = int(input())
        transactions = [input().strip() for _ in range(N)]
        merkle_root = compute_merkle_root(transactions)
        results.append(merkle_root)

    for result in results:
        print(result)

if __name__ == "__main__":
    main()
