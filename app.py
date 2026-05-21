from src.hasher import calculate_hash

file_path = "watched/test.txt"

hash_value = calculate_hash(file_path)

print("SHA-256 Hash:")
print(hash_value)