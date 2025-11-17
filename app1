import os
import json
import base64
import hashlib
from math import gcd

def mod_exp(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result

def is_prime(n, k=5):
    if n < 2: return False
    if n == 2 or n == 3: return True
    if n % 2 == 0: return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = 2 + os.urandom(1)[0] % (n - 3)
        x = mod_exp(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = mod_exp(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits=512):
    while True:
        num = int.from_bytes(os.urandom(bits // 8), 'big')
        num |= (1 << bits - 1) | 1
        if is_prime(num):
            return num

def mod_inverse(a, m):
    if gcd(a, m) != 1:
        return None
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m

def generate_keypair():
    """RSA key pair generation"""
    print("Generating keys (this may take 5–10 seconds).")
    p, q = generate_prime(512), generate_prime(512)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi)

    public_key = {'e': e, 'n': n}
    private_key = {'d': d, 'n': n}
    return public_key, private_key

def key_to_string(key):
    """Convert key to string"""
    json_str = json.dumps(key)
    return base64.b64encode(json_str.encode()).decode()

def string_to_key(key_str):
    """Convert string to key"""
    try:
        json_str = base64.b64decode(key_str.encode()).decode()
        return json.loads(json_str)
    except:
        return None

def encrypt_message(message, public_key_str):
    """Encrypt message using public key"""
    public_key = string_to_key(public_key_str)
    if not public_key:
        return None

    e, n = public_key['e'], public_key['n']
    block_size = (n.bit_length() - 1) // 8 - 1
    encrypted_blocks = []

    for i in range(0, len(message), block_size):
        block = message[i:i + block_size]
        m = int.from_bytes(block, 'big')
        c = mod_exp(m, e, n)
        encrypted_blocks.append(c)

    #encode to string
    result = json.dumps(encrypted_blocks)
    return base64.b64encode(result.encode()).decode()

def decrypt_message(encrypted_str, private_key_str):
    """Decrypt message using private key"""
    private_key = string_to_key(private_key_str)
    if not private_key:
        return None

    d, n = private_key['d'], private_key['n']

    try:
        #decode blocks
        result = base64.b64decode(encrypted_str.encode()).decode()
        encrypted_blocks = json.loads(result)

        decrypted_data = b''
        for c in encrypted_blocks:
            m = mod_exp(c, d, n)
            block = m.to_bytes((m.bit_length() + 7) // 8, 'big')
            decrypted_data += block

        return decrypted_data.decode('utf-8')
    except:
        return None

def main():
    public_key, private_key = None, None

    while True:
        print("\n" + "=" * 50)
        print("RSA ENCRYPTION WITH PUBLIC/PRIVATE KEY")
        print("=" * 50)
        print("1. Generate pair of keys")
        print("2. Show my keys")
        print("3. Encrypt message (public key required)")
        print("4. Decrypt message (private key required)")
        print("0. Exit")
        print("=" * 50)

        c = input("\nChoice: ").strip()

        if c == "1":
            public_key, private_key = generate_keypair()
            print("\nKeys generated!")
            print("\nPUBLIC KEY (share with someone who wants to encrypt messages to you):")
            print("-" * 50)
            pub_str = key_to_string(public_key)
            print(pub_str)
            print("-" * 50)
            print("\nPRIVATE KEY (keep it secret!):")
            print("-" * 50)
            priv_str = key_to_string(private_key)
            print(priv_str)
            print("-" * 50)

        elif c == "2":
            if not public_key:
                print("Generate keys first (option 1)")
            else:
                print("\nPUBLIC KEY:")
                print(key_to_string(public_key))
                print("\nPRIVATE KEY:")
                print(key_to_string(private_key))

        elif c == "3":
            print("\nEnter the message to encrypt:")
            message = input("> ")
            print("\nPaste the recipient's PUBLIC key:")
            pub_key_str = input("> ")

            encrypted = encrypt_message(message.encode('utf-8'), pub_key_str)
            if encrypted:
                print("\nENCRYPTED MESSAGE:")
                print("-" * 50)
                print(encrypted)
                print("-" * 50)
                print("\nSend this to the recipient!")
            else:
                print("Encryption error. Check the key!")

        elif c == "4":
            print("\nPaste the encrypted message:")
            encrypted_str = input("> ")
            print("\nPaste your PRIVATE key:")
            priv_key_str = input("> ")

            decrypted = decrypt_message(encrypted_str, priv_key_str)
            if decrypted:
                print("\nDECRYPTED MESSAGE:")
                print("-" * 50)
                print(decrypted)
                print("-" * 50)
            else:
                print("Decryption error. Check the key and message!")

        elif c == "0":
            print("\nGoodbye!")
            break
        else:
            print("Invalid choice!")

if __name__ == "__main__":
    main()
