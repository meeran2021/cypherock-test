

# 🔢 Multiplicative-to-Additive (MtA) Share Conversion Demo

This repository demonstrates how to convert two **32-byte multiplicative terms** `a` and `b` into **additive shares** `c` and `d` such that:

```
(a * b) mod p == (c + d) mod p
```

All computations are done over the [secp256k1](https://en.bitcoin.it/wiki/Secp256k1) prime field:

```
p = 2^256 - 2^32 - 977
```

🔐 This project uses a **self-contained C implementation** with **no external cryptographic libraries** (e.g., no OpenSSL, no GMP).

---

## 🔧 Requirements

- C compiler: `gcc`, `clang`, or `mingw`  
- Platform: Windows, macOS, or Linux  
- No external libraries or dependencies required

---

## 🚀 How to Clone and Run

```bash
# Clone the repository
git clone https://github.com/meeran2021/cypherock-test.git

# Compile (Linux/macOS)
gcc -O2 mta_no_openssl.c -o mta

# Or on Windows (e.g. with MinGW)
gcc -O2 mta_no_openssl.c -o mta.exe

# Run
./mta         # On Linux/macOS
.\mta.exe     # On Windows
```

---

## 🧪 Example Input/Output

The program automatically generates random inputs `a` and `b` in \([0, p-1]\), computes their product, and splits it into encrypted additive shares `c` and `d`.

### Sample Run:

```
a = 562e317cce1e1c413cfa8c2670de0a36f7a3e56c68f0bc4bb1389a2c7a3fc09e
b = 91a7c52f96e7dc0197fd13d3b98b85d64dd6e60af2158e72fc9470f3b182276e
Encrypted c = eef25c15d3ef3a59c8495e...  (32 bytes XORed with key)
Encrypted d = 4a13c87a7a02ad3a4cd9ff...  (32 bytes XORed with key)
MtA success: c+d == a*b (mod p)
```
