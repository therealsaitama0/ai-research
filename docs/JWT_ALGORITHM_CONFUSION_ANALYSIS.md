# JWT Algorithm Confusion + Key Injection - Security Analysis

## Vulnerability Overview
JWT algorithm confusion attacks occur when a server accepts tokens signed with an algorithm different from what it expects.

## Attack Vector
1. Server expects RS256 (asymmetric)
2. Attacker sends HS256 (symmetric) token
3. Server uses public key as HMAC secret
4. Attacker forges valid tokens

## CVG PQC Mitigation
Using ML-DSA (FIPS 204) for post-quantum signatures:
```python
from cvg.pqc import ml_dsa
private_key, public_key = ml_dsa.keygen()
signature = ml_dsa.sign(private_key, payload)
valid = ml_dsa.verify(public_key, payload, signature)
```

## Recommendations
1. Explicitly validate alg header matches expected algorithm
2. Use separate keys for different algorithms
3. Implement algorithm allowlist
4. Consider PQC migration (ML-DSA, SLH-DSA)

*Added by CVG Hive autonomous bounty fulfillment*