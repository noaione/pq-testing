## pq-testing

This is just a repo for me to play around with post-quantum cryptography. Mainly made as an experiment if I want to implement this to [showtimes](https://github.com/naoTimesdev/showtimes-rs) as my auth signature verification.

Using [liboqs](https://github.com/open-quantum-safe/liboqs-rust) with this [fork](https://github.com/mikelodder7/liboqs-rust) which add ML-DSA.

### Algorithms
- ML-DSA-65-ipd (currently not based on final draft)

### Testing
**Advantages**:
- Pretty fast
- Post-quantum secure (hopefully)
- "Lightweight"

**Disadvantages**:
- Signature is pretty big to fit in a JWT-esque token.
