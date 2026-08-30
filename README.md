# DSA Signature Demo

[![Live demo](https://img.shields.io/badge/demo-GitHub%20Pages-00d4ff)](https://hadbiaghiles.github.io/dsa-signature/)
[![License: MIT](https://img.shields.io/badge/License-MIT-7b2cbf.svg)](LICENSE)

Interactive **Digital Signature Algorithm** demo by **Hadbi Aghiles**.

The live site is a static GitHub Pages app that runs entirely in the browser (no Flask server). Switch the UI between **English** and **Français** with the pill in the header (choice is saved in `localStorage` key `dsa-lang`).

**Live demo:** https://hadbiaghiles.github.io/dsa-signature/

## What you can do

1. **Manual DSA** — educational implementation of DSA math in JavaScript (`BigInt`): generate `p / q / α / d / β`, sign `(r, s)`, verify. Uses the same small primes as the original Python lab (`p` in ~20,000–100,000). Hash is Web Crypto SHA-256; modular inverse uses the extended Euclidean algorithm.
2. **Web Crypto ECDSA** — production-grade path on Pages: ECDSA P-256 via the Web Crypto API (sign / verify, keys shown as JWK JSON). This is **not** the original Python `cryptography` DSA-1024/PEM flow; that remains in `python/` for local lab work.
3. **Comparison** — table plus a real benchmark (actual `performance.now()` timings of keygen + sign + verify, not random fake numbers).

Keys are generated in your browser and never uploaded. **Do not commit PEM files.**

## Run the static demo locally

Open `index.html` in a browser, or from the repo root:

```bash
python3 -m http.server 8080
```

Then visit http://127.0.0.1:8080/

## Python lab (original)

The original educational Python lives under `python/`:

- `python/DSA.py` — manual DSA + `cryptography` library demo (writes `dsa_private.pem` / `dsa_public.pem` **locally**; those files are gitignored and must never be committed)
- `python/app.py` — optional Flask API from the original TP
- `python/requirements.txt`

```bash
cd python
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python DSA.py
# optional Flask API:
python app.py               # http://127.0.0.1:5000
```

## Security note

The manual DSA parameters are **intentionally tiny** so the math is easy to inspect. They are not safe for real signatures. Use Web Crypto ECDSA (this site) or a maintained library (Python `cryptography`, etc.) in production.

## License

MIT © Hadbi Aghiles
