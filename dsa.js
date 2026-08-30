/**
 * Educational DSA (Digital Signature Algorithm) implemented with JS BigInt.
 * Uses small primes (p in ~20,000–100,000), matching the original Python lab.
 * NOT cryptographically secure. Production path on this demo is Web Crypto ECDSA P-256.
 */
(function (root) {
  "use strict";

  const P_MIN = 20000;
  const P_MAX = 100000;
  const Q_MIN = 50n;
  const MAX_P_ATTEMPTS = 800;

  function bytesToBigInt(bytes) {
    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, "0");
    }
    return hex.length ? BigInt("0x" + hex) : 0n;
  }

  function sqrtBigInt(n) {
    if (n < 0n) throw new Error("sqrt of negative");
    if (n < 2n) return n;
    let x = n;
    let y = (x + 1n) / 2n;
    while (y < x) {
      x = y;
      y = (x + n / x) / 2n;
    }
    return x;
  }

  function isPrime(n) {
    n = BigInt(n);
    if (n < 2n) return false;
    if (n === 2n || n === 3n) return true;
    if (n % 2n === 0n || n % 3n === 0n) return false;
    const limit = sqrtBigInt(n);
    for (let i = 5n; i <= limit; i += 6n) {
      if (n % i === 0n || n % (i + 2n) === 0n) return false;
    }
    return true;
  }

  function randomInt(min, max) {
    min = Math.ceil(min);
    max = Math.floor(max);
    const span = max - min + 1;
    const cryptoObj = root.crypto;
    if (cryptoObj && typeof cryptoObj.getRandomValues === "function") {
      const buf = new Uint32Array(1);
      cryptoObj.getRandomValues(buf);
      return min + (buf[0] % span);
    }
    return min + Math.floor(Math.random() * span);
  }

  function randomBigIntInclusive(min, max) {
    min = BigInt(min);
    max = BigInt(max);
    if (max < min) throw new Error("invalid range");
    const span = max - min + 1n;
    const bits = span.toString(2).length;
    const byteLen = Math.ceil(bits / 8) + 1;
    const buf = new Uint8Array(byteLen);
    const cryptoObj = root.crypto;
    function fill() {
      if (cryptoObj && typeof cryptoObj.getRandomValues === "function") {
        cryptoObj.getRandomValues(buf);
      } else {
        for (let i = 0; i < buf.length; i++) buf[i] = Math.floor(Math.random() * 256);
      }
    }
    fill();
    let x = bytesToBigInt(buf);
    return min + (x % span);
  }

  function modPow(base, exp, mod) {
    base = BigInt(base);
    exp = BigInt(exp);
    mod = BigInt(mod);
    if (mod === 0n) throw new Error("mod 0");
    if (mod === 1n) return 0n;
    if (exp < 0n) throw new Error("negative exponent");
    let result = 1n;
    base = ((base % mod) + mod) % mod;
    while (exp > 0n) {
      if (exp & 1n) result = (result * base) % mod;
      exp >>= 1n;
      base = (base * base) % mod;
    }
    return result;
  }

  function egcd(a, b) {
    a = BigInt(a);
    b = BigInt(b);
    if (a < 0n) a = -a;
    if (b < 0n) b = -b;
    let x0 = 1n;
    let x1 = 0n;
    let y0 = 0n;
    let y1 = 1n;
    while (b !== 0n) {
      const q = a / b;
      const nb = a % b;
      a = b;
      b = nb;
      const nx = x0 - q * x1;
      x0 = x1;
      x1 = nx;
      const ny = y0 - q * y1;
      y0 = y1;
      y1 = ny;
    }
    return { g: a, x: x0, y: y0 };
  }

  function modInverse(a, m) {
    m = BigInt(m);
    a = ((BigInt(a) % m) + m) % m;
    const { g, x } = egcd(a, m);
    if (g !== 1n) throw new Error("no modular inverse");
    return ((x % m) + m) % m;
  }

  function generateP(intervalMin, intervalMax) {
    const lo = intervalMin == null ? P_MIN : intervalMin;
    const hi = intervalMax == null ? P_MAX : intervalMax;
    for (let i = 0; i < 20000; i++) {
      let n = randomInt(lo, hi);
      if (n % 2 === 0) n += 1;
      if (n > hi) n = hi % 2 === 0 ? hi - 1 : hi;
      if (n < lo) continue;
      if (isPrime(BigInt(n))) return BigInt(n);
    }
    throw new Error("failed to generate prime p");
  }

  function primeDivisorsOf(n, minValue) {
    n = BigInt(n);
    const primes = [];
    const seen = new Set();
    function add(p) {
      if (p > minValue && isPrime(p) && !seen.has(p.toString())) {
        seen.add(p.toString());
        primes.push(p);
      }
    }
    let rem = n;
    if (rem % 2n === 0n) {
      add(2n);
      while (rem % 2n === 0n) rem /= 2n;
    }
    let f = 3n;
    while (f * f <= rem) {
      if (rem % f === 0n) {
        add(f);
        while (rem % f === 0n) rem /= f;
      }
      f += 2n;
    }
    if (rem > 1n) add(rem);
    return primes;
  }

  function generateQ(p, minValue) {
    const minV = minValue == null ? Q_MIN : BigInt(minValue);
    const primes = primeDivisorsOf(p - 1n, minV);
    if (primes.length === 0) return null;
    return primes[randomInt(0, primes.length - 1)];
  }

  function generateAlpha(p, q) {
    const exp = (p - 1n) / q;
    const limit = p - 1n;
    for (let g = 2n; g < limit; g++) {
      const alpha = modPow(g, exp, p);
      if (alpha !== 1n && modPow(alpha, q, p) === 1n) return alpha;
    }
    return null;
  }

  function generatePrivateKey(q) {
    return randomBigIntInclusive(1n, q - 1n);
  }

  function calculatePublicKey(alpha, d, p) {
    return modPow(alpha, d, p);
  }

  function generateKeys() {
    for (let attempt = 0; attempt < MAX_P_ATTEMPTS; attempt++) {
      const p = generateP();
      const q = generateQ(p);
      if (q == null) continue;
      const alpha = generateAlpha(p, q);
      if (alpha == null) continue;
      const d = generatePrivateKey(q);
      const beta = calculatePublicKey(alpha, d, p);
      return { p, q, alpha, d, beta };
    }
    throw new Error("failed to generate DSA parameters");
  }

  async function sha256ToBigInt(message) {
    const encoded =
      typeof TextEncoder !== "undefined"
        ? new TextEncoder().encode(message)
        : Buffer.from(String(message), "utf8");
    let digest;
    if (root.crypto && root.crypto.subtle && typeof root.crypto.subtle.digest === "function") {
      const buf = await root.crypto.subtle.digest("SHA-256", encoded);
      digest = new Uint8Array(buf);
    } else {
      const nodeCrypto = require("crypto");
      digest = new Uint8Array(nodeCrypto.createHash("sha256").update(String(message), "utf8").digest());
    }
    return bytesToBigInt(digest);
  }

  async function sign(message, params) {
    const { p, q, alpha, d } = params;
    const hashInt = await sha256ToBigInt(message);
    for (let i = 0; i < 10000; i++) {
      const k = randomBigIntInclusive(1n, q - 1n);
      const r = modPow(alpha, k, p) % q;
      if (r === 0n) continue;
      let kInv;
      try {
        kInv = modInverse(k, q);
      } catch (_e) {
        continue;
      }
      const s = (kInv * (hashInt + d * r)) % q;
      if (s !== 0n) return { r, s };
    }
    throw new Error("failed to produce signature");
  }

  async function verify(message, signature, publicParams) {
    const r = BigInt(signature.r);
    const s = BigInt(signature.s);
    const { p, q, alpha, beta } = publicParams;
    if (r === 0n || s === 0n) return false;
    if (r < 0n || s < 0n || r >= q || s >= q) return false;
    const hashInt = await sha256ToBigInt(message);
    let w;
    try {
      w = modInverse(s, q);
    } catch (_e) {
      return false;
    }
    const u1 = (hashInt * w) % q;
    const u2 = (r * w) % q;
    const v = (((modPow(alpha, u1, p) * modPow(beta, u2, p)) % p) % q);
    return v === r;
  }

  function toStringKeys(keys) {
    const out = {};
    for (const k of Object.keys(keys)) out[k] = keys[k].toString();
    return out;
  }

  const DSA = {
    isPrime,
    modPow,
    modInverse,
    generateP,
    generateQ,
    generateAlpha,
    generatePrivateKey,
    calculatePublicKey,
    generateKeys,
    sign,
    verify,
    sha256ToBigInt,
    toStringKeys,
  };

  root.DSA = DSA;
  if (typeof module !== "undefined" && module.exports) {
    module.exports = DSA;
  }
})(typeof globalThis !== "undefined" ? globalThis : this);
