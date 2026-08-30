/**
 * Bilingual UI strings. Default language: English.
 * Persisted in localStorage key "dsa-lang".
 */
(function (root) {
  "use strict";

  const STORAGE_KEY = "dsa-lang";

  const I18N = {
    en: {
      pageTitle: "DSA – Digital Signature Algorithm",
      appTitle: "DSA – Digital Signature Algorithm",
      appSubtitle: "Interactive demo: manual DSA math in the browser + Web Crypto ECDSA",
      tabManual: "Manual implementation",
      tabLibrary: "Web Crypto ECDSA",
      tabCompare: "Comparison",
      manualKeysTitle: "Key generation",
      manualKeysInfo: "Generates a DSA key pair with parameters p, q, \u03b1 and private key d. Educational small primes (p \u2248 20,000\u2013100,000) \u2014 not secure.",
      btnGenerateKeys: "Generate keys",
      generating: "Generating keys\u2026",
      publicKeyTitle: "Public key (p, q, \u03b1, \u03b2)",
      privateKeyTitle: "Private key (d)",
      signTitle: "Sign a message",
      signInfo: "Sign a message with the generated private key. The signature is a pair (r, s).",
      labelMessageToSign: "Message to sign",
      placeholderMessage: "Enter your message here\u2026",
      btnSign: "Sign message",
      signing: "Signing\u2026",
      signatureTitle: "Signature (r, s)",
      verifyTitle: "Verify a signature",
      verifyInfo: "Verify a signature with the public key.",
      labelMessage: "Message",
      placeholderVerifyMessage: "Message to verify",
      placeholderR: "Value of r",
      placeholderS: "Value of s",
      placeholderP: "Value of p",
      placeholderQ: "Value of q",
      placeholderAlpha: "Value of \u03b1",
      placeholderBeta: "Value of \u03b2",
      btnVerify: "Verify signature",
      verifying: "Verifying\u2026",
      statusValid: "Signature VALID",
      statusInvalid: "Signature INVALID",
      libBanner: "Production-grade path on GitHub Pages: Web Crypto API ECDSA P-256 (browser). The original Python lab used the cryptography library with DSA-1024 and PEM keys.",
      libKeysTitle: "Key generation (Web Crypto ECDSA P-256)",
      libKeysInfo: "Generates an ECDSA P-256 key pair via the Web Crypto API. Keys are shown as JWK JSON (not PEM DSA).",
      libPrivateJwk: "Private key (JWK)",
      libPublicJwk: "Public key (JWK)",
      libSignTitle: "Sign (Web Crypto ECDSA)",
      libSignInfo: "Sign with the ECDSA P-256 private key. The signature is a raw (r||s) hex string.",
      btnSignShort: "Sign",
      libSignatureTitle: "Signature (hex)",
      libVerifyTitle: "Verify (Web Crypto ECDSA)",
      libVerifyInfo: "Verify with the ECDSA P-256 public key kept in this tab.",
      labelSignatureHex: "Signature (hex)",
      placeholderSigHex: "Hexadecimal signature",
      btnVerifyShort: "Verify",
      compareTitle: "Implementation comparison",
      thFeature: "Characteristic",
      thManual: "Manual DSA (JS BigInt)",
      thLibrary: "Web Crypto ECDSA P-256",
      rowKeySize: "Key size",
      rowKeySizeManual: "Small primes (not secure)",
      rowKeySizeLib: "256-bit elliptic curve (production-grade)",
      rowPerf: "Performance",
      rowPerfManual: "Slower (pure JS, trial-division primes)",
      rowPerfLib: "Fast (native browser crypto)",
      rowSecurity: "Security",
      rowSecurityManual: "Educational only",
      rowSecurityLib: "Production-ready",
      rowKeyFormat: "Key format",
      rowKeyFormatManual: "Raw numbers (p, q, \u03b1, \u03b2, d)",
      rowKeyFormatLib: "JWK (JSON Web Key)",
      rowUse: "Use case",
      rowUseManual: "Understand the algorithm",
      rowUseLib: "Real applications",
      rowAlgo: "Algorithm",
      rowAlgoManual: "DSA over a finite field (SHA-256)",
      rowAlgoLib: "ECDSA on NIST P-256 (SHA-256)",
      benchTitle: "Performance test",
      benchInfo: "Times a full keygen + sign + verify cycle for both implementations (real wall-clock, not simulated).",
      btnBenchmark: "Run benchmark",
      runningBench: "Running benchmark\u2026",
      benchResults: "Results",
      benchManualLabel: "Manual DSA",
      benchLibLabel: "Web Crypto ECDSA",
      benchManualNote: "small educational parameters",
      benchLibNote: "P-256, production-grade",
      benchFaster: "Web Crypto was about {n}\u00d7 faster in this run.",
      benchManualFaster: "Manual DSA was about {n}\u00d7 faster in this run (tiny keys vs P-256).",
      benchSimilar: "Both finished in a similar time on this run.",
      alertEnterMessage: "Please enter a message.",
      alertFillAll: "Please fill in all fields.",
      alertGenerateFirst: "Generate keys first.",
      alertError: "Error: ",
      footer: "Educational demo by Hadbi Aghiles \u00b7 MIT License \u00b7 Keys stay in your browser and are never uploaded."
    },
    fr: {
      pageTitle: "DSA \u2013 Digital Signature Algorithm",
      appTitle: "DSA \u2013 Digital Signature Algorithm",
      appSubtitle: "D\u00e9mo interactive : maths DSA manuelles dans le navigateur + Web Crypto ECDSA",
      tabManual: "Impl\u00e9mentation manuelle",
      tabLibrary: "Web Crypto ECDSA",
      tabCompare: "Comparaison",
      manualKeysTitle: "G\u00e9n\u00e9ration des cl\u00e9s",
      manualKeysInfo: "G\u00e9n\u00e8re une paire de cl\u00e9s DSA avec les param\u00e8tres p, q, \u03b1 et la cl\u00e9 priv\u00e9e d. Petits nombres premiers \u00e9ducatifs (p \u2248 20 000\u2013100 000) \u2014 non s\u00e9curis\u00e9.",
      btnGenerateKeys: "G\u00e9n\u00e9rer les cl\u00e9s",
      generating: "G\u00e9n\u00e9ration des cl\u00e9s\u2026",
      publicKeyTitle: "Cl\u00e9 publique (p, q, \u03b1, \u03b2)",
      privateKeyTitle: "Cl\u00e9 priv\u00e9e (d)",
      signTitle: "Signature de message",
      signInfo: "Signe un message avec la cl\u00e9 priv\u00e9e g\u00e9n\u00e9r\u00e9e. La signature est une paire (r, s).",
      labelMessageToSign: "Message \u00e0 signer",
      placeholderMessage: "Entrez votre message ici\u2026",
      btnSign: "Signer le message",
      signing: "Signature\u2026",
      signatureTitle: "Signature (r, s)",
      verifyTitle: "V\u00e9rification de signature",
      verifyInfo: "V\u00e9rifie une signature avec la cl\u00e9 publique.",
      labelMessage: "Message",
      placeholderVerifyMessage: "Message \u00e0 v\u00e9rifier",
      placeholderR: "Valeur de r",
      placeholderS: "Valeur de s",
      placeholderP: "Valeur de p",
      placeholderQ: "Valeur de q",
      placeholderAlpha: "Valeur de \u03b1",
      placeholderBeta: "Valeur de \u03b2",
      btnVerify: "V\u00e9rifier la signature",
      verifying: "V\u00e9rification\u2026",
      statusValid: "Signature VALIDE",
      statusInvalid: "Signature INVALIDE",
      libBanner: "Chemin production sur GitHub Pages : Web Crypto API ECDSA P-256 (navigateur). Le TP Python original utilisait la biblioth\u00e8que cryptography avec DSA-1024 et des cl\u00e9s PEM.",
      libKeysTitle: "G\u00e9n\u00e9ration des cl\u00e9s (Web Crypto ECDSA P-256)",
      libKeysInfo: "G\u00e9n\u00e8re une paire de cl\u00e9s ECDSA P-256 via l'API Web Crypto. Les cl\u00e9s sont affich\u00e9es en JWK JSON (pas du DSA PEM).",
      libPrivateJwk: "Cl\u00e9 priv\u00e9e (JWK)",
      libPublicJwk: "Cl\u00e9 publique (JWK)",
      libSignTitle: "Signature (Web Crypto ECDSA)",
      libSignInfo: "Signe avec la cl\u00e9 priv\u00e9e ECDSA P-256. La signature est une cha\u00eene hex brute (r||s).",
      btnSignShort: "Signer",
      libSignatureTitle: "Signature (hex)",
      libVerifyTitle: "V\u00e9rification (Web Crypto ECDSA)",
      libVerifyInfo: "V\u00e9rifie avec la cl\u00e9 publique ECDSA P-256 conserv\u00e9e dans cet onglet.",
      labelSignatureHex: "Signature (hex)",
      placeholderSigHex: "Signature en hexad\u00e9cimal",
      btnVerifyShort: "V\u00e9rifier",
      compareTitle: "Comparaison des impl\u00e9mentations",
      thFeature: "Caract\u00e9ristique",
      thManual: "DSA manuel (JS BigInt)",
      thLibrary: "Web Crypto ECDSA P-256",
      rowKeySize: "Taille des cl\u00e9s",
      rowKeySizeManual: "Petits nombres premiers (non s\u00e9curis\u00e9)",
      rowKeySizeLib: "Courbe elliptique 256 bits (niveau production)",
      rowPerf: "Performance",
      rowPerfManual: "Plus lente (JS pur, primalit\u00e9 par division)",
      rowPerfLib: "Rapide (crypto native du navigateur)",
      rowSecurity: "S\u00e9curit\u00e9",
      rowSecurityManual: "\u00c9ducative uniquement",
      rowSecurityLib: "Pr\u00eate pour la production",
      rowKeyFormat: "Format de cl\u00e9",
      rowKeyFormatManual: "Nombres bruts (p, q, \u03b1, \u03b2, d)",
      rowKeyFormatLib: "JWK (JSON Web Key)",
      rowUse: "Utilisation",
      rowUseManual: "Comprendre l'algorithme",
      rowUseLib: "Applications r\u00e9elles",
      rowAlgo: "Algorithme",
      rowAlgoManual: "DSA sur un corps fini (SHA-256)",
      rowAlgoLib: "ECDSA sur NIST P-256 (SHA-256)",
      benchTitle: "Test de performance",
      benchInfo: "Chronom\u00e8tre un cycle complet g\u00e9n\u00e9ration + signature + v\u00e9rification pour les deux impl\u00e9mentations (temps r\u00e9el, non simul\u00e9).",
      btnBenchmark: "Lancer le benchmark",
      runningBench: "Benchmark en cours\u2026",
      benchResults: "R\u00e9sultats",
      benchManualLabel: "DSA manuel",
      benchLibLabel: "Web Crypto ECDSA",
      benchManualNote: "petits param\u00e8tres \u00e9ducatifs",
      benchLibNote: "P-256, niveau production",
      benchFaster: "Web Crypto a \u00e9t\u00e9 environ {n}\u00d7 plus rapide dans cet essai.",
      benchManualFaster: "Le DSA manuel a \u00e9t\u00e9 environ {n}\u00d7 plus rapide dans cet essai (petites cl\u00e9s vs P-256).",
      benchSimilar: "Les deux ont fini en un temps similaire dans cet essai.",
      alertEnterMessage: "Veuillez entrer un message.",
      alertFillAll: "Veuillez remplir tous les champs.",
      alertGenerateFirst: "G\u00e9n\u00e9rez d'abord les cl\u00e9s.",
      alertError: "Erreur : ",
      footer: "D\u00e9mo \u00e9ducative par Hadbi Aghiles \u00b7 Licence MIT \u00b7 Les cl\u00e9s restent dans votre navigateur et ne sont jamais envoy\u00e9es."
    }
  };

  let currentLang = "en";

  function t(key, vars) {
    const dict = I18N[currentLang] || I18N.en;
    let s = dict[key] != null ? dict[key] : (I18N.en[key] != null ? I18N.en[key] : key);
    if (vars) {
      Object.keys(vars).forEach(function (k) {
        s = s.split("{" + k + "}").join(String(vars[k]));
      });
    }
    return s;
  }

  function applyLang(lang) {
    if (lang !== "fr" && lang !== "en") lang = "en";
    currentLang = lang;
    try { localStorage.setItem(STORAGE_KEY, lang); } catch (_e) {}
    document.documentElement.lang = lang;
    document.title = t("pageTitle");
    document.querySelectorAll("[data-i18n]").forEach(function (el) {
      el.textContent = t(el.getAttribute("data-i18n"));
    });
    document.querySelectorAll("[data-i18n-placeholder]").forEach(function (el) {
      el.setAttribute("placeholder", t(el.getAttribute("data-i18n-placeholder")));
    });
    document.querySelectorAll(".lang-switch button").forEach(function (btn) {
      const isActive = btn.getAttribute("data-lang") === lang;
      btn.classList.toggle("active", isActive);
      btn.setAttribute("aria-pressed", isActive ? "true" : "false");
    });
    if (typeof root.refreshDynamicI18n === "function") root.refreshDynamicI18n();
  }

  function initLang() {
    let lang = "en";
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored === "fr" || stored === "en") lang = stored;
    } catch (_e) {}
    applyLang(lang);
    document.querySelectorAll(".lang-switch button").forEach(function (btn) {
      btn.addEventListener("click", function () {
        applyLang(btn.getAttribute("data-lang"));
      });
    });
  }

  root.I18N_DICT = I18N;
  root.t = t;
  root.applyLang = applyLang;
  root.initLang = initLang;
  root.getLang = function () { return currentLang; };
})(typeof globalThis !== "undefined" ? globalThis : this);
