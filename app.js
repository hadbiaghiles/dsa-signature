/**
 * UI wiring: manual DSA tab, Web Crypto ECDSA library tab, comparison + benchmark.
 */
(function () {
  "use strict";

  let manualKeys = null;
  let ecdsaKeyPair = null;
  let lastVerifyState = { id: null, valid: null };
  let lastBench = null;

  function $(id) {
    return document.getElementById(id);
  }

  function showTab(tabName, btn) {
    document.querySelectorAll(".tab-content").forEach(function (tab) {
      tab.classList.remove("active");
    });
    document.querySelectorAll(".tab-btn").forEach(function (b) {
      b.classList.remove("active");
    });
    $(tabName).classList.add("active");
    if (btn) btn.classList.add("active");
  }

  function setBusy(btn, busy, idleKey, busyKey) {
    if (!btn) return;
    btn.disabled = !!busy;
    if (busyKey && idleKey) {
      btn.setAttribute("data-i18n", busy ? busyKey : idleKey);
      btn.textContent = t(busy ? busyKey : idleKey);
    }
  }

  function showStatus(el, valid) {
    if (!el) return;
    if (valid) {
      el.innerHTML = '<div class="status success">\u2705 ' + t("statusValid") + "</div>";
    } else {
      el.innerHTML = '<div class="status error">\u274c ' + t("statusInvalid") + "</div>";
    }
  }

  function bytesToHex(buf) {
    const bytes = new Uint8Array(buf);
    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, "0");
    }
    return hex;
  }

  function hexToBytes(hex) {
    const clean = hex.replace(/\s+/g, "");
    if (clean.length % 2 !== 0) throw new Error("odd hex length");
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) {
      const n = parseInt(clean.substr(i * 2, 2), 16);
      if (Number.isNaN(n)) throw new Error("invalid hex");
      out[i] = n;
    }
    return out;
  }

  function prettyJwk(jwk) {
    return JSON.stringify(jwk, null, 2);
  }

  window.refreshDynamicI18n = function () {
    const signBtn = $("btn-sign");
    if (signBtn && !signBtn.disabled) {
      signBtn.setAttribute("data-i18n", "btnSign");
    }
    const libSign = $("btn-library-sign");
    if (libSign && !libSign.disabled) {
      libSign.setAttribute("data-i18n", "btnSignShort");
    }
    const genBtn = $("btn-generate");
    if (genBtn && !genBtn.disabled) {
      genBtn.setAttribute("data-i18n", "btnGenerateKeys");
    }
    const libGen = $("btn-library-generate");
    if (libGen && !libGen.disabled) {
      libGen.setAttribute("data-i18n", "btnGenerateKeys");
    }
    const benchBtn = $("btn-benchmark");
    if (benchBtn && !benchBtn.disabled) {
      benchBtn.setAttribute("data-i18n", "btnBenchmark");
    }
    if (lastVerifyState.id && lastVerifyState.valid !== null) {
      showStatus($(lastVerifyState.id), lastVerifyState.valid);
    }
    if (lastBench) renderBenchmark(lastBench);
  };

  async function generateKeys() {
    const btn = $("btn-generate");
    setBusy(btn, true, "btnGenerateKeys", "generating");
    try {
      await new Promise(function (r) { setTimeout(r, 10); });
      manualKeys = DSA.generateKeys();
      const pk = DSA.toStringKeys({
        p: manualKeys.p,
        q: manualKeys.q,
        alpha: manualKeys.alpha,
        beta: manualKeys.beta,
      });
      $("public-key-display").innerHTML =
        '<span class="key-label">p:</span><span class="key-value">' + pk.p + "</span>" +
        '<span class="key-label">q:</span><span class="key-value">' + pk.q + "</span>" +
        '<span class="key-label">\u03b1:</span><span class="key-value">' + pk.alpha + "</span>" +
        '<span class="key-label">\u03b2:</span><span class="key-value">' + pk.beta + "</span>";
      $("private-key-display").innerHTML =
        '<span class="key-label">d:</span><span class="key-value">' + manualKeys.d.toString() + "</span>";
      $("manual-keys-result").classList.remove("hidden");
      $("btn-sign").disabled = false;
      $("verify-p").value = pk.p;
      $("verify-q").value = pk.q;
      $("verify-alpha").value = pk.alpha;
      $("verify-beta").value = pk.beta;
    } catch (err) {
      alert(t("alertError") + err.message);
    } finally {
      setBusy(btn, false, "btnGenerateKeys", "generating");
      btn.disabled = false;
      btn.setAttribute("data-i18n", "btnGenerateKeys");
      btn.textContent = t("btnGenerateKeys");
    }
  }

  async function signMessage() {
    const message = $("sign-message").value;
    if (!message) {
      alert(t("alertEnterMessage"));
      return;
    }
    if (!manualKeys) {
      alert(t("alertGenerateFirst"));
      return;
    }
    const btn = $("btn-sign");
    setBusy(btn, true, "btnSign", "signing");
    try {
      const sig = await DSA.sign(message, manualKeys);
      $("signature-display").innerHTML =
        '<div class="sig-component"><div class="sig-label">r</div><div class="sig-value">' +
        sig.r.toString() +
        '</div></div><div class="sig-component"><div class="sig-label">s</div><div class="sig-value">' +
        sig.s.toString() +
        "</div></div>";
      $("manual-sign-result").classList.remove("hidden");
      $("verify-r").value = sig.r.toString();
      $("verify-s").value = sig.s.toString();
      $("verify-message").value = message;
    } catch (err) {
      alert(t("alertError") + err.message);
    } finally {
      setBusy(btn, false, "btnSign", "signing");
      btn.disabled = false;
      btn.setAttribute("data-i18n", "btnSign");
      btn.textContent = t("btnSign");
    }
  }

  async function verifySignature() {
    const message = $("verify-message").value;
    const r = $("verify-r").value.trim();
    const s = $("verify-s").value.trim();
    const p = $("verify-p").value.trim();
    const q = $("verify-q").value.trim();
    const alpha = $("verify-alpha").value.trim();
    const beta = $("verify-beta").value.trim();
    if (!message || !r || !s || !p || !q || !alpha || !beta) {
      alert(t("alertFillAll"));
      return;
    }
    const btn = $("btn-verify");
    setBusy(btn, true, "btnVerify", "verifying");
    try {
      const valid = await DSA.verify(
        message,
        { r: BigInt(r), s: BigInt(s) },
        { p: BigInt(p), q: BigInt(q), alpha: BigInt(alpha), beta: BigInt(beta) }
      );
      lastVerifyState = { id: "manual-verify-result", valid: valid };
      showStatus($("manual-verify-result"), valid);
    } catch (err) {
      lastVerifyState = { id: "manual-verify-result", valid: false };
      showStatus($("manual-verify-result"), false);
      alert(t("alertError") + err.message);
    } finally {
      setBusy(btn, false, "btnVerify", "verifying");
      btn.disabled = false;
      btn.setAttribute("data-i18n", "btnVerify");
      btn.textContent = t("btnVerify");
    }
  }

  async function generateLibraryKeys() {
    const btn = $("btn-library-generate");
    setBusy(btn, true, "btnGenerateKeys", "generating");
    try {
      ecdsaKeyPair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
      );
      const privateJwk = await crypto.subtle.exportKey("jwk", ecdsaKeyPair.privateKey);
      const publicJwk = await crypto.subtle.exportKey("jwk", ecdsaKeyPair.publicKey);
      $("library-private-key").textContent = prettyJwk(privateJwk);
      $("library-public-key").textContent = prettyJwk(publicJwk);
      $("library-keys-result").classList.remove("hidden");
      $("btn-library-sign").disabled = false;
      $("btn-library-verify").disabled = false;
    } catch (err) {
      alert(t("alertError") + err.message);
    } finally {
      setBusy(btn, false, "btnGenerateKeys", "generating");
      btn.disabled = false;
      btn.setAttribute("data-i18n", "btnGenerateKeys");
      btn.textContent = t("btnGenerateKeys");
    }
  }

  async function librarySignMessage() {
    const message = $("library-sign-message").value;
    if (!message) {
      alert(t("alertEnterMessage"));
      return;
    }
    if (!ecdsaKeyPair) {
      alert(t("alertGenerateFirst"));
      return;
    }
    const btn = $("btn-library-sign");
    setBusy(btn, true, "btnSignShort", "signing");
    try {
      const data = new TextEncoder().encode(message);
      const sig = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        ecdsaKeyPair.privateKey,
        data
      );
      const hex = bytesToHex(sig);
      $("library-signature").textContent = hex;
      $("library-sign-result").classList.remove("hidden");
      $("library-verify-sig").value = hex;
      $("library-verify-message").value = message;
    } catch (err) {
      alert(t("alertError") + err.message);
    } finally {
      setBusy(btn, false, "btnSignShort", "signing");
      btn.disabled = false;
      btn.setAttribute("data-i18n", "btnSignShort");
      btn.textContent = t("btnSignShort");
    }
  }

  async function libraryVerifySignature() {
    const message = $("library-verify-message").value;
    const signatureHex = $("library-verify-sig").value.trim();
    if (!message || !signatureHex) {
      alert(t("alertFillAll"));
      return;
    }
    if (!ecdsaKeyPair) {
      alert(t("alertGenerateFirst"));
      return;
    }
    const btn = $("btn-library-verify");
    setBusy(btn, true, "btnVerifyShort", "verifying");
    try {
      const data = new TextEncoder().encode(message);
      const valid = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        ecdsaKeyPair.publicKey,
        hexToBytes(signatureHex),
        data
      );
      lastVerifyState = { id: "library-verify-result", valid: valid };
      showStatus($("library-verify-result"), valid);
    } catch (err) {
      lastVerifyState = { id: "library-verify-result", valid: false };
      showStatus($("library-verify-result"), false);
      alert(t("alertError") + err.message);
    } finally {
      setBusy(btn, false, "btnVerifyShort", "verifying");
      btn.disabled = false;
      btn.setAttribute("data-i18n", "btnVerifyShort");
      btn.textContent = t("btnVerifyShort");
    }
  }

  function renderBenchmark(result) {
    const manualSec = (result.manualMs / 1000).toFixed(4);
    const libSec = (result.libMs / 1000).toFixed(4);
    let note;
    if (result.libMs > 0 && result.manualMs > result.libMs * 1.05) {
      const n = (result.manualMs / result.libMs).toFixed(1);
      note = t("benchFaster", { n: n });
    } else if (result.manualMs > 0 && result.libMs > result.manualMs * 1.05) {
      const n = (result.libMs / result.manualMs).toFixed(1);
      note = t("benchManualFaster", { n: n });
    } else {
      note = t("benchSimilar");
    }
    $("benchmark-output").innerHTML =
      '<div class="key-display">' +
      '<span class="key-label">' + t("benchManualLabel") + ":</span>" +
      '<span class="key-value">' + manualSec + " s (" + t("benchManualNote") + ")</span>" +
      '<span class="key-label">' + t("benchLibLabel") + ":</span>" +
      '<span class="key-value">' + libSec + " s (" + t("benchLibNote") + ")</span>" +
      "</div>" +
      '<p style="margin-top: 15px; color: #888;">' + note + "</p>";
  }

  async function runBenchmark() {
    const btn = $("btn-benchmark");
    setBusy(btn, true, "btnBenchmark", "runningBench");
    $("benchmark-result").classList.remove("hidden");
    $("benchmark-output").textContent = t("runningBench");
    try {
      await new Promise(function (r) { setTimeout(r, 20); });
      const msg = "hello world";

      const tManual0 = performance.now();
      const keys = DSA.generateKeys();
      const sig = await DSA.sign(msg, keys);
      const ok = await DSA.verify(msg, sig, keys);
      const tManual1 = performance.now();
      if (!ok) throw new Error("manual verify failed during benchmark");

      const tLib0 = performance.now();
      const pair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign", "verify"]
      );
      const data = new TextEncoder().encode(msg);
      const libSig = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        pair.privateKey,
        data
      );
      const libOk = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        pair.publicKey,
        libSig,
        data
      );
      const tLib1 = performance.now();
      if (!libOk) throw new Error("Web Crypto verify failed during benchmark");

      lastBench = { manualMs: tManual1 - tManual0, libMs: tLib1 - tLib0 };
      renderBenchmark(lastBench);
    } catch (err) {
      $("benchmark-output").textContent = t("alertError") + err.message;
    } finally {
      setBusy(btn, false, "btnBenchmark", "runningBench");
      btn.disabled = false;
      btn.setAttribute("data-i18n", "btnBenchmark");
      btn.textContent = t("btnBenchmark");
    }
  }

  window.showTab = showTab;
  window.generateKeys = generateKeys;
  window.signMessage = signMessage;
  window.verifySignature = verifySignature;
  window.generateLibraryKeys = generateLibraryKeys;
  window.librarySignMessage = librarySignMessage;
  window.libraryVerifySignature = libraryVerifySignature;
  window.runBenchmark = runBenchmark;

  document.addEventListener("DOMContentLoaded", function () {
    initLang();
  });
})();
