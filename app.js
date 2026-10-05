"use strict";

const PREFIX = "BY1.";
const ITERATIONS = 600000;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const MIN_PAYLOAD_BYTES = 4 + SALT_BYTES + IV_BYTES + 16;
const KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const protocolBytes = encoder.encode("Bytarith/BY1/AES-256-GCM/PBKDF2-SHA256");

const $ = (id) => document.getElementById(id);

function setStatus(message, type) {
  const el = $("statusLine");
  el.textContent = message || "";
  el.className = "status-line" + (type ? " " + type : "");
}

function concatBytes() {
  const arrays = Array.from(arguments);
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  arrays.forEach((a) => {
    out.set(a, offset);
    offset += a.length;
  });
  return out;
}

function uint32Bytes(value) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

function bytesToUint32(bytes) {
  return new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, false);
}

function bytesToBase64Url(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("The BY1 payload contains invalid characters.");
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  let binary;
  try {
    binary = atob(padded);
  } catch {
    throw new Error("The BY1 payload is not valid Base64URL data.");
  }
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

async function deriveAesKey(secret, salt, iterations) {
  const material = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256"
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function generateSecureKey() {
  const random = new Uint8Array(16);
  crypto.getRandomValues(random);
  let raw = "";
  for (let i = 0; i < random.length; i++) raw += KEY_ALPHABET[random[i] & 31];
  return raw.match(/.{1,4}/g).join("-");
}

function generatedKeyLike(value) {
  return /^[A-HJ-NP-Z2-9]{4}(?:-[A-HJ-NP-Z2-9]{4}){3}$/.test(value);
}

function updateKeyStrength() {
  const value = $("encryptKey").value;
  const label = $("keyStrength");
  if (!value) {
    label.textContent = "Use a generated key";
  } else if (generatedKeyLike(value)) {
    label.textContent = "80-bit generated key";
  } else if (value.length >= 16) {
    label.textContent = "Long custom key";
  } else if (value.length >= 10) {
    label.textContent = "Custom key";
  } else {
    label.textContent = "Weak custom key";
  }
}

function updateByteCount() {
  $("plainCount").textContent = encoder.encode($("plainInput").value).length + " bytes";
}

async function encryptMessage() {
  const plaintext = $("plainInput").value;
  const secret = $("encryptKey").value;

  if (!plaintext.length) throw new Error("Enter a message to encrypt.");
  if (secret.length < 8) throw new Error("Use a key with at least 8 characters. A generated key is recommended.");
  if (!window.crypto || !crypto.subtle) throw new Error("Web Crypto is unavailable in this browser.");

  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const iterationBytes = uint32Bytes(ITERATIONS);
  const key = await deriveAesKey(secret, salt, ITERATIONS);
  const additionalData = concatBytes(protocolBytes, iterationBytes, salt, iv);

  const encrypted = new Uint8Array(await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData,
      tagLength: 128
    },
    key,
    encoder.encode(plaintext)
  ));

  const packed = concatBytes(iterationBytes, salt, iv, encrypted);
  return PREFIX + bytesToBase64Url(packed);
}

async function decryptMessage(serialized, secret) {
  const input = serialized.trim();
  if (!input.startsWith(PREFIX)) throw new Error("This is not a BY1 Bytarith string.");
  if (secret.length < 8) throw new Error("Enter the matching Bytarith key.");

  const packed = base64UrlToBytes(input.slice(PREFIX.length));
  if (packed.length < MIN_PAYLOAD_BYTES) throw new Error("The BY1 string is incomplete or damaged.");

  const iterationBytes = packed.slice(0, 4);
  const iterations = bytesToUint32(iterationBytes);
  if (iterations !== ITERATIONS) throw new Error("Unsupported BY1 key-derivation settings.");

  const salt = packed.slice(4, 4 + SALT_BYTES);
  const iv = packed.slice(4 + SALT_BYTES, 4 + SALT_BYTES + IV_BYTES);
  const ciphertext = packed.slice(4 + SALT_BYTES + IV_BYTES);
  const key = await deriveAesKey(secret, salt, iterations);
  const additionalData = concatBytes(protocolBytes, iterationBytes, salt, iv);

  let decrypted;
  try {
    decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData,
        tagLength: 128
      },
      key,
      ciphertext
    );
  } catch {
    throw new Error("Decryption failed. The key is wrong, or the BY1 string was changed.");
  }

  try {
    return decoder.decode(decrypted);
  } catch {
    throw new Error("The decrypted data is not valid UTF-8 text.");
  }
}

function setBusy(button, busy, label) {
  if (busy) {
    button.dataset.original = button.querySelector("span").textContent;
    button.querySelector("span").textContent = label;
    button.disabled = true;
  } else {
    button.querySelector("span").textContent = button.dataset.original || button.querySelector("span").textContent;
    button.disabled = false;
  }
}

async function copyText(value, successMessage) {
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
    setStatus(successMessage, "success");
  } catch {
    setStatus("Copy failed. Select the text and copy it manually.", "error");
  }
}

function switchMode(mode) {
  const encrypting = mode === "encrypt";
  $("encryptTab").classList.toggle("active", encrypting);
  $("decryptTab").classList.toggle("active", !encrypting);
  $("encryptTab").setAttribute("aria-selected", String(encrypting));
  $("decryptTab").setAttribute("aria-selected", String(!encrypting));
  $("encryptPanel").hidden = !encrypting;
  $("decryptPanel").hidden = encrypting;
  $("encryptPanel").classList.toggle("active", encrypting);
  $("decryptPanel").classList.toggle("active", !encrypting);
  setStatus("");
}

$("encryptTab").addEventListener("click", () => switchMode("encrypt"));
$("decryptTab").addEventListener("click", () => switchMode("decrypt"));
$("plainInput").addEventListener("input", updateByteCount);
$("encryptKey").addEventListener("input", updateKeyStrength);

$("generateKey").addEventListener("click", () => {
  $("encryptKey").value = generateSecureKey();
  $("encryptKey").type = "text";
  const visibility = document.querySelector('[data-target="encryptKey"]');
  visibility.textContent = "Hide";
  updateKeyStrength();
  setStatus("Secure 80-bit random key generated. Keep it separate from the BY1 string.", "success");
});

document.querySelectorAll(".key-visibility").forEach((button) => {
  button.addEventListener("click", () => {
    const input = $(button.dataset.target);
    const showing = input.type === "text";
    input.type = showing ? "password" : "text";
    button.textContent = showing ? "Show" : "Hide";
  });
});

$("encryptButton").addEventListener("click", async () => {
  const button = $("encryptButton");
  setBusy(button, true, "Encrypting…");
  setStatus("Deriving a 256-bit key and encrypting locally…");
  try {
    const result = await encryptMessage();
    $("cipherOutput").value = result;
    $("cipherSize").textContent = result.length + " characters";
    $("encryptResult").classList.remove("hidden");
    setStatus("Encrypted successfully. The plaintext and key never left this browser.", "success");
  } catch (error) {
    setStatus(error.message || "Encryption failed.", "error");
  } finally {
    setBusy(button, false);
  }
});

$("decryptButton").addEventListener("click", async () => {
  const button = $("decryptButton");
  setBusy(button, true, "Decrypting…");
  setStatus("Authenticating and decrypting locally…");
  try {
    const result = await decryptMessage($("cipherInput").value, $("decryptKey").value);
    $("plainOutput").value = result;
    $("decryptResult").classList.remove("hidden");
    setStatus("Authentication passed and the message was decrypted.", "success");
  } catch (error) {
    $("decryptResult").classList.add("hidden");
    $("plainOutput").value = "";
    setStatus(error.message || "Decryption failed.", "error");
  } finally {
    setBusy(button, false);
  }
});

$("copyCipher").addEventListener("click", () => copyText($("cipherOutput").value, "Bytarith string copied."));
$("copyPlain").addEventListener("click", () => copyText($("plainOutput").value, "Decrypted message copied."));

updateByteCount();
updateKeyStrength();
