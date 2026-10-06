"use strict";

const PREFIX = "BY1.";
const TRANSFORM_PREFIX = "BT1.";\nconst FAST_TRANSFORM_PREFIX = "BT2.";
const ITERATIONS = 600000;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const MIN_PAYLOAD_BYTES = 4 + SALT_BYTES + IV_BYTES + 16;
const KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const MAX_TRANSFORM_BYTES = 1000000;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const protocolBytes = encoder.encode("Bytarith/BY1/AES-256-GCM/PBKDF2-SHA256");
const transformMaskLabel = encoder.encode("Bytarith/BT1/mask");\nconst fastTransformMaskLabel = encoder.encode("Bytarith/BT2/mask");

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

function base64UrlToBytes(value, label) {
  const name = label || "payload";
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("The " + name + " contains invalid characters.");
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  let binary;
  try {
    binary = atob(padded);
  } catch {
    throw new Error("The " + name + " is not valid Base64URL data.");
  }
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function encodeVarint(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("Invalid transform integer.");
  const out = [];
  do {
    let byte = value & 0x7f;
    value = Math.floor(value / 128);
    if (value) byte |= 0x80;
    out.push(byte);
  } while (value);
  return new Uint8Array(out);
}

function readVarint(bytes, state) {
  let value = 0;
  let multiplier = 1;
  for (let count = 0; count < 8; count++) {
    if (state.offset >= bytes.length) throw new Error("The BT1 key is truncated.");
    const byte = bytes[state.offset++];
    value += (byte & 0x7f) * multiplier;
    if (!(byte & 0x80)) return value;
    multiplier *= 128;
  }
  throw new Error("The BT1 key contains an invalid integer.");
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

async function digest16(bytes) {
  return (await sha256(bytes)).slice(0, 2);
}

async function xorWithCoverStream(bytes, coverBytes) {
  const out = new Uint8Array(bytes.length);
  let offset = 0;
  let counter = 0;
  while (offset < bytes.length) {
    const seed = concatBytes(transformMaskLabel, coverBytes, uint32Bytes(counter++));
    const block = new Uint8Array(await crypto.subtle.digest("SHA-256", seed));
    const take = Math.min(block.length, bytes.length - offset);
    for (let i = 0; i < take; i++) out[offset + i] = bytes[offset + i] ^ block[i];
    offset += take;
  }
  return out;
}

async function streamToBytes(readable) {
  const reader = readable.getReader();
  const chunks = [];
  let length = 0;
  while (true) {
    const result = await reader.read();
    if (result.done) break;
    const chunk = new Uint8Array(result.value);
    chunks.push(chunk);
    length += chunk.length;
    if (length > MAX_TRANSFORM_BYTES * 2) throw new Error("Compressed transform data is unexpectedly large.");
  }
  const out = new Uint8Array(length);
  let offset = 0;
  chunks.forEach((chunk) => {
    out.set(chunk, offset);
    offset += chunk.length;
  });
  return out;
}

async function compressDeflate(bytes) {
  if (!("CompressionStream" in window)) return null;
  try {
    const stream = new CompressionStream("deflate");
    const writer = stream.writable.getWriter();
    await writer.write(bytes);
    await writer.close();
    return await streamToBytes(stream.readable);
  } catch {
    return null;
  }
}

async function decompressDeflate(bytes) {
  if (!("DecompressionStream" in window)) throw new Error("This browser cannot restore compressed BT1 keys.");
  const stream = new DecompressionStream("deflate");
  const writer = stream.writable.getWriter();
  await writer.write(bytes);
  await writer.close();
  return await streamToBytes(stream.readable);
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
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
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
  if (!value) label.textContent = "Use a generated key";
  else if (generatedKeyLike(value)) label.textContent = "80-bit generated key";
  else if (value.length >= 16) label.textContent = "Long custom key";
  else if (value.length >= 10) label.textContent = "Custom key";
  else if (value.length >= 6) label.textContent = "Weak custom key";
  else if (value.length >= 2) label.textContent = "Very weak · obfuscation only";
  else label.textContent = "Minimum 2 characters";
}

function updateByteCounts() {
  $("plainCount").textContent = encoder.encode($("plainInput").value).length + " bytes";
  $("transformOriginalCount").textContent = encoder.encode($("transformOriginal").value).length + " bytes";
  $("transformCoverCount").textContent = encoder.encode($("transformCover").value).length + " bytes";
}

async function encryptMessage() {
  const plaintext = $("plainInput").value;
  const secret = $("encryptKey").value;

  if (!plaintext.length) throw new Error("Enter a message to encrypt.");
  if (secret.length < 2) throw new Error("Use a key with at least 2 characters. Short keys are weak; a generated key is recommended.");
  if (!window.crypto || !crypto.subtle) throw new Error("Web Crypto is unavailable in this browser.");

  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const iterationBytes = uint32Bytes(ITERATIONS);
  const key = await deriveAesKey(secret, salt, ITERATIONS);
  const additionalData = concatBytes(protocolBytes, iterationBytes, salt, iv);

  const encrypted = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData, tagLength: 128 },
    key,
    encoder.encode(plaintext)
  ));

  return PREFIX + bytesToBase64Url(concatBytes(iterationBytes, salt, iv, encrypted));
}

async function decryptMessage(serialized, secret) {
  const input = serialized.trim();
  if (!input.startsWith(PREFIX)) throw new Error("This is not a BY1 Bytarith string.");
  if (secret.length < 2) throw new Error("Enter the matching Bytarith key.");

  const packed = base64UrlToBytes(input.slice(PREFIX.length), "BY1 payload");
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
      { name: "AES-GCM", iv, additionalData, tagLength: 128 },
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

function commonPrefixLength(a, b) {
  const max = Math.min(a.length, b.length);
  let i = 0;
  while (i < max && a[i] === b[i]) i++;
  return i;
}

function commonSuffixLength(a, b, prefix) {
  const max = Math.min(a.length, b.length) - prefix;
  let i = 0;
  while (i < max && a[a.length - 1 - i] === b[b.length - 1 - i]) i++;
  return i;
}

function varintLength(value) {
  let length = 1;
  while (value >= 128) {
    value = Math.floor(value / 128);
    length++;
  }
  return length;
}

function writeVarint(target, offset, value) {
  do {
    let byte = value & 0x7f;
    value = Math.floor(value / 128);
    if (value) byte |= 0x80;
    target[offset++] = byte;
  } while (value);
  return offset;
}

function buildPatchPayload(original, cover) {
  const prefix = commonPrefixLength(original, cover);
  const suffix = commonSuffixLength(original, cover, prefix);
  const middle = original.slice(prefix, original.length - suffix);
  const out = new Uint8Array(varintLength(prefix) + varintLength(suffix) + middle.length);
  let offset = writeVarint(out, 0, prefix);
  offset = writeVarint(out, offset, suffix);
  out.set(middle, offset);
  return out;
}

function restorePatchPayload(payload, cover) {
  const state = { offset: 0 };
  const prefix = readVarint(payload, state);
  const suffix = readVarint(payload, state);
  if (prefix + suffix > cover.length) throw new Error("The visible text does not match this BT1 key.");
  const middle = payload.slice(state.offset);
  return concatBytes(cover.slice(0, prefix), middle, cover.slice(cover.length - suffix));
}

function buildSparsePayload(original, cover) {
  if (original.length !== cover.length) return null;

  let changes = 0;
  let payloadBytes = 0;
  let previous = 0;

  for (let i = 0; i < original.length; i++) {
    if (original[i] === cover[i]) continue;
    changes++;
    payloadBytes += varintLength(i - previous) + 1;
    previous = i;
  }

  const out = new Uint8Array(varintLength(changes) + payloadBytes);
  let offset = writeVarint(out, 0, changes);
  previous = 0;

  for (let i = 0; i < original.length; i++) {
    if (original[i] === cover[i]) continue;
    offset = writeVarint(out, offset, i - previous);
    out[offset++] = original[i];
    previous = i;
  }

  return out;
}

function restoreSparsePayload(payload, cover) {
  const state = { offset: 0 };
  const count = readVarint(payload, state);
  const out = cover.slice();
  let position = 0;
  for (let i = 0; i < count; i++) {
    position += readVarint(payload, state);
    if (position >= out.length || state.offset >= payload.length) throw new Error("The BT1 sparse recipe is damaged.");
    out[position] = payload[state.offset++];
  }
  if (state.offset !== payload.length) throw new Error("The BT1 sparse recipe contains extra data.");
  return out;
}

async function makeTransformCandidate(codec, method, payload, coverBytes, coverHash, originalHash) {
  const masked = await xorWithCoverStream(payload, coverBytes);
  const binary = concatBytes(new Uint8Array([codec]), coverHash, originalHash, masked);
  return { codec, method, binary, key: TRANSFORM_PREFIX + bytesToBase64Url(binary) };
}

function rotateLeft32(value, bits) {
  return ((value << bits) | (value >>> (32 - bits))) >>> 0;
}

function xorWithFastCoverStream(bytes, seedBytes) {
  const view = new DataView(seedBytes.buffer, seedBytes.byteOffset, seedBytes.byteLength);
  let a = view.getUint32(0, false) || 0x9e3779b9;
  let b = view.getUint32(4, false) || 0x243f6a88;
  let c = view.getUint32(8, false) || 0xb7e15162;
  let d = view.getUint32(12, false) || 0xdeadbeef;

  const out = new Uint8Array(bytes.length);
  let word = 0;
  let available = 0;

  for (let i = 0; i < bytes.length; i++) {
    if (!available) {
      const result = Math.imul(rotateLeft32(Math.imul(b, 5) >>> 0, 7), 9) >>> 0;
      const t = (b << 9) >>> 0;
      c ^= a;
      d ^= b;
      b ^= c;
      a ^= d;
      c ^= t;
      d = rotateLeft32(d, 11);
      word = result;
      available = 4;
    }

    out[i] = bytes[i] ^ (word & 0xff);
    word >>>= 8;
    available--;
  }

  return out;
}

async function makeFastTransformKey(codec, method, payload, coverHash, originalHash, seedBytes) {
  const masked = xorWithFastCoverStream(payload, seedBytes);
  const binary = concatBytes(new Uint8Array([codec]), coverHash, originalHash, masked);
  return { codec, method, binary, key: FAST_TRANSFORM_PREFIX + bytesToBase64Url(binary) };
}

async function createTransform(originalText, coverText) {
  const original = encoder.encode(originalText);
  const cover = encoder.encode(coverText);

  if (!original.length) throw new Error("Enter an original message.");
  if (!cover.length) throw new Error("Enter the visible text you want people to see.");
  if (original.length > MAX_TRANSFORM_BYTES || cover.length > MAX_TRANSFORM_BYTES) {
    throw new Error("Transform currently supports up to 1 MB per text field.");
  }

  const [coverDigest, originalDigest, seedBytes] = await Promise.all([
    sha256(cover),
    sha256(original),
    sha256(concatBytes(fastTransformMaskLabel, cover))
  ]);

  const coverHash = coverDigest.slice(0, 2);
  const originalHash = originalDigest.slice(0, 2);
  const patchPayload = buildPatchPayload(original, cover);
  const sparsePayload = buildSparsePayload(original, cover);

  const candidates = [
    { codec: 0, method: "Masked raw", payload: original },
    { codec: 1, method: "Prefix/suffix patch", payload: patchPayload }
  ];

  if (sparsePayload) {
    candidates.push({ codec: 2, method: "Sparse byte edits", payload: sparsePayload });
  }

  const [compressedOriginal, compressedPatch] = await Promise.all([
    compressDeflate(original),
    compressDeflate(patchPayload)
  ]);

  if (compressedOriginal) {
    candidates.push({ codec: 3, method: "Deflate", payload: compressedOriginal });
  }

  if (compressedPatch) {
    candidates.push({ codec: 4, method: "Compressed patch", payload: compressedPatch });
  }

  candidates.sort((a, b) => a.payload.length - b.payload.length || a.codec - b.codec);
  const best = candidates[0];
  const built = await makeFastTransformKey(
    best.codec,
    best.method,
    best.payload,
    coverHash,
    originalHash,
    seedBytes
  );

  return {
    key: built.key,
    method: built.method,
    originalBytes: original.length,
    keyChars: built.key.length
  };
}

async function restoreTransform(coverText, serialized) {
  const input = serialized.trim();
  const legacy = input.startsWith(TRANSFORM_PREFIX);
  const fast = input.startsWith(FAST_TRANSFORM_PREFIX);

  if (!legacy && !fast) throw new Error("This is not a BT1 or BT2 transform key.");

  const cover = encoder.encode(coverText);
  if (!cover.length) throw new Error("Enter the exact visible text used to create the transform.");

  const prefix = fast ? FAST_TRANSFORM_PREFIX : TRANSFORM_PREFIX;
  const binary = base64UrlToBytes(input.slice(prefix.length), fast ? "BT2 payload" : "BT1 payload");
  if (binary.length < 5) throw new Error("The transform key is incomplete.");

  const codec = binary[0];
  const expectedCoverHash = binary.slice(1, 3);
  const expectedOriginalHash = binary.slice(3, 5);

  const coverDigest = await sha256(cover);
  const actualCoverHash = coverDigest.slice(0, 2);
  if (!bytesEqual(expectedCoverHash, actualCoverHash)) {
    throw new Error("Visible text mismatch. Transform keys are tied to the exact visible text.");
  }

  let payload;
  if (fast) {
    const seedBytes = await sha256(concatBytes(fastTransformMaskLabel, cover));
    payload = xorWithFastCoverStream(binary.slice(5), seedBytes);
  } else {
    payload = await xorWithCoverStream(binary.slice(5), cover);
  }

  let original;
  if (codec === 0) original = payload;
  else if (codec === 1) original = restorePatchPayload(payload, cover);
  else if (codec === 2) original = restoreSparsePayload(payload, cover);
  else if (codec === 3) original = await decompressDeflate(payload);
  else if (codec === 4) original = restorePatchPayload(await decompressDeflate(payload), cover);
  else throw new Error("Unsupported transform method.");

  if (original.length > MAX_TRANSFORM_BYTES) throw new Error("The restored message exceeds the transform size limit.");

  const actualOriginalHash = (await sha256(original)).slice(0, 2);
  if (!bytesEqual(expectedOriginalHash, actualOriginalHash)) {
    throw new Error("The transform key is damaged or does not match this visible text.");
  }

  try {
    return decoder.decode(original);
  } catch {
    throw new Error("The restored transform data is not valid UTF-8 text.");
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
  ["encrypt", "decrypt", "transform"].forEach((name) => {
    const active = name === mode;
    const tab = $(name + "Tab");
    const panel = $(name + "Panel");
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-selected", String(active));
    panel.hidden = !active;
    panel.classList.toggle("active", active);
  });
  setStatus("");
}

function switchTransformAction(action) {
  const creating = action === "create";
  $("transformCreateTab").classList.toggle("active", creating);
  $("transformRestoreTab").classList.toggle("active", !creating);
  $("transformCreate").hidden = !creating;
  $("transformRestore").hidden = creating;
  setStatus("");
}

$("encryptTab").addEventListener("click", () => switchMode("encrypt"));
$("decryptTab").addEventListener("click", () => switchMode("decrypt"));
$("transformTab").addEventListener("click", () => switchMode("transform"));
$("transformCreateTab").addEventListener("click", () => switchTransformAction("create"));
$("transformRestoreTab").addEventListener("click", () => switchTransformAction("restore"));

$("plainInput").addEventListener("input", updateByteCounts);
$("transformOriginal").addEventListener("input", updateByteCounts);
$("transformCover").addEventListener("input", updateByteCounts);
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
    const weak = $("encryptKey").value.length < 10 && !generatedKeyLike($("encryptKey").value);
    setStatus(weak ? "Encrypted, but this short key is vulnerable to offline guessing." : "Encrypted successfully. The plaintext and key never left this browser.", weak ? "error" : "success");
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

$("transformButton").addEventListener("click", async () => {
  const button = $("transformButton");
  setBusy(button, true, "Optimizing…");
  setStatus("Testing reversible transform recipes and choosing the shortest key…");
  try {
    const original = $("transformOriginal").value;
    const cover = $("transformCover").value;
    const result = await createTransform(original, cover);
    $("transformKeyOutput").value = result.key;
    $("transformMethod").textContent = result.method;
    $("transformKeyChars").textContent = String(result.keyChars);
    const originalChars = Math.max(1, original.length);
    $("transformEfficiency").textContent = Math.round((result.keyChars / originalChars) * 100) + "%";
    $("transformResult").classList.remove("hidden");
    setStatus("Transform created. The visible text stays exactly as you wrote it.", "success");
  } catch (error) {
    $("transformResult").classList.add("hidden");
    setStatus(error.message || "Transform creation failed.", "error");
  } finally {
    setBusy(button, false);
  }
});

$("restoreTransformButton").addEventListener("click", async () => {
  const button = $("restoreTransformButton");
  setBusy(button, true, "Restoring…");
  setStatus("Applying the BT1 recipe to the visible text…");
  try {
    const result = await restoreTransform($("restoreCover").value, $("restoreKey").value);
    $("restoreOutput").value = result;
    $("restoreTransformResult").classList.remove("hidden");
    setStatus("Original message restored and verified.", "success");
  } catch (error) {
    $("restoreTransformResult").classList.add("hidden");
    $("restoreOutput").value = "";
    setStatus(error.message || "Transform restore failed.", "error");
  } finally {
    setBusy(button, false);
  }
});

$("copyCipher").addEventListener("click", () => copyText($("cipherOutput").value, "Bytarith string copied."));
$("copyPlain").addEventListener("click", () => copyText($("plainOutput").value, "Decrypted message copied."));
$("copyTransformKey").addEventListener("click", () => copyText($("transformKeyOutput").value, "BT1 transform key copied."));
$("copyTransformPair").addEventListener("click", () => {
  const pair = $("transformCover").value + "\n\nBT1 Key: " + $("transformKeyOutput").value;
  copyText(pair, "Visible text and BT1 key copied.");
});
$("copyRestoreOutput").addEventListener("click", () => copyText($("restoreOutput").value, "Original message copied."));

updateByteCounts();
updateKeyStrength();
