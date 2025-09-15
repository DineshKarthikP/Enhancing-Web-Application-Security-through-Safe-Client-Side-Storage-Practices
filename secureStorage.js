const SecureStorage = (function () {
  const STORAGE_PREFIX = "ssw_v2::";
  const SALT_KEY = STORAGE_PREFIX + "salt";
  let cryptoKey = null;

  function buf2base64(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
  }

  function base642buf(b64) {
    const bin = atob(b64);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr.buffer;
  }

  async function deriveKeyFromPassphrase(passphrase, salt) {
    const enc = new TextEncoder();
    const passKey = await crypto.subtle.importKey(
      "raw",
      enc.encode(passphrase),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: 150000, hash: "SHA-256" },
      passKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function init({ passphrase } = {}) {
    if (!passphrase) throw new Error("Passphrase required");
    let salt;
    const savedSaltB64 = localStorage.getItem(SALT_KEY);
    if (savedSaltB64) {
      salt = new Uint8Array(base642buf(savedSaltB64));
    } else {
      salt = crypto.getRandomValues(new Uint8Array(16));
      localStorage.setItem(SALT_KEY, buf2base64(salt));
    }
    cryptoKey = await deriveKeyFromPassphrase(passphrase, salt);
    return { saltB64: buf2base64(salt) };
  }

  async function encryptRaw(plainText) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, enc.encode(plainText));
    return { cipherB64: buf2base64(cipher), ivB64: buf2base64(iv.buffer) };
  }

  async function decryptRaw(cipherB64, ivB64) {
    const cipherBuf = base642buf(cipherB64);
    const ivBuf = base642buf(ivB64);
    try {
      const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(ivBuf) }, cryptoKey, cipherBuf);
      return new TextDecoder().decode(plainBuf);
    } catch (e) {
      return null;
    }
  }

  function storageKey(key) { return STORAGE_PREFIX + key; }

  async function setItem(key, value, expirySeconds = null) {
    const payload = typeof value === "string" ? value : JSON.stringify(value);
    const { cipherB64, ivB64 } = await encryptRaw(payload);
    const meta = { cipher: cipherB64, iv: ivB64, createdAt: Date.now(), expiry: expirySeconds ? Date.now() + expirySeconds * 1000 : null };
    localStorage.setItem(storageKey(key), JSON.stringify(meta));
    return true;
  }

  async function getItem(key) {
    const raw = localStorage.getItem(storageKey(key));
    if (!raw) return null;
    try {
      const meta = JSON.parse(raw);
      if (meta.expiry && Date.now() > meta.expiry) { localStorage.removeItem(storageKey(key)); return null; }
      const plain = await decryptRaw(meta.cipher, meta.iv);
      if (plain === null) { localStorage.removeItem(storageKey(key)); return null; }
      try { return JSON.parse(plain); } catch { return plain; }
    } catch (e) {
      localStorage.removeItem(storageKey(key));
      return null;
    }
  }

  function removeItem(key) { localStorage.removeItem(storageKey(key)); }

  function clear() {
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && k.startsWith(STORAGE_PREFIX)) localStorage.removeItem(k);
    }
  }

  return { init, setItem, getItem, removeItem, clear };
})();
export default SecureStorage;
