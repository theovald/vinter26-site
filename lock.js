(() => {
  const STORAGE_KEY = "vinter26-password";
  const PARALLEL = 6;

  const form = document.getElementById("lock");
  const input = document.getElementById("password");
  const error = document.getElementById("error");
  const button = form.querySelector("button");

  function fromBase64(s) {
    return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  }

  async function deriveKey(password, salt, iterations) {
    const material = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveKey"],
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
  }

  function unseal(key, sealed) {
    return crypto.subtle.decrypt(
      { name: "AES-GCM", iv: sealed.subarray(0, 12) },
      key,
      sealed.subarray(12),
    );
  }

  async function loadImages(key) {
    const byName = new Map();
    for (const img of document.querySelectorAll("img[data-enc]")) {
      const list = byName.get(img.dataset.enc) || [];
      list.push(img);
      byName.set(img.dataset.enc, list);
    }
    const queue = [...byName.entries()];
    async function worker() {
      while (queue.length) {
        const [name, imgs] = queue.shift();
        try {
          const res = await fetch(`d/${name}.bin`);
          const plain = await unseal(key, new Uint8Array(await res.arrayBuffer()));
          const url = URL.createObjectURL(new Blob([plain], { type: "image/jpeg" }));
          for (const img of imgs) img.src = url;
        } catch {}
      }
    }
    await Promise.all(Array.from({ length: PARALLEL }, worker));
  }

  async function unlock(password) {
    const res = await fetch("payload.json", { cache: "no-store" });
    const payload = await res.json();
    const key = await deriveKey(
      password,
      fromBase64(payload.salt),
      payload.iterations,
    );
    const html = new TextDecoder().decode(await unseal(key, fromBase64(payload.data)));
    try {
      sessionStorage.setItem(STORAGE_KEY, password);
    } catch {}
    document.open();
    document.write(html);
    document.close();
    loadImages(key);
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    error.hidden = true;
    button.disabled = true;
    try {
      await unlock(input.value);
    } catch {
      error.hidden = false;
      button.disabled = false;
      input.select();
    }
  });

  let saved = null;
  try {
    saved = sessionStorage.getItem(STORAGE_KEY);
  } catch {}
  if (saved) unlock(saved).catch(() => {});
})();
