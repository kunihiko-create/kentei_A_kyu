// A級アプリの入口。アプリ本体とデータ（exam-a-data.js、パスワードで暗号化したもの）を、
// 最初に使うときだけパスワードで復号する。成功したら鍵をこのブラウザに残し、次からは聞かない。
// 暗号は PBKDF2（SHA-256）で作った鍵の AES-GCM。tools/build-a-only.js が暗号化する
(function () {
  const KEY_STORAGE = "indonesian-exam-a-key-v1";
  const enc = window.EXAM_A_ENC;
  const root = document.querySelector("#exam-app");

  function fromBase64(text) {
    const binary = atob(text);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  function toBase64(bytes) {
    let binary = "";
    bytes.forEach((byte) => {
      binary += String.fromCharCode(byte);
    });
    return btoa(binary);
  }

  function loadSavedKey() {
    try {
      return localStorage.getItem(KEY_STORAGE) || "";
    } catch (error) {
      return "";
    }
  }

  function saveKey(raw) {
    try {
      localStorage.setItem(KEY_STORAGE, toBase64(raw));
    } catch (error) {
      // 残せない環境では、毎回パスワードを聞く
    }
  }

  function forgetKey() {
    try {
      localStorage.removeItem(KEY_STORAGE);
    } catch (error) {
      // 何もしない
    }
  }

  async function keyFromPassword(password) {
    const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt: new TextEncoder().encode(enc.salt), iterations: enc.iterations },
      material,
      256
    );
    return new Uint8Array(bits);
  }

  // 鍵が違えば AES-GCM の検証で失敗する
  async function decrypt(raw) {
    const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromBase64(enc.iv) }, key, fromBase64(enc.data));
    return JSON.parse(new TextDecoder().decode(plain));
  }

  // もとの index.html と同じ順に、ファイルごとに script として実行する
  function start(files) {
    root.innerHTML = "";
    files.forEach(([name, code]) => {
      const script = document.createElement("script");
      script.textContent = `${code}\n//# sourceURL=${name}`;
      document.body.appendChild(script);
    });
  }

  function renderForm(message) {
    root.innerHTML = `
      <form class="exam-panel exam-gate">
        <h2>パスワード</h2>
        <p class="exam-muted">最初に使うときだけ、パスワードを入れてください。次からはこのブラウザでは聞きません。</p>
        <input class="exam-search-input" type="password" autocomplete="current-password" aria-label="パスワード" required />
        <p class="exam-gate-message" role="alert">${message || ""}</p>
        <button class="exam-button primary" type="submit">開く</button>
      </form>
    `;
    const form = root.querySelector("form");
    const input = form.querySelector("input");
    const button = form.querySelector("button");
    input.focus();
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      button.disabled = true;
      button.textContent = "確認しています…";
      try {
        const raw = await keyFromPassword(input.value);
        const files = await decrypt(raw);
        saveKey(raw);
        start(files);
      } catch (error) {
        renderForm("パスワードが違います。");
      }
    });
  }

  function renderUnsupported() {
    root.innerHTML = '<p class="exam-panel">このブラウザでは開けません。Safari・Chrome・Edge・Firefox の新しい版で開いてください。</p>';
  }

  async function init() {
    if (!enc || !window.crypto || !crypto.subtle) {
      renderUnsupported();
      return;
    }
    const saved = loadSavedKey();
    if (saved) {
      try {
        start(await decrypt(fromBase64(saved)));
        return;
      } catch (error) {
        // パスワードが変わった時など。もう一度聞く
        forgetKey();
      }
    }
    renderForm("");
  }

  init();
})();
