/* CRM revizní technik – mobil. Fotky a diktát do složky „CRM mobil/inbox/<id revize>/“ na OneDrivu.
   Žádné cizí knihovny: přihlášení OAuth 2.0 + PKCE (osobní Microsoft účty), Microsoft Graph přes fetch. */
"use strict";

const VERSION = "1.0.0";
const CFG = window.CRM_CONFIG || {};
const AUTH = "https://login.microsoftonline.com/consumers/oauth2/v2.0";
const GRAPH = "https://graph.microsoft.com/v1.0";
const SCOPES = "Files.ReadWrite offline_access openid profile";
const REDIRECT = location.origin + location.pathname.replace(/index\.html$/, "");
const MAX_PX = 2560;

// ---------------------------------------------------------------- úložiště
const ls = {
  get(k, d = null) { try { const v = localStorage.getItem("crm." + k); return v === null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem("crm." + k, JSON.stringify(v)); } catch { /* plné nebo zakázané */ } },
  del(k) { try { localStorage.removeItem("crm." + k); } catch { /* */ } },
};
const settings = () => ({ folder: ls.get("folder", CFG.defaultFolder || "CRM mobil"), shrink: ls.get("shrink", true) });

const $ = (id) => document.getElementById(id);
function toast(text, ms = 2600) {
  const t = $("toast"); t.textContent = text; t.hidden = false;
  clearTimeout(toast._t); toast._t = setTimeout(() => (t.hidden = true), ms);
}
function esc(s) { return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }

// ---------------------------------------------------------------- přihlášení (PKCE)
function b64url(bytes) {
  let s = ""; new Uint8Array(bytes).forEach((b) => (s += String.fromCharCode(b)));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function randomStr(n = 48) { const a = new Uint8Array(n); crypto.getRandomValues(a); return b64url(a); }
async function sha256(text) { return crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)); }

async function login(selectAccount = true) {
  if (!CFG.clientId) { $("login-noconfig").hidden = false; return; }
  const verifier = randomStr(64);
  const state = randomStr(16);
  ls.set("pkce", { verifier, state });
  const params = new URLSearchParams({
    client_id: CFG.clientId, response_type: "code", redirect_uri: REDIRECT, response_mode: "query",
    scope: SCOPES, code_challenge: b64url(await sha256(verifier)), code_challenge_method: "S256", state,
  });
  if (selectAccount) params.set("prompt", "select_account");
  const hint = ls.get("user");
  if (!selectAccount && hint) params.set("login_hint", hint);
  location.assign(`${AUTH}/authorize?${params}`);
}

async function tokenRequest(body) {
  const res = await fetch(`${AUTH}/token`, {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: CFG.clientId, scope: SCOPES, ...body }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(data.error_description || data.error || `HTTP ${res.status}`), { code: data.error });
  const tok = {
    access: data.access_token, refresh: data.refresh_token || (ls.get("tok") || {}).refresh,
    exp: Date.now() + (data.expires_in || 3600) * 1000,
  };
  ls.set("tok", tok);
  needRelogin = false; if (document.getElementById("relogin")) updateRelogin();
  if (data.id_token) {
    try {
      const p = JSON.parse(atob(data.id_token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
      ls.set("user", p.preferred_username || p.email || p.name || "");
    } catch { /* */ }
  }
  return tok;
}

async function handleRedirect() {
  const q = new URLSearchParams(location.search);
  if (!q.has("code") && !q.has("error")) return;
  history.replaceState(null, "", REDIRECT);
  if (q.has("error")) { showLoginError(q.get("error_description") || q.get("error")); return; }
  const pkce = ls.get("pkce");
  ls.del("pkce");
  if (!pkce || pkce.state !== q.get("state")) { showLoginError("Přihlášení se nepodařilo ověřit, zkus to znovu."); return; }
  try {
    await tokenRequest({ grant_type: "authorization_code", code: q.get("code"), redirect_uri: REDIRECT, code_verifier: pkce.verifier });
  } catch (e) { showLoginError("Přihlášení selhalo: " + e.message); }
}
function showLoginError(text) { const el = $("login-error"); el.textContent = text; el.hidden = false; }

let needRelogin = false;
const authError = (msg) => Object.assign(new Error(msg), { auth: true });
const netError = (msg) => Object.assign(new Error(msg), { network: true });
/** Platný přístupový token. Vyhodí {auth} jen když je opravdu potřeba nové přihlášení, při výpadku sítě {network}. */
async function getToken() {
  const tok = ls.get("tok");
  if (!tok) throw authError("Nepřihlášeno");
  if (tok.access && tok.exp - Date.now() > 120000) return tok.access;
  if (!tok.refresh) { needRelogin = true; updateRelogin(); throw authError("Přihlášení vypršelo"); }
  if (!navigator.onLine) throw netError("Bez připojení");
  try {
    return (await tokenRequest({ grant_type: "refresh_token", refresh_token: tok.refresh })).access;
  } catch (e) {
    if (e.code) { needRelogin = true; updateRelogin(); throw authError("Přihlášení vypršelo – přihlas se znovu."); }
    throw netError("Nepodařilo se spojit s Microsoftem");
  }
}
const signedIn = () => !!ls.get("tok");
function logout() { ls.del("tok"); ls.del("user"); ls.del("index"); location.assign(REDIRECT); }

// ---------------------------------------------------------------- Microsoft Graph
const encPath = (p) => p.split("/").filter(Boolean).map(encodeURIComponent).join("/");
const drivePath = (rel) => `/me/drive/root:/${encPath(settings().folder + "/" + rel)}`;

async function graph(method, path, opts = {}) {
  const send = async () => {
    const token = await getToken();
    try {
      return await fetch(GRAPH + path, { method, body: opts.body, headers: { Authorization: `Bearer ${token}`, ...(opts.headers || {}) } });
    } catch { throw netError("Nepodařilo se spojit s OneDrivem"); }
  };
  let res = await send();
  if (res.status === 401) {                       // token mohl vypršet dřív – jednou obnovit a zkusit znovu
    const tok = ls.get("tok"); if (tok) { tok.exp = 0; ls.set("tok", tok); }
    res = await send();
    if (res.status === 401) { needRelogin = true; updateRelogin(); throw authError("Přihlášení vypršelo – přihlas se znovu."); }
  }
  return res;
}

async function loadIndex() {
  const meta = await graph("GET", drivePath("index.json"));
  if (meta.status === 404) throw Object.assign(new Error("notfound"), { notFound: true });
  if (!meta.ok) throw new Error(`OneDrive vrátil chybu ${meta.status}`);
  const item = await meta.json();
  const url = item["@microsoft.graph.downloadUrl"];
  if (!url) throw new Error("OneDrive nevrátil odkaz ke stažení seznamu.");
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`Stažení seznamu selhalo (${res.status})`);
  const index = await res.json();
  ls.set("index", index);
  ls.set("indexAt", Date.now());
  return index;
}

async function inboxCount(rid) {
  const res = await graph("GET", drivePath(`inbox/${rid}`) + ":/children?$select=name&$top=500");
  if (res.status === 404) return 0;
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return ((await res.json()).value || []).filter((f) => !f.name.startsWith(".")).length;
}

async function uploadItem(item) {
  const body = item.blob || new Blob([item.text], { type: "text/plain;charset=utf-8" });
  const res = await graph("PUT", drivePath(`inbox/${item.rid}/${item.name}`) + ":/content?@microsoft.graph.conflictBehavior=rename",
    { body, headers: { "Content-Type": item.type || "application/octet-stream" } });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw Object.assign(new Error(data?.error?.message || `HTTP ${res.status}`), { status: res.status });
  }
}

// ---------------------------------------------------------------- fronta (IndexedDB) – funguje i bez signálu
let dbp = null;
function db() {
  if (!dbp) dbp = new Promise((resolve, reject) => {
    const r = indexedDB.open("crm-mobil", 1);
    r.onupgradeneeded = () => r.result.createObjectStore("queue", { keyPath: "id", autoIncrement: true });
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
  return dbp;
}
async function store(mode, fn) {
  const d = await db();
  return new Promise((resolve, reject) => {
    const tx = d.transaction("queue", mode); const st = tx.objectStore("queue");
    const req = fn(st);
    tx.oncomplete = () => resolve(req && req.result);
    tx.onerror = () => reject(tx.error);
  });
}
const qAdd = (item) => store("readwrite", (s) => s.add(item));
const qAll = () => store("readonly", (s) => s.getAll());
const qDel = (id) => store("readwrite", (s) => s.delete(id));
const qClear = () => store("readwrite", (s) => s.clear());

let flushing = false;
let lastError = "";
async function flushQueue() {
  if (flushing || !navigator.onLine || !signedIn()) { await refreshQueueChip(); return; }
  flushing = true;
  try {
    const items = (await qAll()).sort((a, b) => a.id - b.id);
    for (const item of items) {
      try {
        await uploadItem(item);
        await qDel(item.id);
        lastError = "";
        markSent(item);
      } catch (e) {
        lastError = e.message;
        break;                              // zkusíme znovu později (signál, přihlášení…)
      }
      await refreshQueueChip();
    }
  } finally {
    flushing = false;
    await refreshQueueChip();
  }
}

async function refreshQueueChip() {
  let items = [];
  try { items = await qAll(); } catch { /* */ }
  const chip = $("chip-queue");
  chip.hidden = !items.length;
  chip.textContent = `${items.length} čeká`;
  chip.title = lastError || "Čeká na odeslání";
  $("set-queue").textContent = items.length
    ? `Neodesláno: ${items.length} (${items.filter((i) => i.blob).length} fotek, ${items.filter((i) => !i.blob).length} textů).${lastError ? " Poslední chyba: " + lastError : ""}`
    : "Vše je odeslané.";
  window.__queue = items;
  if (current) renderQueuedBadges();
}

// ---------------------------------------------------------------- jména souborů (formát, který čte PC aplikace)
let seq = 0;
function stamp(d = new Date()) {
  const p = (n, l = 2) => String(n).padStart(l, "0");
  seq = (seq + 1) % 1000;
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}_${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}${p(seq, 3)}`;
}
function slug(text, fallback) {
  const s = (text || "").normalize("NFKD").replace(/[̀-ͯ]/g, "").replace(/[^A-Za-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40);
  return s || fallback;
}

// ---------------------------------------------------------------- fotky
async function shrinkPhoto(file) {
  if (!settings().shrink || !/^image\/(jpeg|png|webp)$/i.test(file.type)) return { blob: file, ext: extOf(file) };
  try {
    const bmp = await createImageBitmap(file, { imageOrientation: "from-image" });
    const scale = Math.min(1, MAX_PX / Math.max(bmp.width, bmp.height));
    if (scale === 1 && file.type === "image/jpeg") return { blob: file, ext: ".jpg" };
    const c = document.createElement("canvas");
    c.width = Math.round(bmp.width * scale); c.height = Math.round(bmp.height * scale);
    c.getContext("2d").drawImage(bmp, 0, 0, c.width, c.height);
    const blob = await new Promise((r) => c.toBlob(r, "image/jpeg", 0.85));
    return blob ? { blob, ext: ".jpg" } : { blob: file, ext: extOf(file) };
  } catch { return { blob: file, ext: extOf(file) }; }
}
function extOf(file) {
  const m = /\.[a-z0-9]{2,5}$/i.exec(file.name || ""); if (m) return m[0].toLowerCase();
  return ({ "image/png": ".png", "image/webp": ".webp", "image/heic": ".heic" })[file.type] || ".jpg";
}

const thumbs = new Map();    // jméno souboru → {url, sent}
async function addPhotos(files) {
  if (!current || !files.length) return;
  const label = $("photo-label").value.trim();
  for (const file of files) {
    const { blob, ext } = await shrinkPhoto(file);
    const name = `foto_${slug(label, "mobil")}_${stamp()}${ext}`;
    await qAdd({ rid: current.id, name, blob, type: blob.type || "image/jpeg", created: Date.now() });
    thumbs.set(name, { url: URL.createObjectURL(blob), sent: false, rid: current.id });
  }
  renderThumbs();
  toast(files.length === 1 ? "Fotka je ve frontě k odeslání" : `${files.length} fotek ve frontě k odeslání`);
  flushQueue();
}
function markSent(item) {
  const t = thumbs.get(item.name); if (t) t.sent = true;
  if (!item.blob) {
    const sent = ls.get("sentTexts", []);
    sent.unshift({ rid: item.rid, section: item.section, at: Date.now() });
    ls.set("sentTexts", sent.slice(0, 50));
  }
  if (current && item.rid === current.id) { renderThumbs(); renderSentTexts(); refreshInbox(); }
}
function renderThumbs() {
  const box = $("thumbs"); box.innerHTML = "";
  for (const [, t] of [...thumbs].reverse()) {
    if (!current || t.rid !== current.id) continue;
    const d = document.createElement("div"); d.className = "thumb";
    d.innerHTML = `<img alt="" src="${t.url}"><span class="st ${t.sent ? "ok" : ""}">${t.sent ? "✓ na OneDrivu" : "čeká"}</span>`;
    box.appendChild(d);
  }
}

// ---------------------------------------------------------------- diktát (Web Speech API, čeština)
const Rec = window.SpeechRecognition || window.webkitSpeechRecognition;
let rec = null, listening = false;
const COMMANDS = [
  [/\s*\bnov(?:ý|á) odstav(?:ec|ce)\b\s*/gi, "\n\n"],
  [/\s*\bnov(?:ý|á) řád(?:ek|ka)\b\s*/gi, "\n"],
  [/\s*\btečka\b/gi, "."], [/\s*\bčárka\b/gi, ","], [/\s*\botazník\b/gi, "?"],
  [/\s*\bdvojtečka\b/gi, ":"], [/\s*\bvykřičník\b/gi, "!"],
];
function applyCommands(t) { for (const [re, rep] of COMMANDS) t = t.replace(re, rep); return t; }

function insertAtCursor(text) {
  const ta = $("dictation");
  const start = ta.selectionStart ?? ta.value.length, end = ta.selectionEnd ?? ta.value.length;
  const before = ta.value.slice(0, start);
  let piece = applyCommands(text.trim());
  if (!piece) return;
  const sentenceEnd = !before.trim() || /[.!?:\n]\s*$/.test(before);
  if (sentenceEnd && /^[a-zà-ž]/i.test(piece)) piece = piece[0].toLocaleUpperCase("cs") + piece.slice(1);
  if (before && !/\s$/.test(before) && !/^[.,!?:\n]/.test(piece)) piece = " " + piece;
  ta.value = before + piece + ta.value.slice(end);
  const pos = (before + piece).length; ta.setSelectionRange(pos, pos);
  saveDraft();
}

function toggleMic() {
  if (!Rec) { toast("Tento prohlížeč neumí diktát – použij mikrofon na klávesnici.", 4000); return; }
  if (listening) { stopMic(); return; }
  rec = new Rec(); rec.lang = "cs-CZ"; rec.continuous = true; rec.interimResults = true;
  rec.onresult = (ev) => {
    let interim = "";
    for (let i = ev.resultIndex; i < ev.results.length; i++) {
      const r = ev.results[i];
      if (r.isFinal) insertAtCursor(r[0].transcript); else interim += r[0].transcript;
    }
    $("interim").textContent = interim;
  };
  rec.onerror = (ev) => {
    if (ev.error === "not-allowed" || ev.error === "service-not-allowed") {
      toast("Aplikace nemá povolený mikrofon – povol ho v nastavení telefonu.", 5000); stopMic();
    } else if (ev.error === "network") { toast("Diktát potřebuje připojení k internetu.", 4000); stopMic(); }
  };
  rec.onend = () => { if (listening) { try { rec.start(); } catch { stopMic(); } } };   // Android končí po chvíli ticha
  listening = true;
  try { rec.start(); } catch { listening = false; return; }
  const b = $("btn-mic"); b.classList.add("rec"); b.innerHTML = '<span class="recdot"></span> Poslouchám – zastavit';
}
function stopMic() {
  listening = false;
  try { rec && rec.stop(); } catch { /* */ }
  $("interim").textContent = "";
  const b = $("btn-mic"); b.classList.remove("rec"); b.textContent = "🎤 Diktovat";
}

const draftKey = () => current ? `draft.${current.id}.${$("section").value}` : "";
function saveDraft() { if (current) ls.set(draftKey(), $("dictation").value); }
function loadDraft() { $("dictation").value = current ? ls.get(draftKey(), "") : ""; }

async function sendText() {
  const text = $("dictation").value.trim();
  const section = $("section").value;
  if (!current || !text) { toast("Není co odeslat."); return; }
  if (listening) stopMic();
  const name = `diktat_${slug(section, "text")}_${stamp()}.txt`;
  await qAdd({ rid: current.id, name, text: `Sekce: ${section}\n\n${text}\n`, section, type: "text/plain;charset=utf-8", created: Date.now() });
  $("dictation").value = ""; ls.del(draftKey());
  toast("Text je ve frontě k odeslání");
  flushQueue();
}
function renderSentTexts() {
  const box = $("sent-texts"); if (!current) return;
  const today = new Date().toDateString();
  const sent = ls.get("sentTexts", []).filter((s) => s.rid === current.id && new Date(s.at).toDateString() === today);
  box.innerHTML = sent.slice(0, 6).map((s) =>
    `<div><span class="ok">✓</span><span>${esc(s.section)} · ${new Date(s.at).toLocaleTimeString("cs", { hour: "2-digit", minute: "2-digit" })}</span></div>`).join("");
}

// ---------------------------------------------------------------- obrazovky
let current = null;
const VIEWS = ["login", "list", "rev", "settings"];
function show(view) {
  for (const v of VIEWS) $("view-" + v).hidden = v !== view;
  $("btn-back").hidden = view === "list" || view === "login";
  $("btn-settings").hidden = view === "settings" || view === "login";
  $("title").textContent = view === "rev" && current ? (current.number || "Revize") : view === "settings" ? "Nastavení" : "Revize";
  window.scrollTo(0, 0);
}

function revisions() { return (ls.get("index") || {}).revisions || []; }

function renderList() {
  const q = $("search").value.trim().toLowerCase().normalize("NFKD").replace(/[̀-ͯ]/g, "");
  const queued = new Set((window.__queue || []).map((i) => i.rid));
  const list = revisions().filter((r) => !q || [r.number, r.customer, r.location].join(" ").toLowerCase()
    .normalize("NFKD").replace(/[̀-ͯ]/g, "").includes(q));
  $("revlist").innerHTML = list.map((r) => `
    <button class="rev" data-id="${r.id}">
      <span class="top"><span class="num">${esc(r.number || "bez čísla")}</span>
        ${r.druh && r.druh !== "Elektroinstalace" ? `<span class="tag">${esc(r.druh)}</span>` : ""}
        ${queued.has(r.id) ? '<span class="tag q">čeká odeslání</span>' : ""}
        <span class="date">${r.date ? new Date(r.date).toLocaleDateString("cs") : ""}</span></span>
      <span class="cust">${esc(r.customer)}</span>
      <span class="loc">${esc(r.location)}</span>
    </button>`).join("");
  const at = ls.get("indexAt");
  const idx = ls.get("index");
  $("list-meta").textContent = idx
    ? `${list.length} z ${revisions().length} revizí · seznam z PC ${idx.generated_at ? new Date(idx.generated_at).toLocaleString("cs") : ""}${at ? " · staženo " + new Date(at).toLocaleTimeString("cs", { hour: "2-digit", minute: "2-digit" }) : ""}`
    : "";
}
function listStatus(text, kind = "warn") { const el = $("list-status"); el.hidden = !text; el.className = `notice ${kind}`; el.textContent = text || ""; }

async function refreshIndex(silent = false) {
  if (!navigator.onLine) { if (!silent) listStatus("Jsi offline – zobrazuji naposledy stažený seznam."); renderList(); return; }
  if (!silent) listStatus("Načítám seznam revizí z OneDrivu…", "ok");
  try {
    await loadIndex();
    listStatus("");
  } catch (e) {
    if (e.notFound) listStatus(`Na OneDrivu chybí „${settings().folder}/index.json“. V PC aplikaci otevři 📱 Z mobilu → ⚙, nastav složku v osobním OneDrivu a počkej na synchronizaci.`, "bad");
    else if (e.auth) { needRelogin = true; updateRelogin(); listStatus(""); }
    else listStatus("Seznam se nepodařilo načíst: " + e.message + (revisions().length ? " Zobrazuji uložený." : ""), "bad");
  }
  renderList();
}

function openRevision(id) {
  const r = revisions().find((x) => x.id === id);
  if (!r) return;
  current = r;
  ls.set("lastRev", id);
  $("rev-num").textContent = r.number || "bez čísla";
  $("rev-cust").textContent = r.customer || "";
  $("rev-meta").textContent = [r.location, r.date && new Date(r.date).toLocaleDateString("cs"), r.druh].filter(Boolean).join(" · ");
  const sel = $("section");
  const lastSection = ls.get("section." + r.druh, "");
  sel.innerHTML = (r.sections || []).map((s) => `<option${s === lastSection ? " selected" : ""}>${esc(s)}</option>`).join("");
  loadDraft();
  renderThumbs(); renderSentTexts(); refreshInbox();
  history.pushState({ view: "rev" }, "");
  show("rev");
}

async function refreshInbox() {
  if (!current) return;
  const el = $("inbox-info");
  if (!navigator.onLine) { el.textContent = "Offline – stav na OneDrivu teď nejde zjistit."; return; }
  el.textContent = "Zjišťuji stav na OneDrivu…";
  try {
    const n = await inboxCount(current.id);
    el.textContent = n ? `Na OneDrivu čeká na převzetí v PC: ${n} ${n === 1 ? "položka" : n < 5 ? "položky" : "položek"}.`
      : "Na OneDrivu nic nečeká – PC už vše převzalo (nebo zatím nic nepřišlo).";
  } catch (e) { el.textContent = e.auth ? "Je potřeba se znovu přihlásit." : "Stav na OneDrivu teď nejde zjistit: " + e.message; }
}
function renderQueuedBadges() { if (!$("view-list").hidden) renderList(); }

function updateRelogin() { $("relogin").hidden = !needRelogin; }
function updateOnline() { $("chip-offline").hidden = navigator.onLine; }

function openSettings() {
  $("set-user").textContent = ls.get("user") || "—";
  $("set-version").textContent = VERSION;
  $("set-folder").value = settings().folder;
  $("set-shrink").checked = settings().shrink;
  $("clear-confirm").hidden = true;
  refreshQueueChip();
  history.pushState({ view: "settings" }, "");
  show("settings");
}

// ---------------------------------------------------------------- start
async function start() {
  await handleRedirect();
  updateOnline();
  if (!CFG.clientId) $("login-noconfig").hidden = false;

  $("btn-login").onclick = () => login(true);
  $("btn-relogin").onclick = () => login(false);
  $("btn-settings").onclick = openSettings;
  $("btn-back").onclick = () => history.back();
  $("btn-reload").onclick = () => refreshIndex();
  $("search").oninput = renderList;
  $("revlist").onclick = (ev) => { const b = ev.target.closest(".rev"); if (b) openRevision(Number(b.dataset.id)); };
  $("in-camera").onchange = (ev) => { addPhotos([...ev.target.files]); ev.target.value = ""; };
  $("in-gallery").onchange = (ev) => { addPhotos([...ev.target.files]); ev.target.value = ""; };
  $("btn-mic").onclick = toggleMic;
  $("btn-send-text").onclick = sendText;
  $("dictation").oninput = saveDraft;
  $("section").onchange = () => { if (current) ls.set("section." + current.druh, $("section").value); loadDraft(); };
  $("btn-inbox").onclick = refreshInbox;
  $("btn-logout").onclick = logout;
  $("set-folder").onchange = () => { ls.set("folder", $("set-folder").value.trim() || CFG.defaultFolder || "CRM mobil"); ls.del("index"); };
  $("set-shrink").onchange = () => ls.set("shrink", $("set-shrink").checked);
  $("btn-flush").onclick = () => { lastError = ""; flushQueue(); };
  $("btn-clear").onclick = () => ($("clear-confirm").hidden = false);
  $("btn-clear-no").onclick = () => ($("clear-confirm").hidden = true);
  $("btn-clear-yes").onclick = async () => { await qClear(); $("clear-confirm").hidden = true; refreshQueueChip(); toast("Fronta smazána"); };

  window.addEventListener("online", () => { updateOnline(); flushQueue(); refreshIndex(true); });
  window.addEventListener("offline", updateOnline);
  window.addEventListener("popstate", (ev) => {
    if (listening) stopMic();
    if (ev.state && ev.state.view === "rev" && current) { show("rev"); return; }   // zpět z Nastavení do revize
    current = null; show(signedIn() ? "list" : "login"); renderList();
  });
  document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") flushQueue(); });
  setInterval(flushQueue, 30000);

  if (!signedIn()) { show("login"); return; }
  show("list");
  renderList();
  await refreshQueueChip();
  refreshIndex(!!revisions().length);
  flushQueue();
}

if ("serviceWorker" in navigator && location.protocol === "https:") {
  navigator.serviceWorker.register("sw.js").catch(() => { /* aplikace funguje i bez něj */ });
}
start();
