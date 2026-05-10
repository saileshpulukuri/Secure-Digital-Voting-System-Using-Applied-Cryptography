/* global forge */

const LS = {
  voterTok: "sv_voter_token",
  voterId: "sv_voter_id",
  voterKey: "sv_voter_priv_pem",
  adminTok: "sv_admin_token",
  adminUser: "sv_admin_username",
};

const $ = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];

/** Server returns otp_required: true (JSON boolean) after password check until the 6-digit code is submitted. */
function responseRequestedOtp(d) {
  return Boolean(d && d.otp_required === true);
}

function toast(msg, err = false) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.toggle("err", err);
  t.classList.remove("hidden");
  clearTimeout(t._h);
  t._h = setTimeout(() => t.classList.add("hidden"), 4200);
}

function localToIsoZ(val) {
  const d = new Date(val);
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

async function api(path, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (opts.json !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  const voter = localStorage.getItem(LS.voterTok);
  const admin = localStorage.getItem(LS.adminTok);
  if (opts.role === "admin" && admin) headers.Authorization = `Bearer ${admin}`;
  else if (opts.role === "voter" && voter) headers.Authorization = `Bearer ${voter}`;
  else if (opts.auth === "voter" && voter) headers.Authorization = `Bearer ${voter}`;
  else if (opts.auth === "admin" && admin) headers.Authorization = `Bearer ${admin}`;
  else if (voter && opts.auth !== "none" && opts.role !== "admin") headers.Authorization = `Bearer ${voter}`;

  const init = {
    method: opts.method || "GET",
    headers,
  };
  if (opts.json !== undefined) init.body = JSON.stringify(opts.json);
  else if (opts.body !== undefined) init.body = opts.body;

  const r = await fetch(path, init);
  const text = await r.text();
  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { detail: text || r.statusText };
  }
  if (!r.ok) {
    const msg = data.detail || (typeof data === "string" ? data : JSON.stringify(data));
    const msgStr = typeof msg === "string" ? msg : JSON.stringify(msg);
    const voterAuthSent =
      voter &&
      (opts.auth === "voter" || opts.role === "voter" || (opts.auth !== "none" && opts.auth !== "admin"));
    const clearVoterClientState = () => {
      localStorage.removeItem(LS.voterTok);
      localStorage.removeItem(LS.voterId);
      localStorage.removeItem(LS.voterKey);
      pendingVoterPasswordAfterRegister = null;
      resetVoterOtpUi();
      updateNav();
      showView("login");
    };
    if (r.status === 401 && voterAuthSent) {
      clearVoterClientState();
    }
    if (r.status === 403 && voterAuthSent) {
      const allowlist403 =
        msgStr.includes("college authorized database") ||
        msgStr.includes("approved college roster") ||
        msgStr.includes("authorized college roster") ||
        msgStr.includes("not authorized for this SecureVote deployment") ||
        msgStr.includes("authorized student list");
      if (allowlist403) {
        clearVoterClientState();
      }
    }
    throw new Error(msgStr);
  }
  return data;
}

function encryptAndSignVote(contestantId, electionPubPem, voterPrivPem) {
  const plain = JSON.stringify({ contestant_id: contestantId });
  const pk = forge.pki.publicKeyFromPem(electionPubPem);
  const bytes = forge.util.encodeUtf8(plain);
  const encrypted = pk.encrypt(bytes, "RSA-OAEP", {
    md: forge.md.sha256.create(),
    mgf1: { md: forge.md.sha256.create() },
  });
  const encryptedB64 = forge.util.encode64(encrypted);
  const ts = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const sk = forge.pki.privateKeyFromPem(voterPrivPem);
  const md = forge.md.sha256.create();
  md.update(encryptedB64 + "|" + ts, "utf8");
  // Options object (forge 1.x): legacy 3-arg form mapped md/mgf/salt wrong and broke with "r.start is not a function".
  const pss = forge.pss.create({
    md: forge.md.sha256.create(),
    mgf: forge.mgf.mgf1.create(forge.md.sha256.create()),
    saltLength: 32,
  });
  const signature = sk.sign(md, pss);
  const signatureB64 = forge.util.encode64(signature);
  return { encryptedB64, signatureB64, ts };
}

function showView(name) {
  $$(".view").forEach((v) => v.classList.add("hidden"));
  $(`#view-${name}`).classList.remove("hidden");
}

function updateNav() {
  const nav = $("#nav-auth");
  const vt = localStorage.getItem(LS.voterTok);
  const at = localStorage.getItem(LS.adminTok);
  nav.innerHTML = "";
  if (vt) {
    const b = document.createElement("button");
    b.className = "btn ghost sm";
    b.textContent = "Voter dashboard";
    b.onclick = () => {
      showView("voter");
      loadVoterDashboard();
    };
    nav.appendChild(b);
  }
  if (at) {
    const b = document.createElement("button");
    b.className = "btn ghost sm";
    b.textContent = "Admin";
    b.onclick = () => {
      showView("admin");
      loadAdminDashboard();
    };
    nav.appendChild(b);
  }
  if (vt || at) {
    const out = document.createElement("button");
    out.className = "btn ghost sm";
    out.textContent = "Sign out";
    out.onclick = () => {
      localStorage.removeItem(LS.voterTok);
      localStorage.removeItem(LS.adminTok);
      localStorage.removeItem(LS.adminUser);
      localStorage.removeItem(LS.voterId);
      localStorage.removeItem(LS.voterKey);
      pendingVoterPasswordAfterRegister = null;
      resetVoterOtpUi();
      updateNav();
      showView("login");
      toast("Signed out");
    };
    nav.appendChild(out);
  }
}

/* ---- Login / register ---- */
async function refreshAdminSetupUi() {
  const banner = $("#admin-first-run-banner");
  const hint = $("#admin-login-hint");
  if (!banner || !hint) return;
  try {
    const st = await api("/api/admin/setup-status", { auth: "none" });
    if (st.needs_first_admin) {
      banner.classList.remove("hidden");
      hint.textContent = "";
    } else {
      banner.classList.add("hidden");
      hint.textContent =
        "If the server was started with a .env file, try username admin (or your ADMIN_USERNAME) and the password set as ADMIN_PASSWORD.";
      const u = $("#form-admin-login")?.username;
      if (u && !u.value) u.value = "admin";
    }
  } catch {
    hint.textContent = "";
  }
}

$$(".tab").forEach((t) => {
  t.addEventListener("click", () => {
    $$(".tab").forEach((x) => x.classList.remove("active"));
    t.classList.add("active");
    const tab = t.dataset.tab;
    $$(".form-panel").forEach((p) => p.classList.remove("active"));
    $(`#form-${tab === "voter" ? "voter-login" : "admin-login"}`).classList.add("active");
    if (tab === "admin") refreshAdminSetupUi();
  });
});

$("#link-register").onclick = () => {
  resetVoterOtpUi();
  showView("register");
};
$("#link-back-login").onclick = () => {
  pendingVoterPasswordAfterRegister = null;
  resetVoterOtpUi();
  showView("login");
  refreshAdminSetupUi();
};

$("#btn-go-admin-setup")?.addEventListener("click", () => showView("admin-setup"));
$("#link-admin-setup-back")?.addEventListener("click", () => {
  showView("login");
  refreshAdminSetupUi();
});

let voterOtpPending = false;
/** Cleared after voter JWT login succeeds or on sign-out / leaving register. */
let pendingVoterPasswordAfterRegister = null;

function resetVoterOtpUi() {
  voterOtpPending = false;
  $("#otp-field-wrap")?.classList.add("hidden");
  $("#otp-hint")?.classList.add("hidden");
  const otpInput = $("#form-voter-login")?.querySelector("input[name=otp]");
  if (otpInput) {
    otpInput.value = "";
    otpInput.disabled = true;
  }
}

$("#form-admin-first")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  if ($("#view-admin-setup")?.classList.contains("hidden")) {
    return;
  }
  const fd = new FormData(e.target);
  try {
    await api("/api/admin/register-first", {
      method: "POST",
      auth: "none",
      json: { username: fd.get("username"), password: fd.get("password") },
    });
    toast("Administrator created — sign in below");
    e.target.reset();
    showView("login");
    $$(".tab").forEach((x) => x.classList.toggle("active", x.dataset.tab === "admin"));
    $$(".form-panel").forEach((p) => p.classList.remove("active"));
    $("#form-admin-login")?.classList.add("active");
    refreshAdminSetupUi();
  } catch (err) {
    toast(err.message, true);
  }
});

async function restoreSigningKeyFromPassword(password) {
  const data = await api("/api/voter/restore-signing-key", {
    method: "POST",
    role: "voter",
    json: { password },
  });
  localStorage.setItem(LS.voterKey, data.voter_private_key_pem);
  updateVoterKeyBanner();
}

function updateVoterKeyBanner(scrollTo = false) {
  const banner = $("#voter-key-banner");
  if (!banner) return;
  const hasTok = localStorage.getItem(LS.voterTok);
  const hasKey = localStorage.getItem(LS.voterKey);
  if (hasTok && !hasKey) {
    banner.classList.remove("hidden");
    if (scrollTo) banner.scrollIntoView({ behavior: "smooth", block: "nearest" });
  } else {
    banner.classList.add("hidden");
  }
}

$("#form-voter-login").onsubmit = async (e) => {
  e.preventDefault();
  if ($("#view-login")?.classList.contains("hidden")) {
    return;
  }
  const fd = new FormData(e.target);
  const vid = String(fd.get("voter_id") || "").trim().toLowerCase();
  const password = fd.get("password");
  /* Hidden inputs still submit: ignore OTP unless the OTP row is visible (step 2). */
  const otpWrap = $("#otp-field-wrap");
  const otpStepActive = otpWrap && !otpWrap.classList.contains("hidden");
  const otp = otpStepActive ? String(fd.get("otp") || "").trim() : "";
  try {
    const prevId = String(localStorage.getItem(LS.voterId) || "").trim();
    if (prevId !== vid) {
      localStorage.removeItem(LS.voterKey);
    }
    const data = await api("/api/login", {
      method: "POST",
      json: { voter_id: vid, password, ...(otp ? { otp } : {}) },
      auth: "none",
    });
    if (responseRequestedOtp(data)) {
      voterOtpPending = true;
      const otpIn = $("#form-voter-login")?.querySelector("input[name=otp]");
      if (otpIn) otpIn.disabled = false;
      $("#otp-field-wrap")?.classList.remove("hidden");
      const hint = $("#otp-hint");
      if (hint) {
        hint.classList.remove("hidden");
        hint.textContent = data.dev_otp
          ? `OTP sent (demo mode): ${data.dev_otp}. Enter it below, then click Sign in.`
          : "Enter the 6-digit OTP from your email, then click Sign in.";
      }
      toast(data.message || "Enter the one-time code below, then click Sign in.");
      return;
    }
    if (!data.access_token) {
      toast("Unexpected sign-in response. Try again.", true);
      return;
    }
    localStorage.setItem(LS.voterTok, data.access_token);
    localStorage.setItem(LS.voterId, vid);
    pendingVoterPasswordAfterRegister = null;
    let restoreErr = null;
    if (!localStorage.getItem(LS.voterKey)) {
      try {
        await restoreSigningKeyFromPassword(password);
      } catch (err) {
        restoreErr = err;
      }
    }
    updateNav();
    showView("voter");
    loadVoterDashboard();
    if (restoreErr) {
      toast(restoreErr.message, true);
    } else {
      toast("Welcome back");
    }
    resetVoterOtpUi();
  } catch (err) {
    toast(err.message, true);
  }
};

$("#form-restore-key")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  try {
    await restoreSigningKeyFromPassword(fd.get("password"));
    e.target.reset();
    toast("Signing key saved in this browser");
    loadDiscover();
  } catch (err) {
    toast(err.message, true);
  }
});

$("#form-admin-login").onsubmit = async (e) => {
  e.preventDefault();
  if ($("#view-login")?.classList.contains("hidden")) {
    return;
  }
  const fd = new FormData(e.target);
  const username = String(fd.get("username") || "").trim();
  try {
    const data = await api("/api/admin/login", {
      method: "POST",
      json: { username, password: fd.get("password") },
      auth: "none",
    });
    localStorage.setItem(LS.adminTok, data.access_token);
    localStorage.setItem(LS.adminUser, username);
    updateNav();
    showView("admin");
    loadAdminDashboard();
    toast("Signed in as administrator");
  } catch (err) {
    toast(err.message, true);
  }
};

$("#form-register").onsubmit = async (e) => {
  e.preventDefault();
  if ($("#view-register")?.classList.contains("hidden")) {
    return;
  }
  const fd = new FormData(e.target);
  const voterId = String(fd.get("voter_id") || "").trim().toLowerCase();
  const password = fd.get("password");
  try {
    /* Allowlist is enforced on POST /api/register only (no separate precheck call — avoids 404 if server is older). */
    const data = await api("/api/register", {
      method: "POST",
      json: { voter_id: voterId, password },
      auth: "none",
    });
    localStorage.setItem(LS.voterKey, data.voter_private_key_pem);
    localStorage.setItem(LS.voterId, String(data.voter_id || "").trim());
    pendingVoterPasswordAfterRegister = String(password);
    toast("Account created. A one-time code was sent — enter it on the next step.");
    const step1 = await api("/api/login", {
      method: "POST",
      json: { voter_id: voterId, password },
      auth: "none",
    });
    if (responseRequestedOtp(step1)) {
      voterOtpPending = true;
      resetVoterOtpUi();
      $$(".tab").forEach((x) => x.classList.toggle("active", x.dataset.tab === "voter"));
      $$(".form-panel").forEach((p) => p.classList.remove("active"));
      $("#form-voter-login")?.classList.add("active");
      showView("login");
      const form = $("#form-voter-login");
      if (form) {
        const vi = form.querySelector("input[name=voter_id]");
        const pw = form.querySelector("input[name=password]");
        const ot = form.querySelector("input[name=otp]");
        if (vi) vi.value = voterId;
        if (pw) pw.value = pendingVoterPasswordAfterRegister || "";
        if (ot) {
          ot.value = "";
          ot.disabled = false;
        }
      }
      $("#otp-field-wrap")?.classList.remove("hidden");
      const hint = $("#otp-hint");
      if (hint) {
        hint.classList.remove("hidden");
        hint.textContent = step1.dev_otp
          ? `OTP sent (demo mode): ${step1.dev_otp}. Type it in the box below, then click Sign in.`
          : "Enter the 6-digit OTP from your email, then click Sign in.";
      }
      toast(step1.message || "Step 2: enter the one-time code, then click Sign in.");
      return;
    }
    pendingVoterPasswordAfterRegister = null;
    $$(".tab").forEach((x) => x.classList.toggle("active", x.dataset.tab === "voter"));
    $$(".form-panel").forEach((p) => p.classList.remove("active"));
    $("#form-voter-login")?.classList.add("active");
    showView("login");
    const form2 = $("#form-voter-login");
    if (form2) {
      const vi2 = form2.querySelector("input[name=voter_id]");
      if (vi2) vi2.value = voterId;
    }
    toast(
      "Account was created but the one-time code step did not complete. Use Sign in with the same email and password — you will receive a new code (email or, in demo mode, server log).",
      true,
    );
  } catch (err) {
    pendingVoterPasswordAfterRegister = null;
    const msg = String(err.message || "");
    if (msg.includes("already registered") || msg.includes("Voter already exists")) {
      resetVoterOtpUi();
      $$(".tab").forEach((x) => x.classList.toggle("active", x.dataset.tab === "voter"));
      $$(".form-panel").forEach((p) => p.classList.remove("active"));
      $("#form-voter-login")?.classList.add("active");
      showView("login");
      const form = $("#form-voter-login");
      if (form) {
        const vi = form.querySelector("input[name=voter_id]");
        const pw = form.querySelector("input[name=password]");
        if (vi) vi.value = voterId;
        if (pw) {
          pw.value = "";
          pw.focus();
        }
      }
      toast(
        "This email already has an account in the database (e.g. from a past sign-up or test). Use Sign in, enter the same email and the password you set, then click Sign in again for the one-time code.",
        false,
      );
      return;
    }
    toast(msg, true);
  }
};

/* ---- Voter dashboard ---- */
function vTab(name) {
  $$(".subtab[data-vtab]").forEach((b) => b.classList.toggle("active", b.dataset.vtab === name));
  $("#v-panel-discover").classList.toggle("hidden", name !== "discover");
  $("#v-panel-ballots").classList.toggle("hidden", name !== "ballots");
  $("#v-panel-results").classList.toggle("hidden", name !== "results");
}

$$(".subtab[data-vtab]").forEach((b) => {
  b.onclick = () => {
    vTab(b.dataset.vtab);
    if (b.dataset.vtab === "discover") loadDiscover();
    if (b.dataset.vtab === "ballots") loadBallots();
    if (b.dataset.vtab === "results") loadResults();
  };
});

async function loadVoterDashboard() {
  const id = localStorage.getItem(LS.voterId);
  $("#voter-welcome").textContent = id ? `Signed in as ${id}` : "";
  updateVoterKeyBanner();
  vTab("discover");
  await loadDiscover();
}

async function loadDiscover() {
  const el = $("#v-panel-discover");
  el.innerHTML = "<p class='muted'>Loading…</p>";
  try {
    const { elections } = await api("/api/elections", { auth: "voter" });
    if (!elections.length) {
      el.innerHTML = "<p class='muted'>No elections yet. Check back later.</p>";
      return;
    }
    el.innerHTML = '<div class="grid-elections"></div>';
    const grid = el.querySelector(".grid-elections");
    elections.forEach((e) => {
      grid.appendChild(electionCard(e, "discover"));
    });
  } catch (err) {
    el.innerHTML = `<p class="muted">${err.message}</p>`;
  }
}

function electionCard(e, mode) {
  const card = document.createElement("article");
  card.className = "election-card";
  const reg = e.my_registration_status;
  const voted = e.my_voted;
  let statusPill = "<span class='pill'>not registered</span>";
  if (reg === "pending") statusPill = "<span class='pill warn'>approval pending</span>";
  if (reg === "rejected") statusPill = "<span class='pill'>rejected</span>";
  if (reg === "approved" && !voted) statusPill = "<span class='pill ok'>approved — vote</span>";
  if (voted) statusPill = "<span class='pill ok'>voted</span>";

  const canExpand =
    mode === "discover" && reg === "approved" && !voted && !e.closed && e.contestant_count > 0;
  const noCandidates =
    mode === "discover" && reg === "approved" && !voted && !e.closed && e.contestant_count === 0;

  const head = document.createElement("div");
  head.className = `meta election-card-head${canExpand ? " is-clickable" : ""}`;
  head.innerHTML = `
    <span class="tag">${escapeHtml(e.category)}</span>
    <h3>${escapeHtml(e.title)}</h3>
    <div>${statusPill}</div>
    <p class="muted fineprint election-card-dates" style="margin:0;font-size:0.8rem">${e.contestant_count} candidates · ${fmtDate(e.starts_at)} → ${fmtDate(e.ends_at)}</p>
    ${canExpand ? '<span class="election-card-chevron" aria-hidden="true">▼</span>' : ""}`;

  const expand = document.createElement("div");
  expand.className = "election-card-expand hidden";
  expand.dataset.loaded = "0";

  const actions = document.createElement("div");
  actions.className = "actions";

  if (canExpand) {
    head.setAttribute("role", "button");
    head.setAttribute("tabindex", "0");
    head.setAttribute("aria-expanded", "false");
    const toggle = () => toggleElectionExpand(card, e.id, expand, head);
    head.addEventListener("click", toggle);
    head.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter" || ev.key === " ") {
        ev.preventDefault();
        toggle();
      }
    });
    const hint = document.createElement("p");
    hint.className = "muted fineprint";
    hint.textContent = "Tap the card to see candidates and cast your encrypted vote.";
    actions.appendChild(hint);
  }

  if (noCandidates) {
    const p = document.createElement("p");
    p.className = "muted fineprint";
    p.textContent =
      "No candidates in this election yet — an administrator must add them before you can vote.";
    actions.appendChild(p);
  }

  if (mode === "discover" && !reg && !e.closed) {
    const b = document.createElement("button");
    b.className = "btn primary sm";
    b.textContent = "Request access";
    b.onclick = (ev) => {
      ev.stopPropagation();
      registerElection(e.id);
    };
    actions.appendChild(b);
  }
  if (e.closed && !e.results_announced) {
    const p = document.createElement("span");
    p.className = "muted fineprint";
    p.textContent = "Election closed — results pending";
    actions.appendChild(p);
  }

  card.appendChild(head);
  card.appendChild(expand);
  card.appendChild(actions);
  return card;
}

async function toggleElectionExpand(card, electionId, expandEl, headEl) {
  const opening = !card.classList.contains("expanded");
  card.classList.toggle("expanded", opening);
  headEl.setAttribute("aria-expanded", opening ? "true" : "false");
  expandEl.classList.toggle("hidden", !opening);
  const ch = headEl.querySelector(".election-card-chevron");
  if (ch) ch.textContent = opening ? "▲" : "▼";

  if (!opening) return;

  if (expandEl.dataset.loaded === "1") return;

  expandEl.innerHTML = "<p class='muted'>Loading candidates…</p>";
  try {
    const detail = await api(`/api/elections/${electionId}/detail`, { auth: "voter" });
    if (!detail.public_key_pem) {
      expandEl.innerHTML = "<p class='muted'>Could not load election public key.</p>";
      return;
    }
    expandEl.innerHTML = "";
    if (!detail.contestants.length) {
      expandEl.innerHTML = "<p class='muted'>No candidates listed for this election.</p>";
      expandEl.dataset.loaded = "1";
      return;
    }
    const grid = document.createElement("div");
    grid.className = "contestant-grid";
    for (const c of detail.contestants) {
      grid.appendChild(contestantTile(c, electionId, detail));
    }
    expandEl.appendChild(grid);
    expandEl.dataset.loaded = "1";
  } catch (err) {
    expandEl.innerHTML = `<p class="muted">${escapeHtml(err.message)}</p>`;
  }
}

function contestantTile(c, electionId, detail) {
  const tile = document.createElement("div");
  tile.className = "contestant-tile";
  const img = document.createElement("img");
  img.src = c.image_url;
  img.alt = "";
  const info = document.createElement("div");
  info.className = "contestant-tile-info";
  const nm = document.createElement("strong");
  nm.textContent = c.name;
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn primary sm";
  btn.textContent = "Vote";
  btn.onclick = (ev) => {
    ev.stopPropagation();
    submitEncryptedVote(electionId, c.id, detail);
  };
  info.appendChild(nm);
  info.appendChild(btn);
  tile.appendChild(img);
  tile.appendChild(info);
  return tile;
}

async function submitEncryptedVote(electionId, contestantId, detail) {
  const priv = localStorage.getItem(LS.voterKey);
  if (!priv) {
    toast(
      "Missing signing key — use “Restore key” above (enter your account password). Past votes stay valid.",
      true
    );
    updateVoterKeyBanner(true);
    return;
  }
  const voterId = localStorage.getItem(LS.voterId);
  try {
    const { encryptedB64, signatureB64, ts } = encryptAndSignVote(
      contestantId,
      detail.public_key_pem,
      priv
    );
    await api(`/api/elections/${electionId}/vote`, {
      method: "POST",
      role: "voter",
      json: {
        voter_id: voterId,
        encrypted_vote: encryptedB64,
        signature: signatureB64,
        timestamp: ts,
      },
    });
    toast("Vote recorded");
    loadDiscover();
    loadBallots();
  } catch (err) {
    toast(err.message, true);
  }
}

function escapeHtml(s) {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

function fmtDate(iso) {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

async function registerElection(id) {
  try {
    await api(`/api/elections/${id}/register`, { method: "POST", role: "voter" });
    toast("Registration request sent");
    loadDiscover();
  } catch (err) {
    toast(err.message, true);
  }
}

async function loadBallots() {
  const el = $("#v-panel-ballots");
  el.innerHTML = "<p class='muted'>Loading…</p>";
  try {
    const { elections } = await api("/api/elections", { auth: "voter" });
    const pending = elections.filter((e) => e.my_registration_status === "pending");
    const rejected = elections.filter((e) => e.my_registration_status === "rejected");
    const todo = elections.filter((e) => e.my_registration_status === "approved" && !e.my_voted && !e.closed);
    const voted = elections.filter((e) => e.my_voted);
    el.innerHTML = "";
    const addSection = (title, list, mode) => {
      const s = document.createElement("div");
      s.className = "card";
      s.innerHTML = `<h2>${title}</h2>`;
      if (!list.length) {
        s.innerHTML += "<p class='muted'>Nothing here.</p>";
      } else {
        const g = document.createElement("div");
        g.className = "grid-elections";
        list.forEach((e) => g.appendChild(electionCard(e, mode)));
        s.appendChild(g);
      }
      el.appendChild(s);
    };
    addSection("Awaiting admin approval", pending, "discover");
    addSection("Ready to vote", todo, "discover");
    addSection("Rejected requests", rejected, "discover");
    addSection("Voted", voted, "discover");
  } catch (err) {
    el.innerHTML = `<p class="muted">${err.message}</p>`;
  }
}

async function loadResults() {
  const el = $("#v-panel-results");
  el.innerHTML = "<p class='muted'>Loading…</p>";
  try {
    const { elections } = await api("/api/elections", { auth: "voter" });
    const done = elections.filter((e) => e.results_announced);
    if (!done.length) {
      el.innerHTML = "<p class='muted'>No published results yet.</p>";
      return;
    }
    el.innerHTML = "";
    for (const e of done) {
      const res = await api(`/api/elections/${e.id}/results`, { auth: "voter" });
      const block = document.createElement("div");
      block.className = "card";
      const max = Math.max(1, ...res.contestants.map((c) => c.votes));
      block.innerHTML = `<h2>${escapeHtml(res.title)}</h2><p class="muted">${res.total_valid_votes} valid votes</p>`;
      res.contestants.forEach((c) => {
        const row = document.createElement("div");
        row.style.marginTop = "0.75rem";
        const pct = Math.round((c.votes / max) * 100);
        row.innerHTML = `<div style="display:flex;align-items:center;gap:0.75rem"><img src="${c.image_url}" alt="" style="width:40px;height:40px;border-radius:8px;object-fit:cover"/><div style="flex:1"><strong>${escapeHtml(c.name)}</strong> — ${c.votes} votes<div class="results-bar"><span style="width:${pct}%"></span></div></div></div>`;
        block.appendChild(row);
      });
      el.appendChild(block);
    }
  } catch (err) {
    el.innerHTML = `<p class="muted">${err.message}</p>`;
  }
}

/* ---- Admin ---- */
function aTab(name) {
  $$(".subtab[data-atab]").forEach((b) => b.classList.toggle("active", b.dataset.atab === name));
  $("#a-panel-overview").classList.toggle("hidden", name !== "overview");
  $("#a-panel-create").classList.toggle("hidden", name !== "create");
  $("#a-panel-approvals").classList.toggle("hidden", name !== "approvals");
  $("#a-panel-manage").classList.toggle("hidden", name !== "manage");
}

$$(".subtab[data-atab]").forEach((b) => {
  b.onclick = () => {
    aTab(b.dataset.atab);
    if (b.dataset.atab === "approvals") loadApprovals();
    if (b.dataset.atab === "manage") loadManage();
    if (b.dataset.atab === "overview") loadAdminSummary();
  };
});

$("#qa-approvals")?.addEventListener("click", () => {
  aTab("approvals");
  loadApprovals();
});
$("#qa-create")?.addEventListener("click", () => {
  aTab("create");
  initAdminDefaults();
});
$("#qa-manage")?.addEventListener("click", () => {
  aTab("manage");
  loadManage();
});

function addContestantRow() {
  const tpl = $("#tpl-contestant-row");
  const node = tpl.content.cloneNode(true);
  const row = node.querySelector(".contestant-row");
  row.querySelector(".rm-row").onclick = () => {
    row.remove();
  };
  $("#contestant-rows").appendChild(row);
}

$("#btn-add-contestant").onclick = () => addContestantRow();

$("#form-create-election").onsubmit = async (e) => {
  e.preventDefault();
  const form = e.target;
  const rows = $$(".contestant-row", form);
  const names = [];
  const files = [];
  for (const r of rows) {
    const n = r.querySelector(".c-name").value.trim();
    const f = r.querySelector(".c-photo").files[0];
    if (!n || !f) {
      toast("Each contestant needs name + photo", true);
      return;
    }
    names.push(n);
    files.push(f);
  }
  const fd = new FormData();
  fd.append("title", form.title.value.trim());
  fd.append("category", form.category.value);
  fd.append("starts_at", localToIsoZ(form.starts_at.value));
  fd.append("ends_at", localToIsoZ(form.ends_at.value));
  fd.append("contestant_names", JSON.stringify(names));
  files.forEach((file) => fd.append("photos", file));

  try {
    await fetch("/api/admin/elections", {
      method: "POST",
      headers: { Authorization: `Bearer ${localStorage.getItem(LS.adminTok)}` },
      body: fd,
    }).then(async (r) => {
      const t = await r.text();
      const d = t ? JSON.parse(t) : {};
      if (!r.ok) throw new Error(d.detail || t);
      return d;
    });
    toast("Election created");
    form.reset();
    $("#contestant-rows").innerHTML = "";
    addContestantRow();
    addContestantRow();
    loadAdminSummary();
  } catch (err) {
    toast(err.message, true);
  }
};

function bindAdminStatsNav() {
  const host = $("#admin-stats");
  if (!host || host.dataset.statsNavBound) return;
  host.dataset.statsNavBound = "1";
  host.addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-admin-tab]");
    if (!btn) return;
    const tab = btn.dataset.adminTab;
    if (!tab) return;
    aTab(tab);
    if (tab === "approvals") loadApprovals();
    else if (tab === "manage") loadManage();
    else if (tab === "create") initAdminDefaults();
    else if (tab === "overview") loadAdminSummary();
  });
}

async function loadAdminSummary() {
  const host = $("#admin-stats");
  const un = localStorage.getItem(LS.adminUser);
  const line = $("#admin-welcome-line");
  if (line && un) line.textContent = `Signed in as ${un}. Manage voter access, elections, and published results.`;
  if (!host) return;
  bindAdminStatsNav();
  try {
    const s = await api("/api/admin/dashboard-summary", { role: "admin" });
    host.innerHTML = `
      <button type="button" class="stat-card" data-admin-tab="approvals" aria-label="Open pending approvals"><span class="stat-val">${s.pending_approvals}</span><span class="stat-lbl">Pending approvals</span></button>
      <button type="button" class="stat-card" data-admin-tab="manage" aria-label="Open elections and results"><span class="stat-val">${s.elections_total}</span><span class="stat-lbl">Elections</span></button>
      <button type="button" class="stat-card" data-admin-tab="manage" aria-label="Open elections open for voting"><span class="stat-val">${s.elections_open}</span><span class="stat-lbl">Open for voting</span></button>
      <button type="button" class="stat-card" data-admin-tab="manage" aria-label="Open votes and election management"><span class="stat-val">${s.votes_recorded}</span><span class="stat-lbl">Votes recorded</span></button>
      <button type="button" class="stat-card" data-admin-tab="manage" aria-label="Open published results management"><span class="stat-val">${s.results_published}</span><span class="stat-lbl">Results published</span></button>`;
    const badge = $("#badge-approvals");
    if (badge) {
      badge.textContent = String(s.pending_approvals);
      badge.classList.toggle("hidden", s.pending_approvals === 0);
    }
  } catch (err) {
    host.innerHTML = `<p class="muted">${escapeHtml(err.message)}</p>`;
  }
}

async function loadAdminDashboard() {
  aTab("overview");
  await loadAdminSummary();
  initAdminDefaults();
  $("#contestant-rows").innerHTML = "";
  addContestantRow();
  addContestantRow();
}

function initAdminDefaults() {
  const start = new Date(Date.now() - 3600000);
  const end = new Date(Date.now() + 7 * 86400000);
  const f = (d) => {
    const pad = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  };
  const form = $("#form-create-election");
  if (form && form.starts_at && !form.starts_at.value) {
    form.starts_at.value = f(start);
    form.ends_at.value = f(end);
  }
}

async function loadApprovals() {
  const el = $("#a-panel-approvals");
  el.innerHTML = "<p class='muted'>Loading…</p>";
  try {
    const data = await api("/api/admin/registrations?status_filter=pending", { role: "admin" });
    if (!data.registrations.length) {
      el.innerHTML = "<p class='muted'>No pending requests.</p>";
      return;
    }
    let html =
      '<div class="table-wrap"><table><thead><tr><th>Election</th><th>Voter</th><th>Requested</th><th></th></tr></thead><tbody>';
    for (const r of data.registrations) {
      html += `<tr><td>${escapeHtml(r.election_title)}</td><td>${escapeHtml(r.voter_id)}</td><td>${fmtDate(r.created_at)}</td><td>
        <button class="btn primary sm" data-apr="${r.id}">Approve</button>
        <button class="btn ghost sm" data-rej="${r.id}">Reject</button>
      </td></tr>`;
    }
    html += "</tbody></table></div>";
    el.innerHTML = html;
    el.querySelectorAll("[data-apr]").forEach((b) => {
      b.onclick = async () => {
        try {
          await api(`/api/admin/registrations/${b.dataset.apr}/approve`, { method: "POST", role: "admin" });
          toast("Approved");
          loadApprovals();
          loadAdminSummary();
        } catch (err) {
          toast(err.message, true);
        }
      };
    });
    el.querySelectorAll("[data-rej]").forEach((b) => {
      b.onclick = async () => {
        try {
          await api(`/api/admin/registrations/${b.dataset.rej}/reject`, { method: "POST", role: "admin" });
          toast("Rejected");
          loadApprovals();
          loadAdminSummary();
        } catch (err) {
          toast(err.message, true);
        }
      };
    });
  } catch (err) {
    el.innerHTML = `<p class="muted">${err.message}</p>`;
  }
}

async function loadManage() {
  const el = $("#a-panel-manage");
  el.innerHTML = "<p class='muted'>Loading…</p>";
  try {
    const { elections } = await api("/api/admin/election-stats", { role: "admin" });
    if (!elections.length) {
      el.innerHTML = "<p class='muted'>No elections.</p>";
      return;
    }
    el.innerHTML = "";
    elections.forEach((e) => {
      const c = document.createElement("div");
      c.className = "card";
      c.innerHTML = `<h3>${escapeHtml(e.title)}</h3><p class="muted">${escapeHtml(e.category)} · <strong>${e.ballots_cast}</strong> encrypted ballot(s) cast · ${e.contestant_count} candidate(s) · closed: ${e.closed} · results published: ${e.results_announced}</p><div class="actions" style="display:flex;gap:0.5rem;flex-wrap:wrap"></div>`;
      const act = c.querySelector(".actions");
      if (!e.closed) {
        const b = document.createElement("button");
        b.className = "btn ghost sm";
        b.textContent = "Close election";
        b.onclick = async () => {
          try {
            await api(`/api/admin/elections/${e.id}/close`, { method: "POST", role: "admin" });
            toast("Closed");
            loadManage();
            loadAdminSummary();
          } catch (err) {
            toast(err.message, true);
          }
        };
        act.appendChild(b);
      }
      if (e.closed && !e.results_announced) {
        const b = document.createElement("button");
        b.className = "btn primary sm";
        b.textContent = "Publish results";
        b.onclick = async () => {
          try {
            await api(`/api/admin/elections/${e.id}/publish-results`, { method: "POST", role: "admin" });
            toast("Results published");
            loadManage();
            loadAdminSummary();
          } catch (err) {
            toast(err.message, true);
          }
        };
        act.appendChild(b);
      }
      el.appendChild(c);
    });
  } catch (err) {
    el.innerHTML = `<p class="muted">${err.message}</p>`;
  }
}

/* boot — verify voter JWT with server so localStorage cannot fake a session */
(async function boot() {
  bindAdminStatsNav();
  updateNav();
  const vt = localStorage.getItem(LS.voterTok);
  const at = localStorage.getItem(LS.adminTok);
  if (vt) {
    try {
      await api("/api/voter/session", { auth: "voter" });
      showView("voter");
      await loadVoterDashboard();
    } catch (e) {
      toast(e.message, true);
      showView("login");
      refreshAdminSetupUi();
    }
  } else if (at) {
    showView("admin");
    await loadAdminDashboard();
  } else {
    showView("login");
    refreshAdminSetupUi();
  }
})();
