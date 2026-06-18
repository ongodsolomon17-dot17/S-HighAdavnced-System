"use strict";

const API_URL = "https://s-highadavnced-system.onrender.com";

// ===== Auth Store ===========================================================
const Auth = {
  get token()    { return sessionStorage.getItem("att_token"); },
  get company()  { return sessionStorage.getItem("att_company"); },
  get role()     { return sessionStorage.getItem("att_role"); },
  get staffId()  { return sessionStorage.getItem("att_staff_id"); },
  get staffName(){ return sessionStorage.getItem("att_staff_name"); },
  set(token, company, role, staffId, staffName) {
    sessionStorage.setItem("att_token",      token);
    sessionStorage.setItem("att_company",    company);
    sessionStorage.setItem("att_role",       role || "admin");
    sessionStorage.setItem("att_staff_id",   staffId   || "");
    sessionStorage.setItem("att_staff_name", staffName || "");
  },
  clear() {
    ["att_token","att_company","att_role","att_staff_id","att_staff_name",
     "att_geofence","att_schedule","att_branding"].forEach(k => sessionStorage.removeItem(k));
  },
  isLoggedIn() { return !!this.token; }
};

// ===== Splash Screen ========================================================
function hideSplash() {
  const splash = document.getElementById("splash-screen");
  if (splash) {
    setTimeout(() => {
      splash.style.display = "none";

      // After splash, decide what to show
      if (Auth.isLoggedIn()) {
        apiFetch("/auth/profile").catch(() => {
          Auth.clear();
          showAuthShell();
          showToast("Session expired, please sign in again.", "error");
        });
      } else {
        showAuthShell();
      }
    }, 3200);
  }
}
hideSplash();

// ===== Sound Engine =========================================================
const SoundEngine = {
  ctx: null,
  enabled: true,
  staffMuted: false,

  init() {
    try { this.ctx = new (window.AudioContext || window.webkitAudioContext)(); } catch (_) {}
  },

  _play(type, idx) {
    if (!this.ctx || !this.enabled || this.staffMuted) return;
    // Resume context if suspended (autoplay policy)
    if (this.ctx.state === "suspended") this.ctx.resume();

    const osc  = this.ctx.createOscillator();
    const gain = this.ctx.createGain();
    osc.connect(gain);
    gain.connect(this.ctx.destination);

    const now = this.ctx.currentTime;
    const successTones = [
      [880, "sine", 0.18, 0.15],
      [1046, "sine", 0.16, 0.18],
      [784, "triangle", 0.2, 0.14],
      [1174, "sine", 0.15, 0.2],
      [988, "triangle", 0.18, 0.16],
      [1318, "sine", 0.14, 0.22],
    ];
    const failTones = [
      [220, "sawtooth", 0.2, 0.25],
      [180, "square",   0.15, 0.2],
      [196, "sawtooth", 0.18, 0.22],
      [165, "square",   0.2, 0.18],
      [207, "sawtooth", 0.16, 0.28],
      [174, "square",   0.18, 0.2],
    ];

    const tones = type === "success" ? successTones : failTones;
    const [freq, wave, vol, dur] = tones[idx % tones.length];
    osc.type      = wave;
    osc.frequency.setValueAtTime(freq, now);
    gain.gain.setValueAtTime(vol, now);
    gain.gain.exponentialRampToValueAtTime(0.001, now + dur);
    osc.start(now);
    osc.stop(now + dur);
  },

  success(idx = 0) { this._play("success", idx); },
  fail(idx = 0)    { this._play("fail",    idx); },
};

SoundEngine.init();

function testSuccessSound() { SoundEngine.enabled = true; SoundEngine.staffMuted = false; SoundEngine.success(Math.floor(Math.random()*6)); }
function testFailSound()    { SoundEngine.enabled = true; SoundEngine.staffMuted = false; SoundEngine.fail(Math.floor(Math.random()*6)); }

function toggleStaffMute() {
  SoundEngine.staffMuted = !SoundEngine.staffMuted;
  localStorage.setItem("staff_muted", SoundEngine.staffMuted ? "1" : "0");
  const btn = document.getElementById("staff-mute-btn");
  if (btn) btn.textContent = SoundEngine.staffMuted ? "🔇" : "🔔";
  showToast(SoundEngine.staffMuted ? "Sounds muted 🔇" : "Sounds on 🔔", "success");
}

function applySoundSettings(soundEnabled) {
  SoundEngine.enabled    = soundEnabled;
  SoundEngine.staffMuted = localStorage.getItem("staff_muted") === "1";
  const btn = document.getElementById("staff-mute-btn");
  if (btn) btn.textContent = SoundEngine.staffMuted ? "🔇" : "🔔";
}

async function saveSoundSetting() {
  const enabled = document.getElementById("sound-enabled").checked;
  document.getElementById("sound-enabled-label").textContent = enabled ? "Sounds On 🔊" : "Sounds Off";
  SoundEngine.enabled = enabled;
  try {
    const profile = await apiFetch("/auth/profile");
    await apiFetch("/settings/schedule", {
      method: "PUT",
      body: JSON.stringify({
        checkin_time:          document.getElementById("sched-checkin").value  || profile.checkin_time  || "09:00",
        checkout_time:         document.getElementById("sched-checkout").value || profile.checkout_time || "17:00",
        sound_enabled:         enabled,
        clockout_enabled:      document.getElementById("clockout-enabled")?.checked ?? true,
        night_clockout_enabled:document.getElementById("night-clockout-enabled")?.checked ?? true,
        max_devices:           parseInt(document.getElementById("max-devices")?.value || 3)
      })
    });
    showToast(enabled ? "Sounds enabled!" : "Sounds disabled!", "success");
  } catch (_) {}
}

async function saveMaxDevices() {
  const max = parseInt(document.getElementById("max-devices").value);
  if (isNaN(max) || max < 1 || max > 5) { showToast("Max devices must be 1–5.", "error"); return; }
  try {
    const profile = await apiFetch("/auth/profile");
    await apiFetch("/settings/schedule", {
      method: "PUT",
      body: JSON.stringify({
        checkin_time:  profile.checkin_time  || "09:00",
        checkout_time: profile.checkout_time || "17:00",
        max_devices:   max,
        sound_enabled: profile.sound_enabled ?? true,
        clockout_enabled:       profile.clockout_enabled ?? true,
        night_clockout_enabled: profile.night_clockout_enabled ?? true,
      })
    });
    showToast(`Max devices set to ${max}.`, "success");
  } catch (err) { showToast(err.message, "error"); }
}

// ===== Device Fingerprint ===================================================
function getDeviceFingerprint() {
  const raw = [navigator.userAgent, navigator.language, navigator.platform,
    screen.width+"x"+screen.height, screen.colorDepth,
    new Date().getTimezoneOffset(), navigator.hardwareConcurrency||0].join("|");
  let h = 0;
  for (let i = 0; i < raw.length; i++) { h = ((h<<5)-h)+raw.charCodeAt(i); h|=0; }
  return Math.abs(h).toString(36);
}
function getDeviceName() {
  const ua = navigator.userAgent;
  if (/iPhone/.test(ua)) return "iPhone";
  if (/iPad/.test(ua))   return "iPad";
  if (/Android/.test(ua))return "Android Device";
  if (/Windows/.test(ua))return "Windows PC";
  if (/Mac/.test(ua))    return "Mac";
  return "Unknown Device";
}
let _pendingDeviceTrust = false;

// ===== Geolocation ==========================================================
let staffGeoPos = null, adminGeoPos = null;

function startStaffGeoWatch() {
  const el = document.getElementById("geo-status-staff");
  if (!navigator.geolocation) { if (el) el.textContent = "📍 Geolocation not supported"; return; }
  navigator.geolocation.watchPosition(
    pos => { staffGeoPos = pos; if (el) el.textContent = `📍 Location active (±${pos.coords.accuracy.toFixed(0)}m)`; },
    ()  => { if (el) el.textContent = "⚠️ Location unavailable — check permissions"; },
    { enableHighAccuracy: true }
  );
}

function startAdminGeoWatch() {
  if (!navigator.geolocation) return;
  navigator.geolocation.watchPosition(
    pos => { adminGeoPos = pos; const el = document.getElementById("admin-geo-status"); if (el) el.textContent = `📍 Location active (±${pos.coords.accuracy.toFixed(0)}m)`; },
    ()  => { const el = document.getElementById("admin-geo-status"); if (el) el.textContent = "⚠️ Location unavailable"; },
    { enableHighAccuracy: true }
  );
}

// ===== Toast ================================================================
let toastTimer = null;
function showToast(message, type = "success") {
  const toast = document.getElementById("toast");
  toast.textContent = message;
  toast.className = `toast ${type}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.add("hidden"), 3500);
  if (type === "success") SoundEngine.success(Math.floor(Math.random()*6));
  else if (type === "error") SoundEngine.fail(Math.floor(Math.random()*6));
}

// ===== API Fetch ============================================================
async function apiFetch(path, options = {}, requireAuth = true) {
  const headers = { "Content-Type": "application/json" };
  if (requireAuth) {
    if (!Auth.isLoggedIn()) { showAuthShell(); return; }
    headers["Authorization"] = `Bearer ${Auth.token}`;
  }
  const res  = await fetch(`${API_URL}${path}`, { headers, ...options });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) { Auth.clear(); showAuthShell(); throw new Error("Session expired."); }
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

// ===== Branding =============================================================
function applyBranding(pictureUrl) {
  ["auth-badge","admin-badge","staff-badge","splash-badge"].forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    if (pictureUrl) {
      el.style.backgroundImage = `url(${pictureUrl})`;
      el.style.backgroundSize = "cover";
      el.style.backgroundPosition = "center";
      el.textContent = "";
    } else {
      el.style.backgroundImage = "";
      el.textContent = "S";
    }
  });
  const preview = document.getElementById("profile-pic-preview");
  if (preview) {
    if (pictureUrl) preview.innerHTML = `<img src="${pictureUrl}" style="width:100%;height:100%;object-fit:cover;border-radius:50%" />`;
    else preview.innerHTML = "S";
  }
}

async function loadBranding() {
  try {
    const data = await apiFetch("/company/branding");
    if (data.profile_picture) applyBranding(data.profile_picture);
    sessionStorage.setItem("att_branding", data.profile_picture || "");
  } catch (_) {}
}

// ===== Auth modes ===========================================================
let authMode = "admin";
function switchAuthMode(mode) {
  authMode = mode;
  document.getElementById("admin-auth-panel").classList.toggle("hidden", mode !== "admin");
  document.getElementById("staff-auth-panel").classList.toggle("hidden", mode !== "staff");
  document.getElementById("rtab-admin").classList.toggle("active", mode === "admin");
  document.getElementById("rtab-staff").classList.toggle("active", mode === "staff");
  document.getElementById("auth-message").classList.add("hidden");
}

function switchStaffTab(tab) {
  document.getElementById("staff-form-login").classList.toggle("hidden",    tab !== "login");
  document.getElementById("staff-form-register").classList.toggle("hidden", tab !== "register");
  document.getElementById("stab-login").classList.toggle("active",    tab === "login");
  document.getElementById("stab-register").classList.toggle("active", tab === "register");
  document.getElementById("auth-message").classList.add("hidden");
}

function showAuthShell() {
  document.getElementById("auth-shell").classList.remove("hidden");
  document.getElementById("app-shell").classList.add("hidden");
  document.getElementById("staff-shell").classList.add("hidden");
  const saved = sessionStorage.getItem("att_branding");
  if (saved) applyBranding(saved);
}

function showAppShell() {
  document.getElementById("auth-shell").classList.add("hidden");
  document.getElementById("app-shell").classList.remove("hidden");
  document.getElementById("staff-shell").classList.add("hidden");
  document.getElementById("company-name-display").textContent = Auth.company || "Your Company";
  loadBranding();
  refreshDisplay();
  loadDashboard();
  startAdminGeoWatch();
  loadDevices();
  loadPendingDevices();
}

function showStaffShell() {
  document.getElementById("auth-shell").classList.add("hidden");
  document.getElementById("app-shell").classList.add("hidden");
  document.getElementById("staff-shell").classList.remove("hidden");
  document.getElementById("staff-company-display").textContent = Auth.company || "Company";
  document.getElementById("staff-name-display").textContent = Auth.staffName || Auth.staffId || "Staff";
  loadBranding();
  renderStaffQR();
  loadStaffSummary("daily");
  startStaffGeoWatch();
  loadStaffNotices();
  applyScheduleDisplay();
  applySoundSettings(JSON.parse(sessionStorage.getItem("att_schedule") || "{}").sound_enabled ?? true);
}

// ===== Sign Out Confirmation ================================================
function confirmSignOut() { openModal("signout-modal"); }
function doSignOut() {
  Auth.clear();
  closeModal();
  showAuthShell();
  switchTab("login");
  showToast("Signed out successfully.", "success");
}

// ===== Staff Search =========================================================
let _allStaffCache = [];

async function ensureStaffCache() {
  if (!_allStaffCache.length) { try { _allStaffCache = await listStaff(); } catch (_) {} }
}

function searchStaffLive(query, context) {
  const resultsId  = context === "attendance" ? "staff-search-results"  : "report-search-results";
  const hiddenId   = context === "attendance" ? "attendance-staff"       : "report-staff-id";
  const displayId  = context === "attendance" ? "selected-staff-display" : "report-staff-display";
  const results    = document.getElementById(resultsId);

  if (!query.trim()) {
    results.classList.add("hidden");
    if (context === "report") {
      document.getElementById(hiddenId).value = "";
      document.getElementById(displayId).textContent = "";
    }
    return;
  }

  const q       = query.toLowerCase();
  const matches = _allStaffCache.filter(s =>
    s.name.toLowerCase().includes(q) || s.id.toLowerCase().includes(q)
  ).slice(0, 8);

  if (!matches.length) { results.innerHTML = '<div class="search-result-item" style="color:var(--text-muted)">No staff found</div>'; results.classList.remove("hidden"); return; }

  results.innerHTML = matches.map(s => `
    <div class="search-result-item" onclick="selectSearchStaff('${esc(s.id)}','${esc(s.name)}','${context}')">
      <span>${esc(s.name)}</span>
      <span class="staff-id-chip">${esc(s.id)}</span>
    </div>
  `).join("");
  results.classList.remove("hidden");
}

function selectSearchStaff(id, name, context) {
  const resultsId = context === "attendance" ? "staff-search-results"  : "report-search-results";
  const inputId   = context === "attendance" ? "staff-search-input"    : "report-search-input";
  const hiddenId  = context === "attendance" ? "attendance-staff"      : "report-staff-id";
  const displayId = context === "attendance" ? "selected-staff-display": "report-staff-display";

  document.getElementById(resultsId).classList.add("hidden");
  document.getElementById(inputId).value   = name;
  document.getElementById(hiddenId).value  = id;
  document.getElementById(displayId).textContent = `✅ Selected: ${name} (${id})`;
}

// Close search results on outside click
document.addEventListener("click", e => {
  ["staff-search-results","report-search-results"].forEach(id => {
    const el = document.getElementById(id);
    if (el && !el.contains(e.target)) el.classList.add("hidden");
  });
});

// ===== Tab Switching ========================================================
function switchTab(tab) {
  document.getElementById("form-login").classList.toggle("hidden",    tab !== "login");
  document.getElementById("form-register").classList.toggle("hidden", tab !== "register");
  document.getElementById("tab-login").classList.toggle("active",    tab === "login");
  document.getElementById("tab-register").classList.toggle("active", tab === "register");
  document.getElementById("auth-message").classList.add("hidden");
}

function showAuthMessage(msg, type = "error") {
  const el = document.getElementById("auth-message");
  el.textContent = msg; el.className = `auth-message ${type}`;
}

function toggleEye(inputId, btn) {
  const inp = document.getElementById(inputId);
  inp.type = inp.type === "password" ? "text" : "password";
  btn.textContent = inp.type === "password" ? "👁" : "🙈";
}

let currentMainTab = "dashboard", currentDashPeriod = "daily";

function switchMainTab(tab) {
  document.querySelectorAll(".nav-tab").forEach(b => b.classList.toggle("active", b.dataset.tab === tab));
  document.querySelectorAll(".tab-panel").forEach(p => p.classList.toggle("hidden", p.id !== `tab-${tab}`));
  currentMainTab = tab;
  if (tab === "analytics") loadAnalytics();
  if (tab === "reports")   { ensureStaffCache(); }
  if (tab === "settings")  loadSettingsData();
  if (tab === "notices")   loadNotices();
}

function switchDashPeriod(period) {
  currentDashPeriod = period;
  ["daily","weekly","monthly","annual"].forEach(p => {
    document.getElementById(`dash-period-${p}`)?.classList.toggle("active", p === period);
  });
  loadSummaryTable(period);
}

// ===== Shift selection ======================================================
let selectedShift = "day";
function applyScheduleDisplay() {
  const sched = JSON.parse(sessionStorage.getItem("att_schedule") || "{}");
  const el    = document.getElementById("staff-schedule-display");
  if (el && sched.checkin_time) {
    el.textContent = `⏰ ${sched.checkin_time}–${sched.checkout_time}`;
  }
  if (sched.night_checkin_time) {
    document.getElementById("shift-selector")?.classList.remove("hidden");
  }
  // Show/hide clock-out button based on admin setting
  const coBtn = document.getElementById("btn-staff-checkout");
  if (coBtn) {
    const show = sched.clockout_enabled !== false;
    coBtn.style.display = show ? "" : "none";
  }
}

function selectShift(shift) {
  selectedShift = shift;
  document.getElementById("shift-btn-day").classList.toggle("active",   shift === "day");
  document.getElementById("shift-btn-night").classList.toggle("active", shift === "night");
  // Update clock-out visibility based on shift
  const sched = JSON.parse(sessionStorage.getItem("att_schedule") || "{}");
  const coBtn = document.getElementById("btn-staff-checkout");
  if (coBtn) {
    const show = shift === "day" ? sched.clockout_enabled !== false : sched.night_clockout_enabled !== false;
    coBtn.style.display = show ? "" : "none";
  }
}

// ===== Password Strength ====================================================
document.getElementById("reg-password")?.addEventListener("input", function() {
  const pw = this.value;
  const el = document.getElementById("pw-strength");
  if (!pw) { el.textContent = ""; el.className = "pw-strength"; return; }
  let score = 0;
  if (pw.length >= 8) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  const labels  = ["","Weak","Fair","Good","Strong"];
  const classes = ["","pw-weak","pw-fair","pw-good","pw-strong"];
  el.textContent = labels[score] || "Weak";
  el.className   = `pw-strength ${classes[score] || "pw-weak"}`;
});

// ===== Register =============================================================
async function handleRegister() {
  const company  = document.getElementById("reg-company").value.trim();
  const email    = document.getElementById("reg-email").value.trim();
  const phone    = document.getElementById("reg-phone").value.trim();
  const password = document.getElementById("reg-password").value;
  const password2= document.getElementById("reg-password2").value;
  const pin      = document.getElementById("reg-pin").value.trim();
  if (!company)              { showAuthMessage("Please enter your company name."); return; }
  if (!email)                { showAuthMessage("Please enter your email."); return; }
  if (password.length < 8)   { showAuthMessage("Password must be at least 8 characters."); return; }
  if (password !== password2){ showAuthMessage("Passwords do not match."); return; }
  if (!/^\d{4,8}$/.test(pin)){ showAuthMessage("PIN must be 4–8 digits."); return; }
  const btn = document.getElementById("btn-register");
  const sp  = document.getElementById("register-spinner");
  btn.disabled = true; sp.classList.remove("hidden");
  try {
    const res = await apiFetch("/auth/register", { method: "POST", body: JSON.stringify({ company, email, phone, password, pin }) }, false);
    Auth.set(res.token, res.company, "admin");
    await checkDeviceTrust();
    showAppShell();
    showToast(`Welcome, ${res.company}!`, "success");
  } catch (err) { showAuthMessage(err.message); SoundEngine.fail(0); }
  finally { btn.disabled = false; sp.classList.add("hidden"); }
}

// ===== Login ================================================================
async function handleLogin() {
  const email    = document.getElementById("login-email").value.trim();
  const password = document.getElementById("login-password").value;
  if (!email || !password) { showAuthMessage("Please enter email and password."); return; }
  const btn = document.getElementById("btn-login");
  const sp  = document.getElementById("login-spinner");
  btn.disabled = true; sp.classList.remove("hidden");
  try {
    const fp  = getDeviceFingerprint();
    const res = await fetch(`${API_URL}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Device-FP": fp },
      body: JSON.stringify({ email, password })
    });
    const resData = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(resData.error || `Login failed (${res.status})`);
    Auth.set(resData.token, resData.company, "admin");
    await checkDeviceTrust();
    showAppShell();
    showToast(`Welcome back, ${resData.company}!`, "success");
  } catch (err) { showAuthMessage(err.message); SoundEngine.fail(0); }
  finally { btn.disabled = false; sp.classList.add("hidden"); }
}

// ===== Staff Login ===========================================================
async function handleStaffLogin() {
  const email    = document.getElementById("slogin-email").value.trim();
  const password = document.getElementById("slogin-password").value;
  if (!email || !password) { showAuthMessage("Please enter email and password."); return; }
  const btn = document.getElementById("btn-staff-login");
  const sp  = document.getElementById("staff-login-spinner");
  btn.disabled = true; sp.classList.remove("hidden");
  try {
    const fp2 = getDeviceFingerprint();
    const res = await fetch(`${API_URL}/auth/staff-login`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Device-FP": fp2 },
      body: JSON.stringify({ email, password })
    });
    const resData2 = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(resData2.error || `Login failed (${res.status})`);
    Auth.set(resData2.token, resData2.company, "staff", resData2.staff_id, resData2.name);
    if (resData2.geofence) sessionStorage.setItem("att_geofence", JSON.stringify(resData2.geofence));
    if (resData2.schedule) sessionStorage.setItem("att_schedule", JSON.stringify(resData2.schedule));
    await checkDeviceTrust();
    showStaffShell();
    showToast(`Welcome, ${resData2.name}!`, "success");
  } catch (err) { showAuthMessage(err.message); SoundEngine.fail(0); }
  finally { btn.disabled = false; sp.classList.add("hidden"); }
}

// ===== Staff Register =======================================================
async function handleStaffRegister() {
  const company_email = document.getElementById("sreg-company-email").value.trim();
  const staff_id      = document.getElementById("sreg-staffid").value.trim();
  const email         = document.getElementById("sreg-email").value.trim();
  const password      = document.getElementById("sreg-password").value;
  if (!company_email || !staff_id || !email || !password) { showAuthMessage("Please fill in all fields."); return; }
  if (password.length < 8) { showAuthMessage("Password must be at least 8 characters."); return; }
  const btn = document.getElementById("btn-staff-register");
  const sp  = document.getElementById("staff-reg-spinner");
  btn.disabled = true; sp.classList.remove("hidden");
  try {
    await apiFetch("/auth/staff-register", { method: "POST", body: JSON.stringify({ company_email, staff_id, email, password }) }, false);
    showAuthMessage("Account linked! You can now sign in.", "success");
    switchStaffTab("login");
  } catch (err) { showAuthMessage(err.message); }
  finally { btn.disabled = false; sp.classList.add("hidden"); }
}

// ===== Device Trust =========================================================
async function checkDeviceTrust() {
  try {
    const fp   = getDeviceFingerprint();
    const name = getDeviceName();
    const res  = await apiFetch("/devices/verify", { method: "POST", body: JSON.stringify({ fingerprint: fp, device_name: name }) });
    if (res.status === "trusted") {
      if (res.temp && res.expires_at) showToast(`⚠️ Temp access expires ${new Date(res.expires_at+"Z").toLocaleString()}`, "error");
      return;
    }
    if (res.status === "pending") {
      Auth.clear(); showAuthShell();
      showAuthMessage("⏳ Device approval pending. Ask your admin to approve.", "error"); return;
    }
    if (res.status === "rejected") {
      Auth.clear(); showAuthShell();
      showAuthMessage("🚫 Access denied. Device rejected by admin.", "error"); return;
    }
    if (res.status === "unknown" && Auth.role === "admin") { _pendingDeviceTrust = true; openModal("device-modal"); return; }
    if (res.first_bind) showToast("✅ Device registered as your primary device.", "success");
  } catch (_) {}
}

async function trustThisDevice() {
  try {
    await apiFetch("/devices/trust", { method: "POST", body: JSON.stringify({ fingerprint: getDeviceFingerprint(), device_name: getDeviceName() }) });
    showToast("Device trusted!", "success");
  } catch (err) { showToast(err.message, "error"); }
  closeModal(); _pendingDeviceTrust = false;
}

async function loadDevices() {
  try {
    const devices = await apiFetch("/devices");
    const el = document.getElementById("devices-list");
    if (!el) return;
    if (!devices.length) { el.innerHTML = '<p class="hint">No trusted devices.</p>'; return; }
    el.innerHTML = devices.map(d => `
      <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.06)">
        <div>
          <div style="font-size:13px;font-weight:600">${esc(d.device_name||"Unknown")}</div>
          <div style="font-size:11px;color:var(--text-muted)">Last used: ${d.last_used?new Date(d.last_used+"Z").toLocaleDateString():"—"}</div>
        </div>
        <button onclick="revokeDevice(${d.id})" style="padding:5px 12px;border-radius:8px;border:none;background:rgba(255,107,107,0.15);color:var(--danger);font-size:12px;cursor:pointer;font-weight:700">Revoke</button>
      </div>
    `).join("");
  } catch (_) {}
}

async function revokeDevice(id) {
  try { await apiFetch(`/devices/${id}`, { method: "DELETE" }); showToast("Device revoked.", "success"); loadDevices(); }
  catch (err) { showToast(err.message, "error"); }
}

async function loadPendingDevices() {
  try {
    const pending = await apiFetch("/devices/pending");
    const el = document.getElementById("pending-devices-list");
    const badge = document.getElementById("pending-devices-badge");
    if (!el) return;
    if (!pending.length) {
      el.innerHTML = '<p class="hint">No pending requests.</p>';
      if (badge) badge.classList.add("hidden");
      return;
    }
    if (badge) { badge.textContent = pending.length; badge.classList.remove("hidden"); }
    el.innerHTML = pending.map(d => `
      <div style="padding:12px;border-radius:10px;background:rgba(255,193,7,0.07);border:1px solid rgba(255,193,7,0.18);margin-bottom:8px">
        <div style="font-weight:700;font-size:13px">👤 ${esc(d.staff_name||d.staff_id)}</div>
        <div style="font-size:11px;color:var(--text-muted);margin-top:3px">Device: ${esc(d.device_name||"Unknown")} · ${new Date(d.created_at+"Z").toLocaleString()}</div>
        <div style="display:flex;gap:8px;margin-top:8px">
          <button onclick="approveDevice(${d.id})" style="padding:6px 14px;border-radius:8px;border:none;background:rgba(109,210,143,0.15);color:var(--success);font-size:12px;cursor:pointer;font-weight:700">✅ Approve 20h</button>
          <button onclick="rejectDevice(${d.id})"  style="padding:6px 14px;border-radius:8px;border:none;background:rgba(255,107,107,0.15);color:var(--danger);font-size:12px;cursor:pointer;font-weight:700">🚫 Reject</button>
        </div>
      </div>
    `).join("");
  } catch (_) {}
}

async function approveDevice(id) {
  try { await apiFetch(`/devices/${id}/approve`, { method: "POST" }); showToast("Approved for 20h!", "success"); loadPendingDevices(); }
  catch (err) { showToast(err.message, "error"); }
}
async function rejectDevice(id) {
  try { await apiFetch(`/devices/${id}/reject`, { method: "POST" }); showToast("Device rejected.", "success"); loadPendingDevices(); }
  catch (err) { showToast(err.message, "error"); }
}

// ===== PIN Modal ============================================================
let pinResolve = null, pinReject = null;
function requestPin() {
  return new Promise((resolve, reject) => {
    pinResolve = resolve; pinReject = reject;
    document.querySelectorAll(".pin-box").forEach(b => b.value = "");
    document.getElementById("pin-error").classList.add("hidden");
    openModal("pin-modal");
    document.querySelector(".pin-box").focus();
  });
}

document.getElementById("pin-inputs").addEventListener("input", e => {
  if (!e.target.classList.contains("pin-box")) return;
  const boxes = [...document.querySelectorAll(".pin-box")];
  const idx   = boxes.indexOf(e.target);
  if (e.target.value && idx < boxes.length-1) boxes[idx+1].focus();
});
document.getElementById("pin-inputs").addEventListener("keydown", e => {
  if (!e.target.classList.contains("pin-box")) return;
  const boxes = [...document.querySelectorAll(".pin-box")];
  const idx   = boxes.indexOf(e.target);
  if (e.key === "Backspace" && !e.target.value && idx > 0) boxes[idx-1].focus();
  if (e.key === "Enter") confirmPin();
});

async function confirmPin() {
  const pin = [...document.querySelectorAll(".pin-box")].map(b => b.value).join("");
  if (pin.length < 4) { document.getElementById("pin-error").classList.remove("hidden"); return; }
  const btn = document.getElementById("btn-confirm-pin");
  btn.disabled = true;
  try {
    await apiFetch("/auth/verify-pin", { method: "POST", body: JSON.stringify({ pin }) });
    closeModal(); if (pinResolve) pinResolve(true);
  } catch (_) {
    document.getElementById("pin-error").classList.remove("hidden");
    document.querySelectorAll(".pin-box").forEach(b => b.value = "");
    document.querySelector(".pin-box").focus();
    SoundEngine.fail(1);
  } finally { btn.disabled = false; }
}
document.getElementById("btn-confirm-pin").addEventListener("click", confirmPin);
document.getElementById("btn-close-pin").addEventListener("click",  () => { closeModal(); if (pinReject) pinReject(new Error("PIN cancelled")); });
document.getElementById("btn-close-pin2").addEventListener("click", () => { closeModal(); if (pinReject) pinReject(new Error("PIN cancelled")); });

async function withPin(action) {
  try { await requestPin(); await action(); }
  catch (err) { if (err.message !== "PIN cancelled") showToast(err.message, "error"); }
}

// ===== Forgot Password ======================================================
let forgotRole = "admin";
function showForgotPassword(role) {
  forgotRole = role;
  document.getElementById("forgot-step-1").classList.remove("hidden");
  document.getElementById("forgot-step-2").classList.add("hidden");
  document.getElementById("forgot-status").textContent = "";
  document.getElementById("forgot-email").value = "";
  openModal("forgot-modal");
}
async function sendResetCode() {
  const email = document.getElementById("forgot-email").value.trim();
  if (!email) { document.getElementById("forgot-status").textContent = "Please enter your email."; return; }
  try {
    await apiFetch("/auth/forgot-password", { method: "POST", body: JSON.stringify({ email, role: forgotRole }) }, false);
    document.getElementById("forgot-step-1").classList.add("hidden");
    document.getElementById("forgot-step-2").classList.remove("hidden");
    document.getElementById("forgot-status").textContent = "Code sent! Check your email.";
  } catch (err) { document.getElementById("forgot-status").textContent = err.message; }
}
async function confirmResetCode() {
  const email       = document.getElementById("forgot-email").value.trim();
  const code        = document.getElementById("forgot-code").value.trim();
  const newPassword = document.getElementById("forgot-new-password").value;
  if (!code || !newPassword) { document.getElementById("forgot-status").textContent = "Fill in all fields."; return; }
  if (newPassword.length < 8) { document.getElementById("forgot-status").textContent = "Password min 8 chars."; return; }
  try {
    await apiFetch("/auth/reset-password", { method: "POST", body: JSON.stringify({ email, code, new_password: newPassword, role: forgotRole }) }, false);
    showToast("Password reset! Please sign in.", "success");
    closeModal();
  } catch (err) { document.getElementById("forgot-status").textContent = err.message; }
}

// ===== Notices ==============================================================
async function loadNotices() {
  try {
    const notices = await apiFetch("/notices");
    const el = document.getElementById("notices-list");
    if (!el) return;
    if (!notices.length) { el.innerHTML = '<p class="hint">No notices yet.</p>'; return; }
    el.innerHTML = notices.map(n => `
      <div style="padding:12px;border-radius:10px;background:rgba(255,255,255,0.05);margin-bottom:8px;position:relative">
        ${n.pinned ? '<span style="font-size:11px;color:var(--accent);font-weight:700">📌 PINNED</span><br>' : ''}
        <div style="font-weight:700;margin-bottom:4px">${esc(n.title)}</div>
        <div style="font-size:13px;color:var(--text-muted)">${esc(n.body)}</div>
        <div style="font-size:11px;color:var(--text-muted);margin-top:6px">${new Date(n.created_at+"Z").toLocaleString()}</div>
        <button onclick="deleteNotice(${n.id})" style="position:absolute;top:10px;right:10px;padding:4px 10px;border-radius:6px;border:none;background:rgba(255,107,107,0.15);color:var(--danger);font-size:11px;cursor:pointer;font-weight:700">Delete</button>
      </div>
    `).join("");
  } catch (_) {}
}
async function postNotice() {
  const title  = document.getElementById("notice-title").value.trim();
  const body   = document.getElementById("notice-body").value.trim();
  const pinned = document.getElementById("notice-pinned").checked;
  if (!title || !body) { showToast("Please fill in title and message.", "error"); return; }
  try {
    await apiFetch("/notices", { method: "POST", body: JSON.stringify({ title, body, pinned }) });
    document.getElementById("notice-title").value = "";
    document.getElementById("notice-body").value  = "";
    document.getElementById("notice-pinned").checked = false;
    showToast("Notice posted!", "success");
    loadNotices();
  } catch (err) { showToast(err.message, "error"); }
}
async function deleteNotice(id) {
  try { await apiFetch(`/notices/${id}`, { method: "DELETE" }); showToast("Notice deleted.", "success"); loadNotices(); }
  catch (err) { showToast(err.message, "error"); }
}
async function loadStaffNotices() {
  try {
    const notices = await apiFetch("/notices");
    const bar = document.getElementById("staff-notices-bar");
    if (!bar || !notices.length) return;
    bar.style.display = "block";
    bar.innerHTML = notices.slice(0,3).map(n => `
      <div style="padding:10px 16px;border-radius:10px;margin-bottom:8px;
                  background:rgba(63,193,201,0.08);border:1px solid rgba(63,193,201,0.2)">
        ${n.pinned ? '📌 ' : '📢 '}<strong>${esc(n.title)}</strong>
        <span style="margin-left:8px;font-size:12px;color:var(--text-muted)">${esc(n.body)}</span>
      </div>
    `).join("");
  } catch (_) {}
}

// ===== Feedback =============================================================
let selectedRating = 0;
function setRating(r) {
  selectedRating = r;
  document.querySelectorAll("#star-rating span").forEach((s,i) => { s.style.opacity = i < r ? "1" : "0.3"; });
}
async function submitFeedback() {
  const message = document.getElementById("feedback-message").value.trim();
  if (!message) { showToast("Please write a message.", "error"); return; }
  const btn = document.getElementById("feedback-btn-label");
  const sp  = document.getElementById("feedback-spinner");
  btn.textContent = "Sending…"; sp.classList.remove("hidden");
  try {
    await apiFetch("/feedback", { method: "POST", body: JSON.stringify({ message, rating: selectedRating || null }) });
    document.getElementById("feedback-message").value = "";
    selectedRating = 0; setRating(0);
    document.getElementById("feedback-status").textContent = "✅ Feedback sent! Thank you.";
    showToast("Feedback sent!", "success");
  } catch (err) { document.getElementById("feedback-status").textContent = err.message; showToast(err.message, "error"); }
  finally { btn.textContent = "Send Feedback"; sp.classList.add("hidden"); }
}

// ===== Profile Picture ======================================================
async function handleProfilePicUpload(input) {
  const file = input.files[0];
  if (!file) return;
  if (!["image/jpeg","image/png","image/webp"].includes(file.type)) { showToast("Only JPEG, PNG or WebP allowed.", "error"); return; }
  if (file.size > 2*1024*1024) { showToast("Image must be under 2MB.", "error"); return; }
  const reader = new FileReader();
  reader.onload = async e => {
    const b64 = e.target.result.split(",")[1];
    try {
      const res = await apiFetch("/settings/profile-picture", { method: "POST", body: JSON.stringify({ mime_type: file.type, image_b64: b64 }) });
      applyBranding(res.url);
      sessionStorage.setItem("att_branding", res.url);
      document.getElementById("profile-pic-status").textContent = "✅ Logo updated!";
      showToast("Company logo updated!", "success");
    } catch (err) { showToast(err.message, "error"); }
  };
  reader.readAsDataURL(file);
}
async function removeProfilePic() {
  try {
    await apiFetch("/settings/profile-picture", { method: "DELETE" });
    applyBranding(null); sessionStorage.setItem("att_branding", "");
    document.getElementById("profile-pic-status").textContent = "Logo removed.";
    showToast("Logo removed.", "success");
  } catch (err) { showToast(err.message, "error"); }
}

// ===== Profile Edit =========================================================
async function unlockProfileEdit() {
  await withPin(async () => {
    const profile = await apiFetch("/auth/profile");
    document.getElementById("edit-company").value = profile.company || "";
    document.getElementById("edit-email").value   = profile.email   || "";
    document.getElementById("edit-phone").value   = profile.phone   || "";
    document.getElementById("profile-edit-locked").classList.add("hidden");
    document.getElementById("profile-edit-form").classList.remove("hidden");
  });
}
async function saveProfileEdit() {
  const company = document.getElementById("edit-company").value.trim();
  const email   = document.getElementById("edit-email").value.trim();
  const phone   = document.getElementById("edit-phone").value.trim();
  try {
    await apiFetch("/auth/update-profile", { method: "PUT", body: JSON.stringify({ company, email, phone }) });
    if (company) { sessionStorage.setItem("att_company", company); document.getElementById("company-name-display").textContent = company; }
    document.getElementById("profile-edit-status").textContent = "✅ Profile updated!";
    showToast("Profile updated!", "success");
  } catch (err) { showToast(err.message, "error"); }
}
async function savePasswordPin() {
  const newPassword = document.getElementById("edit-new-password").value;
  const newPin      = document.getElementById("edit-new-pin").value.trim();
  if (newPassword) {
    if (newPassword.length < 8) { showToast("Password must be at least 8 characters.", "error"); return; }
    try { await apiFetch("/auth/change-password", { method: "PUT", body: JSON.stringify({ new_password: newPassword }) }); document.getElementById("edit-new-password").value = ""; showToast("Password updated!", "success"); }
    catch (err) { showToast(err.message, "error"); return; }
  }
  if (newPin) {
    if (!/^\d{4,8}$/.test(newPin)) { showToast("PIN must be 4–8 digits.", "error"); return; }
    try { await apiFetch("/auth/change-pin", { method: "PUT", body: JSON.stringify({ new_pin: newPin }) }); document.getElementById("edit-new-pin").value = ""; showToast("PIN updated!", "success"); }
    catch (err) { showToast(err.message, "error"); }
  }
}

// ===== Schedule Settings ====================================================
function toggleNightShift() {
  const enabled = document.getElementById("enable-night-shift").checked;
  document.getElementById("night-shift-fields").classList.toggle("hidden", !enabled);
}
function toggleGeofenceFields() {
  const enabled = document.getElementById("geo-enabled").checked;
  document.getElementById("geo-fields").classList.toggle("hidden", !enabled);
  document.getElementById("geo-enabled-label").textContent = enabled ? "Geofencing On ✅" : "Geofencing Off";
}
async function saveSchedule() {
  const checkin_time          = document.getElementById("sched-checkin").value;
  const checkout_time         = document.getElementById("sched-checkout").value;
  const clockout_enabled      = document.getElementById("clockout-enabled").checked;
  const nightEnabled          = document.getElementById("enable-night-shift").checked;
  const night_checkin         = nightEnabled ? document.getElementById("sched-night-checkin").value  : null;
  const night_checkout        = nightEnabled ? document.getElementById("sched-night-checkout").value : null;
  const night_clockout_enabled= nightEnabled ? document.getElementById("night-clockout-enabled").checked : true;
  const sound_enabled         = document.getElementById("sound-enabled").checked;
  const max_devices           = parseInt(document.getElementById("max-devices")?.value || 3);
  try {
    await apiFetch("/settings/schedule", { method: "PUT", body: JSON.stringify({
      checkin_time, checkout_time, clockout_enabled,
      night_checkin_time: night_checkin, night_checkout_time: night_checkout,
      night_clockout_enabled, sound_enabled, max_devices
    }) });
    document.getElementById("sched-status").textContent = `✅ Schedule saved: ${checkin_time}–${checkout_time}`;
    showToast("Schedule saved!", "success");
  } catch (err) { showToast(err.message, "error"); }
}

// ===== Settings Data Load ===================================================
async function loadSettingsData() {
  try {
    const profile = await apiFetch("/auth/profile");
    const geoEnabled = profile.geofence_enabled || false;
    document.getElementById("geo-enabled").checked = geoEnabled;
    document.getElementById("geo-enabled-label").textContent = geoEnabled ? "Geofencing On ✅" : "Geofencing Off";
    document.getElementById("geo-fields").classList.toggle("hidden", !geoEnabled);
    if (profile.geofence_lat) {
      document.getElementById("geo-lat").value    = profile.geofence_lat;
      document.getElementById("geo-lng").value    = profile.geofence_lng;
      document.getElementById("geo-radius").value = profile.geofence_radius || 200;
    }
    if (profile.checkin_time) {
      document.getElementById("sched-checkin").value  = profile.checkin_time;
      document.getElementById("sched-checkout").value = profile.checkout_time;
    }
    if (profile.night_checkin_time) {
      document.getElementById("enable-night-shift").checked = true;
      document.getElementById("night-shift-fields").classList.remove("hidden");
      document.getElementById("sched-night-checkin").value  = profile.night_checkin_time;
      document.getElementById("sched-night-checkout").value = profile.night_checkout_time;
    }
    document.getElementById("clockout-enabled").checked       = profile.clockout_enabled      ?? true;
    document.getElementById("night-clockout-enabled").checked = profile.night_clockout_enabled ?? true;
    const soundOn = profile.sound_enabled ?? true;
    document.getElementById("sound-enabled").checked = soundOn;
    document.getElementById("sound-enabled-label").textContent = soundOn ? "Sounds On 🔊" : "Sounds Off";
    SoundEngine.enabled = soundOn;
    document.getElementById("max-devices").value = profile.max_devices || 3;
    if (profile.profile_picture) applyBranding(profile.profile_picture);
  } catch (_) {}
  try {
    const intg = await apiFetch("/integrations");
    if (intg) {
      document.getElementById("int-type").value = intg.type;
      const urlKey = intg.type === "google_sheets" ? "apps_script_url" : "url";
      document.getElementById("int-url").value = intg.config[urlKey] || "";
      document.getElementById("int-status").textContent = `✅ ${intg.type} integration active`;
    }
  } catch (_) {}
  loadDevices(); loadPendingDevices();
}

function toggleIntFields() {
  document.getElementById("int-url-label").textContent =
    document.getElementById("int-type").value === "google_sheets" ? "Apps Script URL" : "Webhook URL";
}
function detectMyLocation() {
  navigator.geolocation?.getCurrentPosition(
    pos => { document.getElementById("geo-lat").value = pos.coords.latitude; document.getElementById("geo-lng").value = pos.coords.longitude; showToast("Location detected!", "success"); },
    () => showToast("Location access denied.", "error")
  );
}
async function saveGeofence() {
  const enabled = document.getElementById("geo-enabled").checked;
  const lat     = parseFloat(document.getElementById("geo-lat")?.value);
  const lng     = parseFloat(document.getElementById("geo-lng")?.value);
  const radius  = parseInt(document.getElementById("geo-radius")?.value || 200);
  if (enabled && (isNaN(lat)||isNaN(lng))) { showToast("Enter valid lat/lng.", "error"); return; }
  try {
    await apiFetch("/settings/geofence", { method: "PUT", body: JSON.stringify({ enabled, lat: enabled?lat:null, lng: enabled?lng:null, radius }) });
    document.getElementById("geo-saved-status").textContent = enabled ? `✅ ON: ${lat.toFixed(4)}, ${lng.toFixed(4)} (${radius}m)` : "✅ Geofencing disabled.";
    showToast(enabled ? "Geofence enabled!" : "Geofence disabled!", "success");
  } catch (err) { showToast(err.message, "error"); }
}
async function saveIntegration() {
  const type = document.getElementById("int-type").value;
  const url  = document.getElementById("int-url").value.trim();
  if (!url) { showToast("Please enter the URL.", "error"); return; }
  const configKey = type === "google_sheets" ? "apps_script_url" : "url";
  try { await apiFetch("/integrations", { method: "POST", body: JSON.stringify({ type, config: { [configKey]: url } }) }); document.getElementById("int-status").textContent = `✅ ${type} integration saved`; showToast("Integration saved!", "success"); }
  catch (err) { showToast(err.message, "error"); }
}
async function removeIntegration() {
  if (!confirm("Remove integration?")) return;
  try { await apiFetch("/integrations", { method: "DELETE" }); document.getElementById("int-status").textContent = ""; document.getElementById("int-url").value = ""; showToast("Integration removed.", "success"); }
  catch (err) { showToast(err.message, "error"); }
}

// ===== Grade helpers ========================================================
const GRADE_COLORS = { "Excellent":"#6dd28f","Good":"#3fc1c9","Fair":"#f0c040","Late":"#ff9f43","Very Late":"#ff6b6b","Absent":"#a0a0a0" };
function gradeChip(grade) {
  const color = GRADE_COLORS[grade] || "#fff";
  return `<span style="color:${color};font-weight:700;font-size:12px">${grade||"—"}</span>`;
}

// ===== Staff CRUD ===========================================================
function generateStaffId() { return `S-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).substring(2,5).toUpperCase()}`; }
function sanitize(str, maxLen=120) { return !str ? "" : String(str).replace(/<[^>]*>/g,"").trim().substring(0,maxLen); }

async function addStaff(name, email, phone) {
  const id = generateStaffId();
  await apiFetch("/staff", { method: "POST", body: JSON.stringify({ id, name, email, phone }) });
  showToast(`Staff '${name}' added (${id})`, "success");
  refreshDisplay();
}
async function updateStaff(id, name, email, phone) {
  await apiFetch(`/staff/${encodeURIComponent(id)}`, { method: "PUT", body: JSON.stringify({ name, email, phone }) });
  showToast(`Staff '${id}' updated`, "success"); refreshDisplay();
}
async function removeStaff(id) {
  if (!confirm(`Remove staff '${id}'?`)) return;
  await apiFetch(`/staff/${encodeURIComponent(id)}`, { method: "DELETE" });
  showToast(`Staff '${id}' removed`, "success"); refreshDisplay();
}

// ===== Attendance ===========================================================
async function recordAttendance(type, staffId, lat, lng) {
  const body = { staff_id: staffId, action: type };
  if (lat != null) body.lat = lat;
  if (lng != null) body.lng = lng;
  await apiFetch("/attendance", { method: "POST", body: JSON.stringify(body) });
  showToast(`${staffId} ${type === "check_in" ? "checked in" : "checked out"}`, "success");
  refreshDisplay();
  pushToIntegration({ staff_id: staffId, action: type, timestamp: new Date().toISOString(), lat, lng });
}
async function pushToIntegration(data) {
  try { await apiFetch("/integrations/push", { method: "POST", body: JSON.stringify(data) }); } catch (_) {}
}
async function listStaff()      { return apiFetch("/staff"); }
async function listAttendance() { return apiFetch("/attendance"); }

// ===== Rendering ============================================================
async function renderStaffOptions() {
  await ensureStaffCache();
  const current = document.getElementById("attendance-staff").value;
  // Search-based selection — no need to populate dropdown
  if (current) document.getElementById("selected-staff-display").textContent = `✅ Selected: ${current}`;
}

async function renderStaffTable() {
  const tbody = document.querySelector("#staff-table tbody");
  tbody.innerHTML = "";
  const staff = await listStaff();
  _allStaffCache = staff;
  staff.forEach(person => {
    const row = document.createElement("tr");
    [person.id, person.name, person.email||"—", person.phone||"—"].forEach(val => {
      const td = document.createElement("td"); td.textContent = val; row.appendChild(td);
    });
    tbody.appendChild(row);
  });
  document.getElementById("staff-count").textContent = `${staff.length} staff`;
}

let _cachedAttendance = [];
async function renderAttendanceTable() {
  const tbody = document.querySelector("#attendance-table tbody");
  tbody.innerHTML = "";
  const records = await listAttendance();
  _cachedAttendance = records;
  records.slice(0,50).forEach(record => {
    const date = new Date(record.timestamp+"Z");
    const row  = document.createElement("tr");
    [date.toLocaleDateString(), record.name?`${record.staff_id} • ${record.name}`:record.staff_id,
     record.action==="check_in"?"✅ Check In":"🚪 Check Out", date.toLocaleTimeString(), record.punctuality_grade||"—"
    ].forEach((val,i) => {
      const td = document.createElement("td");
      if (i===4 && record.punctuality_grade) td.innerHTML = gradeChip(record.punctuality_grade);
      else td.textContent = val;
      row.appendChild(td);
    });
    tbody.appendChild(row);
  });
  document.getElementById("attendance-count").textContent = `${records.length} entries`;
}

async function refreshDisplay() {
  try { await Promise.all([renderStaffTable(), renderAttendanceTable()]); }
  catch (err) { showToast(`Failed to load: ${err.message}`, "error"); }
}

// ===== Dashboard ============================================================
let trendChartInstance = null;
async function loadDashboard() {
  try {
    const analytics = await apiFetch("/analytics");
    document.getElementById("kpi-today").textContent   = analytics.today_checkins;
    document.getElementById("kpi-week").textContent    = analytics.week_checkins;
    document.getElementById("kpi-clocked").textContent = analytics.still_clocked_in.length;
    const staff = await listStaff();
    document.getElementById("kpi-staff").textContent   = staff.length;
    const labels = analytics.daily_trend.map(d => d.date.slice(5));
    const values = analytics.daily_trend.map(d => d.checkins);
    const ctx    = document.getElementById("trend-chart").getContext("2d");
    if (trendChartInstance) trendChartInstance.destroy();
    trendChartInstance = new Chart(ctx, {
      type: "line",
      data: { labels, datasets: [{ label: "Check-ins", data: values, borderColor: "#3fc1c9", backgroundColor: "rgba(63,193,201,0.1)", tension: 0.4, fill: true, pointBackgroundColor: "#3fc1c9", pointShadowBlur: 10 }] },
      options: { plugins: { legend: { labels: { color: "#eef4ff" } } }, scales: { x: { ticks: { color: "#9fb3d8" }, grid: { color: "rgba(255,255,255,0.05)" } }, y: { ticks: { color: "#9fb3d8" }, grid: { color: "rgba(255,255,255,0.05)" }, beginAtZero: true } } }
    });
    loadSummaryTable(currentDashPeriod);
  } catch (err) { showToast(`Dashboard error: ${err.message}`, "error"); }
}

async function loadSummaryTable(period) {
  try {
    const summary = await apiFetch(`/attendance/summary?period=${period}`);
    const stbody  = document.querySelector("#summary-table tbody");
    stbody.innerHTML = "";
    if (!summary.summaries.length) {
      stbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:20px">No data for this period.</td></tr>';
      return;
    }
    const daysMap = { daily:1, weekly:5, monthly:22, annual:260 };
    summary.summaries.forEach(s => {
      const row = document.createElement("tr");
      const pct = Math.min(100, Math.round((s.days_present / (daysMap[period]||5)) * 100));
      [`${s.staff_id} • ${s.name||"—"}`, `${s.total_hours}h`, s.days_present, gradeChip(s.grade), `${pct}%`].forEach((val,i) => {
        const td = document.createElement("td");
        if (i===3) td.innerHTML = val; else td.textContent = val;
        row.appendChild(td);
      });
      stbody.appendChild(row);
    });
  } catch (err) { showToast(`Summary error: ${err.message}`, "error"); }
}

// ===== Analytics ============================================================
let freqChartInstance = null, latenessChartInstance = null;
async function loadAnalytics() {
  try {
    const data = await apiFetch("/analytics");
    document.getElementById("ai-today").textContent    = data.today_checkins;
    document.getElementById("ai-week").textContent     = data.week_checkins;
    document.getElementById("ai-still-in").textContent = data.still_clocked_in.length;
    const avgH = data.avg_checkin_hour;
    document.getElementById("ai-avg-hr").textContent = avgH!=null ? `${Math.floor(avgH)}:${String(Math.round((avgH%1)*60)).padStart(2,"0")}` : "—";
    document.getElementById("top-performers").innerHTML = data.top_performers.length ? data.top_performers.map(p => `<li>🏅 ${p.name||p.staff_id} — ${p.sessions} sessions</li>`).join("") : "<li>No data yet</li>";
    document.getElementById("low-attendance").innerHTML = data.low_attendance.length  ? data.low_attendance.map(p  => `<li>⚠️ ${p.name||p.staff_id} — ${p.sessions} sessions</li>`).join("") : "<li>All attending regularly 🎉</li>";
    document.getElementById("still-clocked").innerHTML  = data.still_clocked_in.length ? data.still_clocked_in.map(p => `<li>🟢 ${p.name||p.staff_id}</li>`).join("") : "<li>Nobody clocked in</li>";
    const fLabels = data.attendance_frequency.map(p => p.name||p.staff_id);
    const fValues = data.attendance_frequency.map(p => p.sessions);
    const ctx2    = document.getElementById("freq-chart").getContext("2d");
    if (freqChartInstance) freqChartInstance.destroy();
    freqChartInstance = new Chart(ctx2, {
      type: "bar",
      data: { labels: fLabels, datasets: [{ label: "Sessions", data: fValues, backgroundColor: "rgba(63,193,201,0.6)", borderColor: "#3fc1c9", borderWidth: 1, borderRadius: 6 }] },
      options: { plugins: { legend: { labels: { color: "#eef4ff" } } }, scales: { x: { ticks: { color: "#9fb3d8" }, grid: { color: "rgba(255,255,255,0.05)" } }, y: { ticks: { color: "#9fb3d8" }, grid: { color: "rgba(255,255,255,0.05)" }, beginAtZero: true } } }
    });
    if (data.lateness_breakdown) {
      const lb = data.lateness_breakdown;
      const lLabels = ["Excellent","Good","Fair","Late","Very Late"];
      const lValues = lLabels.map(k => lb[k]||0);
      const lColors = ["#6dd28f","#3fc1c9","#f0c040","#ff9f43","#ff6b6b"];
      const ctx3    = document.getElementById("lateness-chart").getContext("2d");
      if (latenessChartInstance) latenessChartInstance.destroy();
      latenessChartInstance = new Chart(ctx3, {
        type: "doughnut",
        data: { labels: lLabels, datasets: [{ data: lValues, backgroundColor: lColors, borderWidth: 2, borderColor: "rgba(255,255,255,0.05)" }] },
        options: { plugins: { legend: { labels: { color: "#eef4ff", font: { size: 11 } } } }, cutout: "62%" }
      });
    }
  } catch (err) { showToast(`Analytics error: ${err.message}`, "error"); }
}

// ===== Reports ==============================================================
let _reportData = [];
async function generateReport() {
  const from  = document.getElementById("report-from").value;
  const to    = document.getElementById("report-to").value;
  const staff = document.getElementById("report-staff-id").value;
  let url = `/reports/attendance?from=${from||""}&to=${to||""}`;
  if (staff) url += `&staff_id=${encodeURIComponent(staff)}`;
  try { _reportData = await apiFetch(url); renderReportTable(_reportData); }
  catch (err) { showToast(`Report error: ${err.message}`, "error"); }
}
function renderReportTable(data) {
  const tbody = document.querySelector("#report-table tbody");
  tbody.innerHTML = "";
  data.forEach(r => {
    const date = new Date(r.timestamp+"Z");
    const row  = document.createElement("tr");
    [date.toLocaleDateString(), r.staff_id, r.name||"—", r.action==="check_in"?"✅ Check In":"🚪 Check Out", date.toLocaleTimeString(), r.punctuality_grade||"—"].forEach((val,i) => {
      const td = document.createElement("td");
      if (i===5 && r.punctuality_grade) td.innerHTML = gradeChip(r.punctuality_grade);
      else td.textContent = val;
      row.appendChild(td);
    });
    tbody.appendChild(row);
  });
  document.getElementById("report-count").textContent = `${data.length} records`;
}
function exportExcel(data, filename) {
  const rows = [["Date","Staff ID","Name","Action","Time","Status","Lat","Lng"]];
  (data||_reportData).forEach(r => {
    const date = new Date(r.timestamp+"Z");
    rows.push([date.toLocaleDateString(),r.staff_id,r.name||"",r.action,date.toLocaleTimeString(),r.punctuality_grade||"",r.lat||"",r.lng||""]);
  });
  const ws = XLSX.utils.aoa_to_sheet(rows);
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb,ws,"Attendance");
  XLSX.writeFile(wb, filename||"attendance-report.xlsx");
}
function exportPDF(data) {
  const rows = data||_reportData;
  const win  = window.open("","_blank");
  win.document.write(`<!DOCTYPE html><html><head><title>Attendance Report</title>
<style>body{font-family:sans-serif;padding:24px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:6px 10px;font-size:12px}th{background:#eee}</style></head>
<body><h2>Attendance Report</h2><table><thead><tr><th>Date</th><th>Staff ID</th><th>Name</th><th>Action</th><th>Time</th><th>Status</th></tr></thead><tbody>
${rows.map(r=>{const d=new Date(r.timestamp+"Z");return`<tr><td>${d.toLocaleDateString()}</td><td>${r.staff_id}</td><td>${r.name||""}</td><td>${r.action}</td><td>${d.toLocaleTimeString()}</td><td>${r.punctuality_grade||""}</td></tr>`;}).join("")}</tbody></table></body></html>`);
  win.document.close(); win.print();
}

// ===== View All =============================================================
let _viewAllData = [];
function openViewAll() { _viewAllData = [..._cachedAttendance]; renderViewAllTable(_viewAllData); openModal("viewall-modal"); }
function renderViewAllTable(data) {
  const tbody = document.querySelector("#viewall-table tbody");
  tbody.innerHTML = "";
  data.forEach(r => {
    const date = new Date(r.timestamp+"Z");
    const row  = document.createElement("tr");
    [date.toLocaleDateString(),r.staff_id,r.name||"—",r.action==="check_in"?"✅ Check In":"🚪 Check Out",date.toLocaleTimeString(),r.punctuality_grade||"—",r.lat?`${(+r.lat).toFixed(4)},${(+r.lng).toFixed(4)}`:"—"].forEach((val,i) => {
      const td = document.createElement("td");
      if (i===5 && r.punctuality_grade) td.innerHTML = gradeChip(r.punctuality_grade);
      else td.textContent = val;
      row.appendChild(td);
    });
    tbody.appendChild(row);
  });
  document.getElementById("viewall-count").textContent = `${data.length} entries`;
}
function filterViewAll() {
  const q = document.getElementById("viewall-search").value.toLowerCase();
  renderViewAllTable(_viewAllData.filter(r => (r.staff_id||"").toLowerCase().includes(q)||(r.name||"").toLowerCase().includes(q)));
}
function exportViewAllExcel() { exportExcel(_viewAllData,"attendance-full.xlsx"); }
function exportViewAllPDF()   { exportPDF(_viewAllData); }
document.getElementById("btn-close-viewall")?.addEventListener("click", closeModal);

// ===== Staff QR =============================================================
function renderStaffQR() {
  const staffId   = Auth.staffId;
  const container = document.getElementById("staff-qr-display");
  container.innerHTML = "";
  const wrapper = document.createElement("div");
  container.appendChild(wrapper);
  new QRCode(wrapper, { text: staffId, width: 220, height: 220, colorDark: "#000000", colorLight: "#ffffff", correctLevel: QRCode.CorrectLevel.H });
  setTimeout(() => {
    const img    = wrapper.querySelector("img");
    const canvas = wrapper.querySelector("canvas");
    const dl     = document.getElementById("staff-qr-download");
    if (img?.src) dl.href = img.src;
    else if (canvas) dl.href = canvas.toDataURL("image/png");
    dl.download = `qr-${staffId}.png`;
  }, 300);
}

// ===== Staff self-record ====================================================
async function staffSelfRecord(action) {
  const staffId = Auth.staffId;
  if (!staffId) { showToast("No staff ID linked.", "error"); return; }
  let lat = null, lng = null;
  if (staffGeoPos) { lat = staffGeoPos.coords.latitude; lng = staffGeoPos.coords.longitude; }
  const geofence = JSON.parse(sessionStorage.getItem("att_geofence") || "{}");
  if (geofence.enabled && geofence.lat && lat) {
    const dist = haversineM(geofence.lat, geofence.lng, lat, lng);
    if (dist > geofence.radius) { showToast(`Unable to ${action==="check_in"?"clock in":"clock out"} due to location mismatch.`, "error"); return; }
  }
  const sched = JSON.parse(sessionStorage.getItem("att_schedule") || "{}");
  const btn = document.getElementById(action==="check_in"?"btn-staff-checkin":"btn-staff-checkout");
  btn.disabled = true;
  try {
    await apiFetch("/attendance", { method: "POST", body: JSON.stringify({ action, lat, lng, shift: sched.night_checkin_time ? selectedShift : null }) });
    showToast(`${action==="check_in"?"Clocked in":"Clocked out"} successfully! 🎉`, "success");
    loadStaffSummary("daily");
    pushToIntegration({ staff_id: staffId, action, timestamp: new Date().toISOString(), lat, lng });
  } catch (err) { showToast(err.message, "error"); }
  finally { btn.disabled = false; }
}

function haversineM(lat1,lng1,lat2,lng2) {
  const R=6371000,dLat=(lat2-lat1)*Math.PI/180,dLng=(lng2-lng1)*Math.PI/180;
  const a=Math.sin(dLat/2)**2+Math.cos(lat1*Math.PI/180)*Math.cos(lat2*Math.PI/180)*Math.sin(dLng/2)**2;
  return 2*R*Math.atan2(Math.sqrt(a),Math.sqrt(1-a));
}

// ===== Staff summary ========================================================
async function loadStaffSummary(period) {
  ["daily","weekly","monthly","annual"].forEach(p => { document.getElementById(`sbtn-${p}`)?.classList.toggle("active", p===period); });
  try {
    const data = await apiFetch(`/attendance/summary?period=${period}`);
    const stats = document.getElementById("staff-summary-stats");
    if (!data.summaries.length) { stats.innerHTML = "<p class='hint'>No attendance data for this period.</p>"; }
    else {
      const s = data.summaries[0];
      const color = GRADE_COLORS[s.grade] || "#fff";
      const daysMap = { daily:1, weekly:5, monthly:22, annual:260 };
      const pct = Math.min(100, Math.round((s.days_present/(daysMap[period]||5))*100));
      stats.innerHTML = `
        <div class="summary-stat"><div class="summary-val">${s.total_hours}h</div><div class="summary-lbl">Hours</div></div>
        <div class="summary-stat"><div class="summary-val">${s.days_present}</div><div class="summary-lbl">Days Present</div></div>
        <div class="summary-stat"><div class="summary-val" style="color:${color}">${s.grade}</div><div class="summary-lbl">Punctuality</div></div>
        <div class="summary-stat"><div class="summary-val">${pct}%</div><div class="summary-lbl">Attendance %</div></div>
      `;
    }
    const records = await apiFetch("/attendance");
    const tbody   = document.querySelector("#staff-att-table tbody");
    tbody.innerHTML = "";
    records.slice(0,30).forEach(r => {
      const date = new Date(r.timestamp+"Z");
      const row  = document.createElement("tr");
      [date.toLocaleDateString(), r.action==="check_in"?"✅ Clock In":"🚪 Clock Out", date.toLocaleTimeString(), r.punctuality_grade||"—"].forEach((val,i) => {
        const td = document.createElement("td");
        if (i===3 && r.punctuality_grade) td.innerHTML = gradeChip(r.punctuality_grade);
        else td.textContent = val;
        row.appendChild(td);
      });
      tbody.appendChild(row);
    });
  } catch (err) { showToast(`Summary error: ${err.message}`, "error"); }
}

// ===== QR Scanner ===========================================================
let html5Scanner = null, scanType = null, availableCams = [];
async function startScan(type) {
  scanType = type;
  document.getElementById("scanner-title").textContent = type==="check_in" ? "📷 Scan QR – Check In" : "📷 Scan QR – Check Out";
  openModal("scanner-modal");
  document.getElementById("scanner-container").innerHTML = '<div id="qr-reader" style="width:100%"></div>';
  try {
    availableCams = await Html5Qrcode.getCameras();
    const camSel  = document.getElementById("camera-select");
    if (camSel && availableCams.length>0) {
      camSel.innerHTML = availableCams.map((c,i) => `<option value="${c.id}">${c.label||"Camera "+(i+1)}</option>`).join("");
      document.getElementById("camera-selector-row").classList.remove("hidden");
      const back = availableCams.find(c => /back|rear|environment/i.test(c.label));
      if (back) camSel.value = back.id;
    }
  } catch (_) {}
  launchScanner();
}
async function launchScanner() {
  if (html5Scanner) { await html5Scanner.stop().catch(()=>null); html5Scanner = null; }
  document.getElementById("scanner-container").innerHTML = '<div id="qr-reader" style="width:100%"></div>';
  html5Scanner = new Html5Qrcode("qr-reader");
  const camSel   = document.getElementById("camera-select");
  const cameraId = camSel?.value ? { deviceId: { exact: camSel.value } } : { facingMode: "environment" };
  html5Scanner.start(cameraId, { fps: 10, qrbox: { width:250, height:250 } }, async decodedText => {
    const staffId = sanitize(decodedText, 20);
    closeModal();
    let lat = null, lng = null;
    if (adminGeoPos) { lat = adminGeoPos.coords.latitude; lng = adminGeoPos.coords.longitude; }
    try { await withPin(async () => { await recordAttendance(scanType, staffId, lat, lng); }); }
    catch (err) { showToast(err.message, "error"); }
  }).catch(() => { showToast("Unable to start camera.", "error"); closeModal(); });
}
async function switchCamera() { await launchScanner(); }

// ===== QR Code ==============================================================
function showQrForStaff(staffId) {
  const qrPreview = document.getElementById("qr-preview");
  qrPreview.innerHTML = "";
  const wrapper = document.createElement("div");
  qrPreview.appendChild(wrapper);
  new QRCode(wrapper, { text: staffId, width:280, height:280, colorDark:"#000000", colorLight:"#ffffff", correctLevel: QRCode.CorrectLevel.H });
  setTimeout(() => {
    const img=wrapper.querySelector("img"), canvas=wrapper.querySelector("canvas"), dl=document.getElementById("download-qr");
    if (img?.src) dl.href=img.src; else if (canvas) dl.href=canvas.toDataURL("image/png");
    dl.download=`qr-${staffId}.png`;
  }, 300);
  openModal("qr-modal");
}

// ===== Modal helpers ========================================================
function closeModal() {
  document.getElementById("modal-overlay").classList.add("hidden");
  document.querySelectorAll(".modal").forEach(m => m.classList.add("hidden"));
  if (html5Scanner) { html5Scanner.stop().catch(()=>null); html5Scanner = null; }
}
function openModal(id) {
  document.getElementById("modal-overlay").classList.remove("hidden");
  document.getElementById(id).classList.remove("hidden");
}
document.getElementById("modal-overlay").addEventListener("click", e => {
  const pinOpen     = !document.getElementById("pin-modal").classList.contains("hidden");
  const deviceOpen  = !document.getElementById("device-modal").classList.contains("hidden");
  const signoutOpen = !document.getElementById("signout-modal").classList.contains("hidden");
  if (!pinOpen && !deviceOpen && !signoutOpen) closeModal();
});
document.getElementById("btn-close-scanner").addEventListener("click", closeModal);
document.getElementById("btn-close-qr").addEventListener("click",      closeModal);
document.getElementById("btn-stop-scanner").addEventListener("click",  closeModal);
document.addEventListener("keydown", e => {
  if (e.key==="Escape" && document.getElementById("pin-modal").classList.contains("hidden") &&
      document.getElementById("signout-modal").classList.contains("hidden")) closeModal();
});

// ===== Context Menu =========================================================
const staffTableBody = document.querySelector("#staff-table tbody");
const contextMenu    = document.getElementById("context-menu");
let contextTargetId  = null;
function showContextMenu(x,y,row) {
  staffTableBody.querySelectorAll("tr").forEach(r=>r.classList.remove("selected"));
  row.classList.add("selected");
  contextTargetId = row.children[0].textContent;
  contextMenu.style.top=`${Math.min(y,window.innerHeight-160)}px`;
  contextMenu.style.left=`${Math.min(x,window.innerWidth-190)}px`;
  contextMenu.classList.remove("hidden");
}
staffTableBody.addEventListener("contextmenu", e => { e.preventDefault(); const row=e.target.closest("tr"); if(row) showContextMenu(e.pageX,e.pageY,row); });
let longPressTimer=null;
staffTableBody.addEventListener("touchstart", e => { const row=e.target.closest("tr"); if(!row) return; longPressTimer=setTimeout(()=>{ const t=e.touches[0]; showContextMenu(t.pageX,t.pageY,row); },600); }, { passive:true });
staffTableBody.addEventListener("touchend",   ()=>clearTimeout(longPressTimer), { passive:true });
document.addEventListener("click", e => { if(!contextMenu.contains(e.target)) contextMenu.classList.add("hidden"); });
document.querySelectorAll("#context-menu button").forEach(btn => {
  btn.addEventListener("click", async e => {
    const action=e.currentTarget.dataset.action, id=contextTargetId;
    contextMenu.classList.add("hidden"); if (!id) return;
    if (action==="update") { try { const staff=await listStaff(), person=staff.find(s=>s.id===id); if(person) enterUpdateMode(person.id,person.name,person.email,person.phone); } catch(err){showToast(err.message,"error");} }
    if (action==="remove") { await withPin(async()=>{ await removeStaff(id); }); }
    if (action==="qr") showQrForStaff(id);
  });
});

// ===== Staff Form ===========================================================
document.getElementById("btn-submit-staff").addEventListener("click", async () => {
  const name=sanitize(document.getElementById("staff-name").value,80);
  const email=sanitize(document.getElementById("staff-email").value,120);
  const phone=sanitize(document.getElementById("staff-phone").value,30);
  if (!name) { showToast("Please enter a name.", "error"); return; }
  document.getElementById("btn-submit-staff").disabled = true;
  try {
    if (updateMode) { await withPin(async()=>{ await updateStaff(updateTargetId,name,email,phone); exitUpdateMode(); }); }
    else { await withPin(async()=>{ await addStaff(name,email,phone); ["staff-name","staff-email","staff-phone"].forEach(id=>document.getElementById(id).value=""); }); }
  } catch(err) { if(err.message!=="PIN cancelled") showToast(err.message,"error"); }
  finally { document.getElementById("btn-submit-staff").disabled=false; }
});
document.getElementById("btn-cancel-update").addEventListener("click", exitUpdateMode);
document.getElementById("btn-view-staff").addEventListener("click", async()=>{ await refreshDisplay(); loadDashboard(); showToast("Refreshed!","success"); });

// ===== Manual check-in with PIN ============================================
document.getElementById("btn-manual-checkin").addEventListener("click", () => {
  const staffId = document.getElementById("attendance-staff").value;
  if (!staffId) { showToast("Please select a staff member.", "error"); return; }
  withPin(async () => {
    let lat=null,lng=null;
    if (adminGeoPos) { lat=adminGeoPos.coords.latitude; lng=adminGeoPos.coords.longitude; }
    await recordAttendance("check_in", staffId, lat, lng);
  });
});
document.getElementById("btn-manual-checkout").addEventListener("click", () => {
  const staffId = document.getElementById("attendance-staff").value;
  if (!staffId) { showToast("Please select a staff member.", "error"); return; }
  withPin(async () => {
    let lat=null,lng=null;
    if (adminGeoPos) { lat=adminGeoPos.coords.latitude; lng=adminGeoPos.coords.longitude; }
    await recordAttendance("check_out", staffId, lat, lng);
  });
});
document.getElementById("btn-scan-checkin").addEventListener("click",  () => startScan("check_in"));
document.getElementById("btn-scan-checkout").addEventListener("click", () => startScan("check_out"));

// ===== Update Mode ==========================================================
let updateMode=false, updateTargetId=null;
function enterUpdateMode(staffId,name,email,phone) {
  updateMode=true; updateTargetId=staffId;
  document.getElementById("staff-name").value=name||""; document.getElementById("staff-email").value=email||""; document.getElementById("staff-phone").value=phone||""; document.getElementById("staff-id").value=staffId;
  document.getElementById("update-banner-id").textContent=staffId; document.getElementById("update-banner").classList.remove("hidden");
  document.getElementById("btn-submit-staff").textContent="Save Changes"; document.getElementById("staff-name").focus();
  switchMainTab("staff");
}
function exitUpdateMode() {
  updateMode=false; updateTargetId=null;
  ["staff-name","staff-email","staff-phone","staff-id"].forEach(id=>document.getElementById(id).value="");
  document.getElementById("update-banner").classList.add("hidden"); document.getElementById("btn-submit-staff").textContent="Add Staff";
}

// ===== Helpers ==============================================================
function esc(str) { return String(str??"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;"); }

// ===== Enter shortcuts ======================================================
document.getElementById("login-password").addEventListener("keydown",   e=>{ if(e.key==="Enter") handleLogin(); });
document.getElementById("reg-pin").addEventListener("keydown",          e=>{ if(e.key==="Enter") handleRegister(); });
document.getElementById("slogin-password")?.addEventListener("keydown", e=>{ if(e.key==="Enter") handleStaffLogin(); });

// ===== Report defaults ======================================================
(function() {
  const now=new Date(), to=now.toISOString().slice(0,10), from=new Date(now-30*86400000).toISOString().slice(0,10);
  const f=document.getElementById("report-from"), t=document.getElementById("report-to");
  if(f) f.value=from; if(t) t.value=to;
})();

// ===== Init =================================================================
if (Auth.isLoggedIn()) {
  if (Auth.role === "staff") showStaffShell();
  else showAppShell();
} else {
  const saved = sessionStorage.getItem("att_branding");
  if (saved) applyBranding(saved);
}

setInterval(()=>fetch(`${API_URL}/ping`).catch(()=>{}), 240000);
setInterval(()=>{
  if (!Auth.isLoggedIn()||Auth.role==="staff") return;
  if (currentMainTab==="dashboard")  loadDashboard();
  if (currentMainTab==="attendance") renderAttendanceTable();
}, 60000);