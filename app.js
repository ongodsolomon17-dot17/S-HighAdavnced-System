"use strict";

const API_URL = "https://s-high-adavnced-system.onrender.com";

// ====== Token / Auth Store ====================================================
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
    ["att_token","att_company","att_role","att_staff_id","att_staff_name"].forEach(k =>
      sessionStorage.removeItem(k));
  },
  isLoggedIn() { return !!this.token; }
};

// ===== Geolocation cache ====================================================
let cachedGeoPos = null;
function getGeoPos() {
  return new Promise((resolve, reject) => {
    if (!navigator.geolocation) { reject(new Error("Geolocation not supported")); return; }
    navigator.geolocation.getCurrentPosition(
      p => { cachedGeoPos = p; resolve(p); },
      e => reject(new Error("Location access denied")),
      { timeout: 8000 }
    );
  });
}

// ===== Toast ================================================================
let toastTimer = null;
function showToast(message, type = "success") {
  const toast = document.getElementById("toast");
  toast.textContent = message;
  toast.className = `toast ${type}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.add("hidden"), 3500);
}

// ===== API Fetch =============================================================
async function apiFetch(path, options = {}, requireAuth = true) {
  const headers = { "Content-Type": "application/json" };
  if (requireAuth) {
    if (!Auth.isLoggedIn()) { showAuthShell(); return; }
    headers["Authorization"] = `Bearer ${Auth.token}`;
  }
  const res  = await fetch(`${API_URL}${path}`, { headers, ...options });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) {
    Auth.clear();
    showAuthShell();
    throw new Error("Session expired. Please sign in again.");
  }
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

// ===== Auth mode / screen helpers ===========================================
let authMode = "admin";  // "admin" | "staff"
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
}

function showAppShell() {
  document.getElementById("auth-shell").classList.add("hidden");
  document.getElementById("app-shell").classList.remove("hidden");
  document.getElementById("staff-shell").classList.add("hidden");
  document.getElementById("company-name-display").textContent = Auth.company || "Your Company";
  refreshDisplay();
  loadDashboard();
}

function showStaffShell() {
  document.getElementById("auth-shell").classList.add("hidden");
  document.getElementById("app-shell").classList.add("hidden");
  document.getElementById("staff-shell").classList.remove("hidden");
  document.getElementById("staff-company-display").textContent = Auth.company || "Company";
  document.getElementById("staff-name-display").textContent = Auth.staffName || Auth.staffId || "Staff";
  renderStaffQR();
  loadStaffSummary("weekly");
  startStaffGeoWatch();
}

// ===== Main nav tab switching ================================================
let currentMainTab = "dashboard";
function switchMainTab(tab) {
  document.querySelectorAll(".nav-tab").forEach(b =>
    b.classList.toggle("active", b.dataset.tab === tab));
  document.querySelectorAll(".tab-panel").forEach(p =>
    p.classList.toggle("hidden", p.id !== `tab-${tab}`));
  currentMainTab = tab;
  if (tab === "analytics") loadAnalytics();
  if (tab === "reports")   populateReportStaffFilter();
  if (tab === "settings")  loadSettingsData();
}

// ===== Tab Switching (auth) =================================================
function switchTab(tab) {
  document.getElementById("form-login").classList.toggle("hidden",    tab !== "login");
  document.getElementById("form-register").classList.toggle("hidden", tab !== "register");
  document.getElementById("tab-login").classList.toggle("active",    tab === "login");
  document.getElementById("tab-register").classList.toggle("active", tab === "register");
  document.getElementById("auth-message").classList.add("hidden");
}

function showAuthMessage(msg, type = "error") {
  const el = document.getElementById("auth-message");
  el.textContent = msg;
  el.className   = `auth-message ${type}`;
}

function toggleEye(inputId, btn) {
  const inp = document.getElementById(inputId);
  if (inp.type === "password") { inp.type = "text";     btn.textContent = "🙈"; }
  else                         { inp.type = "password"; btn.textContent = "👁"; }
}

// ===== Password Strength ====================================================
document.getElementById("reg-password")?.addEventListener("input", function () {
  const pw = this.value;
  const el = document.getElementById("pw-strength");
  if (!pw) { el.textContent = ""; el.className = "pw-strength"; return; }
  let score = 0;
  if (pw.length >= 8)          score++;
  if (/[A-Z]/.test(pw))        score++;
  if (/[0-9]/.test(pw))        score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  const labels  = ["", "Weak", "Fair", "Good", "Strong"];
  const classes = ["", "pw-weak", "pw-fair", "pw-good", "pw-strong"];
  el.textContent = labels[score] || "Weak";
  el.className   = `pw-strength ${classes[score] || "pw-weak"}`;
});

// ===== Register (admin) =====================================================
async function handleRegister() {
  const company  = document.getElementById("reg-company").value.trim();
  const email    = document.getElementById("reg-email").value.trim();
  const phone    = document.getElementById("reg-phone").value.trim();
  const password = document.getElementById("reg-password").value;
  const password2= document.getElementById("reg-password2").value;
  const pin      = document.getElementById("reg-pin").value.trim();

  if (!company)              { showAuthMessage("Please enter your company/organisation name."); return; }
  if (!email)                { showAuthMessage("Please enter your email address."); return; }
  if (password.length < 8)   { showAuthMessage("Password must be at least 8 characters."); return; }
  if (password !== password2){ showAuthMessage("Passwords do not match."); return; }
  if (!/^\d{4,8}$/.test(pin)){ showAuthMessage("PIN must be 4–8 digits."); return; }

  const btn = document.getElementById("btn-register");
  const sp  = document.getElementById("register-spinner");
  btn.disabled = true; sp.classList.remove("hidden");
  try {
    const res = await apiFetch("/auth/register", {
      method: "POST",
      body: JSON.stringify({ company, email, phone, password, pin })
    }, false);
    Auth.set(res.token, res.company, "admin");
    showAppShell();
    showToast(`Welcome to S Advanced Attendance, ${res.company}!`, "success");
  } catch (err) {
    showAuthMessage(err.message);
  } finally {
    btn.disabled = false; sp.classList.add("hidden");
  }
}

// ===== Login (admin) ========================================================
async function handleLogin() {
  const email    = document.getElementById("login-email").value.trim();
  const password = document.getElementById("login-password").value;
  if (!email || !password) { showAuthMessage("Please enter your email and password."); return; }

  const btn = document.getElementById("btn-login");
  const sp  = document.getElementById("login-spinner");
  btn.disabled = true; sp.classList.remove("hidden");
  try {
    const res = await apiFetch("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password })
    }, false);
    Auth.set(res.token, res.company, "admin");
    showAppShell();
    showToast(`Welcome back, ${res.company}!`, "success");
  } catch (err) {
    showAuthMessage(err.message);
  } finally {
    btn.disabled = false; sp.classList.add("hidden");
  }
}

// ===== Staff login ===========================================================
async function handleStaffLogin() {
  const email    = document.getElementById("slogin-email").value.trim();
  const password = document.getElementById("slogin-password").value;
  if (!email || !password) { showAuthMessage("Please enter email and password."); return; }

  const btn = document.getElementById("btn-staff-login");
  const sp  = document.getElementById("staff-login-spinner");
  btn.disabled = true; sp.classList.remove("hidden");
  try {
    const res = await apiFetch("/auth/staff-login", {
      method: "POST",
      body: JSON.stringify({ email, password })
    }, false);
    Auth.set(res.token, res.company, "staff", res.staff_id, res.name);
    // Store geofence info for client-side reference
    if (res.geofence) sessionStorage.setItem("att_geofence", JSON.stringify(res.geofence));
    showStaffShell();
    showToast(`Welcome, ${res.name}!`, "success");
  } catch (err) {
    showAuthMessage(err.message);
  } finally {
    btn.disabled = false; sp.classList.add("hidden");
  }
}

// ===== Staff register (link to company) =====================================
async function handleStaffRegister() {
  const company_email = document.getElementById("sreg-company-email").value.trim();
  const staff_id      = document.getElementById("sreg-staffid").value.trim();
  const email         = document.getElementById("sreg-email").value.trim();
  const password      = document.getElementById("sreg-password").value;

  if (!company_email || !staff_id || !email || !password) {
    showAuthMessage("Please fill in all fields."); return;
  }
  if (password.length < 8) { showAuthMessage("Password must be at least 8 characters."); return; }

  const btn = document.getElementById("btn-staff-register");
  const sp  = document.getElementById("staff-reg-spinner");
  btn.disabled = true; sp.classList.remove("hidden");
  try {
    await apiFetch("/auth/staff-register", {
      method: "POST",
      body: JSON.stringify({ company_email, staff_id, email, password })
    }, false);
    showAuthMessage("Account linked! You can now sign in.", "success");
    switchStaffTab("login");
  } catch (err) {
    showAuthMessage(err.message);
  } finally {
    btn.disabled = false; sp.classList.add("hidden");
  }
}

// ===== Logout ===============================================================
function handleLogout() {
  Auth.clear();
  showAuthShell();
  switchTab("login");
  showToast("Signed out successfully.", "success");
}

// ===== PIN Modal ============================================================
let pinResolve = null;
let pinReject  = null;

function requestPin() {
  return new Promise((resolve, reject) => {
    pinResolve = resolve;
    pinReject  = reject;
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
  if (e.target.value && idx < boxes.length - 1) boxes[idx + 1].focus();
});

document.getElementById("pin-inputs").addEventListener("keydown", e => {
  if (!e.target.classList.contains("pin-box")) return;
  const boxes = [...document.querySelectorAll(".pin-box")];
  const idx   = boxes.indexOf(e.target);
  if (e.key === "Backspace" && !e.target.value && idx > 0) boxes[idx - 1].focus();
  if (e.key === "Enter") confirmPin();
});

async function confirmPin() {
  const pin = [...document.querySelectorAll(".pin-box")].map(b => b.value).join("");
  if (pin.length < 4) {
    document.getElementById("pin-error").textContent = "Please enter your full PIN.";
    document.getElementById("pin-error").classList.remove("hidden");
    return;
  }
  const btn = document.getElementById("btn-confirm-pin");
  btn.disabled = true;
  try {
    await apiFetch("/auth/verify-pin", { method: "POST", body: JSON.stringify({ pin }) });
    closeModal();
    if (pinResolve) pinResolve(true);
  } catch (err) {
    document.getElementById("pin-error").textContent = "Incorrect PIN. Try again.";
    document.getElementById("pin-error").classList.remove("hidden");
    document.querySelectorAll(".pin-box").forEach(b => b.value = "");
    document.querySelector(".pin-box").focus();
  } finally {
    btn.disabled = false;
  }
}

document.getElementById("btn-confirm-pin").addEventListener("click", confirmPin);
document.getElementById("btn-close-pin").addEventListener("click",  () => {
  closeModal(); if (pinReject) pinReject(new Error("PIN cancelled"));
});
document.getElementById("btn-close-pin2").addEventListener("click", () => {
  closeModal(); if (pinReject) pinReject(new Error("PIN cancelled"));
});

async function withPin(action) {
  try {
    await requestPin();
    await action();
  } catch (err) {
    if (err.message !== "PIN cancelled") showToast(err.message, "error");
  }
}

// ===== Staff ID =============================================================
function generateStaffId() {
  const ts   = Date.now().toString(36).toUpperCase();
  const rand = Math.random().toString(36).substring(2, 5).toUpperCase();
  return `S-${ts}-${rand}`;
}

function sanitize(str, maxLen = 120) {
  if (!str) return "";
  return String(str).replace(/<[^>]*>/g, "").trim().substring(0, maxLen);
}

// ===== Staff CRUD ===========================================================
async function addStaff(name, email, phone) {
  const id = generateStaffId();
  await apiFetch("/staff", {
    method: "POST",
    body: JSON.stringify({ id, name, email, phone })
  });
  showToast(`Staff '${name}' added (${id})`, "success");
  refreshDisplay();
}

async function updateStaff(id, name, email, phone) {
  await apiFetch(`/staff/${encodeURIComponent(id)}`, {
    method: "PUT",
    body: JSON.stringify({ name, email, phone })
  });
  showToast(`Staff '${id}' updated`, "success");
  refreshDisplay();
}

async function removeStaff(id) {
  if (!confirm(`Remove staff '${id}'? Their attendance records will also be deleted.`)) return;
  await apiFetch(`/staff/${encodeURIComponent(id)}`, { method: "DELETE" });
  showToast(`Staff '${id}' removed`, "success");
  refreshDisplay();
}

// ===== Attendance ===========================================================
async function recordAttendance(type, staffId, lat, lng) {
  const body = { staff_id: staffId, action: type };
  if (lat != null) body.lat = lat;
  if (lng != null) body.lng = lng;
  await apiFetch("/attendance", { method: "POST", body: JSON.stringify(body) });
  const label = type === "check_in" ? "checked in" : "checked out";
  showToast(`${staffId} ${label}`, "success");
  refreshDisplay();
  // Auto-push to external integration
  pushToIntegration({ staff_id: staffId, action: type, timestamp: new Date().toISOString(), lat, lng });
}

// ===== External integration push (fire & forget) ============================
async function pushToIntegration(data) {
  try {
    await apiFetch("/integrations/push", { method: "POST", body: JSON.stringify(data) });
  } catch (_) { /* silent — integration errors shouldn't break UI */ }
}

// ===== Fetch Helpers ========================================================
async function listStaff()      { return apiFetch("/staff"); }
async function listAttendance() { return apiFetch("/attendance"); }

// ===== Rendering ============================================================
async function renderStaffOptions() {
  const select  = document.getElementById("attendance-staff");
  const rs      = document.getElementById("report-staff");
  const current = select.value;
  select.innerHTML = '<option value="">-- select staff --</option>';
  if (rs) rs.innerHTML = '<option value="">All staff</option>';
  const staff = await listStaff();
  staff.forEach(person => {
    [select, rs].forEach(sel => {
      if (!sel) return;
      const opt = document.createElement("option");
      opt.value       = person.id;
      opt.textContent = `${person.id} • ${sanitize(person.name)}`;
      sel.appendChild(opt);
    });
  });
  if (current) select.value = current;
}

async function renderStaffTable() {
  const tbody = document.querySelector("#staff-table tbody");
  tbody.innerHTML = "";
  const staff = await listStaff();
  staff.forEach(person => {
    const row = document.createElement("tr");
    [person.id, person.name, person.email || "—", person.phone || "—"].forEach(val => {
      const td = document.createElement("td");
      td.textContent = val;
      row.appendChild(td);
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
  records.slice(0, 50).forEach(record => {
    const date = new Date(record.timestamp + "Z");
    const row  = document.createElement("tr");
    [
      date.toLocaleDateString(),
      record.name ? `${record.staff_id} • ${record.name}` : record.staff_id,
      record.action === "check_in" ? "✅ Check In" : "🚪 Check Out",
      date.toLocaleTimeString()
    ].forEach(val => {
      const td = document.createElement("td");
      td.textContent = val;
      row.appendChild(td);
    });
    tbody.appendChild(row);
  });
  document.getElementById("attendance-count").textContent = `${records.length} entries`;
}

async function refreshDisplay() {
  try {
    await Promise.all([
      renderStaffOptions(),
      renderStaffTable(),
      renderAttendanceTable()
    ]);
  } catch (err) {
    showToast(`Failed to load data: ${err.message}`, "error");
  }
}

// ===== Dashboard ============================================================
let trendChartInstance = null;
async function loadDashboard() {
  try {
    const analytics = await apiFetch("/analytics");
    document.getElementById("kpi-today").textContent   = analytics.today_checkins;
    document.getElementById("kpi-week").textContent    = analytics.week_checkins;
    document.getElementById("kpi-clocked").textContent = analytics.still_clocked_in.length;

    // Staff count from existing data
    const staff = await listStaff();
    document.getElementById("kpi-staff").textContent = staff.length;

    // Trend chart
    const labels = analytics.daily_trend.map(d => d.date.slice(5));
    const values = analytics.daily_trend.map(d => d.checkins);
    const ctx    = document.getElementById("trend-chart").getContext("2d");
    if (trendChartInstance) trendChartInstance.destroy();
    trendChartInstance = new Chart(ctx, {
      type: "line",
      data: {
        labels,
        datasets: [{
          label: "Check-ins",
          data: values,
          borderColor: "#3fc1c9",
          backgroundColor: "rgba(63,193,201,0.12)",
          tension: 0.4,
          fill: true,
          pointBackgroundColor: "#3fc1c9"
        }]
      },
      options: {
        plugins: { legend: { labels: { color: "#eef4ff" } } },
        scales: {
          x: { ticks: { color: "#bfc9e3" }, grid: { color: "rgba(255,255,255,0.06)" } },
          y: { ticks: { color: "#bfc9e3" }, grid: { color: "rgba(255,255,255,0.06)" }, beginAtZero: true }
        }
      }
    });

    // Weekly summary
    const summary = await apiFetch("/attendance/summary?period=weekly");
    const stbody  = document.querySelector("#summary-table tbody");
    stbody.innerHTML = "";
    summary.summaries.forEach(s => {
      const row = document.createElement("tr");
      const gradeColor = { A:"#6dd28f", B:"#3fc1c9", C:"#f0c040", D:"#ff9f43", F:"#ff6b6b" }[s.grade] || "#fff";
      [
        `${s.staff_id} • ${s.name || "—"}`,
        `${s.total_hours}h`,
        s.days_present,
        `<span style="color:${gradeColor};font-weight:700">${s.grade}</span>`,
        `${s.pct}%`
      ].forEach((val, i) => {
        const td = document.createElement("td");
        if (i === 3) td.innerHTML = val;
        else td.textContent = val;
        row.appendChild(td);
      });
      stbody.appendChild(row);
    });
  } catch (err) {
    showToast(`Dashboard error: ${err.message}`, "error");
  }
}

// ===== AI Analytics =========================================================
let freqChartInstance = null;
async function loadAnalytics() {
  try {
    const data = await apiFetch("/analytics");
    document.getElementById("ai-today").textContent    = data.today_checkins;
    document.getElementById("ai-week").textContent     = data.week_checkins;
    document.getElementById("ai-still-in").textContent = data.still_clocked_in.length;
    const avgH = data.avg_checkin_hour;
    document.getElementById("ai-avg-hr").textContent   = avgH != null
      ? `${Math.floor(avgH)}:${String(Math.round((avgH%1)*60)).padStart(2,"0")}`
      : "—";

    const top  = document.getElementById("top-performers");
    const low  = document.getElementById("low-attendance");
    const still = document.getElementById("still-clocked");

    top.innerHTML  = data.top_performers.length
      ? data.top_performers.map(p => `<li>🏅 ${p.name || p.staff_id} — ${p.sessions} sessions</li>`).join("")
      : "<li>No data yet</li>";
    low.innerHTML  = data.low_attendance.length
      ? data.low_attendance.map(p => `<li>⚠️ ${p.name || p.staff_id} — ${p.sessions} sessions</li>`).join("")
      : "<li>All staff are attending regularly 🎉</li>";
    still.innerHTML = data.still_clocked_in.length
      ? data.still_clocked_in.map(p => `<li>🟢 ${p.name || p.staff_id} (${p.staff_id})</li>`).join("")
      : "<li>Nobody currently clocked in</li>";

    // Frequency bar chart
    const labels = data.attendance_frequency.map(p => p.name || p.staff_id);
    const values = data.attendance_frequency.map(p => p.sessions);
    const ctx2   = document.getElementById("freq-chart").getContext("2d");
    if (freqChartInstance) freqChartInstance.destroy();
    freqChartInstance = new Chart(ctx2, {
      type: "bar",
      data: {
        labels,
        datasets: [{
          label: "Check-in sessions",
          data: values,
          backgroundColor: "rgba(63,193,201,0.65)",
          borderColor: "#3fc1c9",
          borderWidth: 1,
          borderRadius: 6
        }]
      },
      options: {
        plugins: { legend: { labels: { color: "#eef4ff" } } },
        scales: {
          x: { ticks: { color: "#bfc9e3" }, grid: { color: "rgba(255,255,255,0.06)" } },
          y: { ticks: { color: "#bfc9e3" }, grid: { color: "rgba(255,255,255,0.06)" }, beginAtZero: true }
        }
      }
    });
  } catch (err) {
    showToast(`Analytics error: ${err.message}`, "error");
  }
}

// ===== Reports ==============================================================
let _reportData = [];

function populateReportStaffFilter() {
  // already populated in renderStaffOptions
}

async function generateReport() {
  const from  = document.getElementById("report-from").value;
  const to    = document.getElementById("report-to").value;
  const staff = document.getElementById("report-staff").value;
  let url = `/reports/attendance?from=${from || ""}&to=${to || ""}`;
  if (staff) url += `&staff_id=${encodeURIComponent(staff)}`;
  try {
    _reportData = await apiFetch(url);
    renderReportTable(_reportData);
  } catch (err) {
    showToast(`Report error: ${err.message}`, "error");
  }
}

function renderReportTable(data) {
  const tbody = document.querySelector("#report-table tbody");
  tbody.innerHTML = "";
  data.forEach(r => {
    const date = new Date(r.timestamp + "Z");
    const row  = document.createElement("tr");
    [
      date.toLocaleDateString(),
      r.staff_id,
      r.name || "—",
      r.action === "check_in" ? "✅ Check In" : "🚪 Check Out",
      date.toLocaleTimeString()
    ].forEach(val => {
      const td = document.createElement("td");
      td.textContent = val;
      row.appendChild(td);
    });
    tbody.appendChild(row);
  });
  document.getElementById("report-count").textContent = `${data.length} records`;
}

function buildExcelSheet(data) {
  const rows = [["Date","Staff ID","Name","Action","Time","Lat","Lng"]];
  data.forEach(r => {
    const date = new Date(r.timestamp + "Z");
    rows.push([
      date.toLocaleDateString(), r.staff_id, r.name || "",
      r.action, date.toLocaleTimeString(), r.lat || "", r.lng || ""
    ]);
  });
  return rows;
}

function exportExcel(data, filename) {
  const rows = buildExcelSheet(data || _reportData);
  const ws   = XLSX.utils.aoa_to_sheet(rows);
  const wb   = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, "Attendance");
  XLSX.writeFile(wb, filename || "attendance-report.xlsx");
}

function exportPDF(data, filename) {
  const rows = data || _reportData;
  const win  = window.open("", "_blank");
  const html = `<!DOCTYPE html><html><head><title>Attendance Report</title>
<style>body{font-family:sans-serif;padding:24px}table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ccc;padding:6px 10px;font-size:13px}th{background:#eee}</style></head>
<body><h2>Attendance Report</h2>
<table><thead><tr><th>Date</th><th>Staff ID</th><th>Name</th><th>Action</th><th>Time</th></tr></thead>
<tbody>${rows.map(r => {
    const d = new Date(r.timestamp + "Z");
    return `<tr><td>${d.toLocaleDateString()}</td><td>${r.staff_id}</td><td>${r.name||""}</td>
    <td>${r.action}</td><td>${d.toLocaleTimeString()}</td></tr>`;
  }).join("")}</tbody></table></body></html>`;
  win.document.write(html);
  win.document.close();
  win.print();
}

// ===== View All Entries ======================================================
let _viewAllData = [];
function openViewAll() {
  _viewAllData = [..._cachedAttendance];
  renderViewAllTable(_viewAllData);
  openModal("viewall-modal");
}

function renderViewAllTable(data) {
  const tbody = document.querySelector("#viewall-table tbody");
  tbody.innerHTML = "";
  data.forEach(r => {
    const date = new Date(r.timestamp + "Z");
    const row  = document.createElement("tr");
    [
      date.toLocaleDateString(),
      r.staff_id,
      r.name || "—",
      r.action === "check_in" ? "✅ Check In" : "🚪 Check Out",
      date.toLocaleTimeString(),
      r.lat ? `${(+r.lat).toFixed(4)}, ${(+r.lng).toFixed(4)}` : "—"
    ].forEach(val => {
      const td = document.createElement("td");
      td.textContent = val;
      row.appendChild(td);
    });
    tbody.appendChild(row);
  });
  document.getElementById("viewall-count").textContent = `${data.length} entries`;
}

function filterViewAll() {
  const q = document.getElementById("viewall-search").value.toLowerCase();
  const filtered = _viewAllData.filter(r =>
    (r.staff_id||"").toLowerCase().includes(q) ||
    (r.name||"").toLowerCase().includes(q)
  );
  renderViewAllTable(filtered);
}

function exportViewAllExcel() { exportExcel(_viewAllData, "attendance-full.xlsx"); }
function exportViewAllPDF()   { exportPDF(_viewAllData); }

function openIntegrationFromViewAll() {
  closeModal();
  switchMainTab("settings");
}

document.getElementById("btn-close-viewall")?.addEventListener("click", closeModal);

// ===== Settings =============================================================
async function loadSettingsData() {
  // Load geofence
  try {
    const profile = await apiFetch("/auth/profile");
    if (profile.geofence_lat) {
      document.getElementById("geo-lat").value    = profile.geofence_lat;
      document.getElementById("geo-lng").value    = profile.geofence_lng;
      document.getElementById("geo-radius").value = profile.geofence_radius || 200;
      document.getElementById("geo-saved-status").textContent =
        `✅ Active fence: ${profile.geofence_lat.toFixed(4)}, ${profile.geofence_lng.toFixed(4)} (${profile.geofence_radius}m)`;
    }
  } catch (_) {}

  // Load integration
  try {
    const intg = await apiFetch("/integrations");
    if (intg) {
      document.getElementById("int-type").value = intg.type;
      const urlKey = intg.type === "google_sheets" ? "apps_script_url" : "url";
      document.getElementById("int-url").value = intg.config[urlKey] || "";
      document.getElementById("int-url-label").textContent =
        intg.type === "google_sheets" ? "Apps Script URL" : "Webhook URL";
      document.getElementById("int-status").textContent =
        `✅ ${intg.type === "google_sheets" ? "Google Sheets" : "Webhook"} integration active`;
    }
  } catch (_) {}
}

function toggleIntFields() {
  const type = document.getElementById("int-type").value;
  const label = document.getElementById("int-url-label");
  label.textContent = type === "google_sheets" ? "Apps Script URL" : "Webhook URL";
}

function detectMyLocation() {
  getGeoPos().then(pos => {
    document.getElementById("geo-lat").value = pos.coords.latitude;
    document.getElementById("geo-lng").value = pos.coords.longitude;
    showToast("Location detected!", "success");
  }).catch(err => showToast(err.message, "error"));
}

async function saveGeofence() {
  const lat    = parseFloat(document.getElementById("geo-lat").value);
  const lng    = parseFloat(document.getElementById("geo-lng").value);
  const radius = parseInt(document.getElementById("geo-radius").value);
  if (isNaN(lat) || isNaN(lng)) { showToast("Enter valid latitude and longitude.", "error"); return; }
  try {
    await apiFetch("/settings/geofence", {
      method: "PUT",
      body: JSON.stringify({ lat, lng, radius })
    });
    document.getElementById("geo-saved-status").textContent =
      `✅ Saved: ${lat.toFixed(4)}, ${lng.toFixed(4)} (${radius}m)`;
    showToast("Geofence saved!", "success");
  } catch (err) {
    showToast(err.message, "error");
  }
}

async function saveIntegration() {
  const type = document.getElementById("int-type").value;
  const url  = document.getElementById("int-url").value.trim();
  if (!url) { showToast("Please enter the URL.", "error"); return; }
  const configKey = type === "google_sheets" ? "apps_script_url" : "url";
  try {
    await apiFetch("/integrations", {
      method: "POST",
      body: JSON.stringify({ type, config: { [configKey]: url } })
    });
    document.getElementById("int-status").textContent =
      `✅ ${type === "google_sheets" ? "Google Sheets" : "Webhook"} integration saved`;
    showToast("Integration saved!", "success");
  } catch (err) {
    showToast(err.message, "error");
  }
}

async function removeIntegration() {
  if (!confirm("Remove external integration?")) return;
  try {
    await apiFetch("/integrations", { method: "DELETE" });
    document.getElementById("int-status").textContent = "";
    document.getElementById("int-url").value = "";
    showToast("Integration removed.", "success");
  } catch (err) {
    showToast(err.message, "error");
  }
}

// ===== Staff QR (staff portal) ==============================================
function renderStaffQR() {
  const staffId   = Auth.staffId;
  const container = document.getElementById("staff-qr-display");
  container.innerHTML = "";
  const wrapper = document.createElement("div");
  container.appendChild(wrapper);
  new QRCode(wrapper, {
    text: staffId, width: 220, height: 220,
    colorDark: "#000000", colorLight: "#ffffff",
    correctLevel: QRCode.CorrectLevel.H
  });
  setTimeout(() => {
    const img    = wrapper.querySelector("img");
    const canvas = wrapper.querySelector("canvas");
    const dl     = document.getElementById("staff-qr-download");
    if (img?.src)  dl.href = img.src;
    else if (canvas) dl.href = canvas.toDataURL("image/png");
    dl.download = `qr-${staffId}.png`;
  }, 300);
}

// ===== Staff self-record (geofenced) ========================================
let staffGeoPos = null;
function startStaffGeoWatch() {
  const statusEl = document.getElementById("geo-status-staff");
  if (!navigator.geolocation) {
    statusEl.textContent = "📍 Geolocation not supported — location not verified";
    return;
  }
  navigator.geolocation.watchPosition(
    pos => {
      staffGeoPos = pos;
      statusEl.textContent = `📍 Location active (${pos.coords.accuracy.toFixed(0)}m accuracy)`;
    },
    () => { statusEl.textContent = "⚠️ Location unavailable — check browser permissions"; },
    { enableHighAccuracy: true }
  );
}

async function staffSelfRecord(action) {
  const staffId = Auth.staffId;
  if (!staffId) { showToast("No staff ID linked.", "error"); return; }
  let lat = null, lng = null;
  if (staffGeoPos) {
    lat = staffGeoPos.coords.latitude;
    lng = staffGeoPos.coords.longitude;
  }
  const btn = document.getElementById(action === "check_in" ? "btn-staff-checkin" : "btn-staff-checkout");
  btn.disabled = true;
  try {
    const body = { action, lat, lng };
    await apiFetch("/attendance", { method: "POST", body: JSON.stringify(body) });
    const label = action === "check_in" ? "Clocked in" : "Clocked out";
    showToast(`${label} successfully! 🎉`, "success");
    loadStaffSummary("daily");
    // Push to external integration
    pushToIntegration({ staff_id: staffId, action, timestamp: new Date().toISOString(), lat, lng });
  } catch (err) {
    showToast(err.message, "error");
  } finally {
    btn.disabled = false;
  }
}

// ===== Staff summary (staff portal) =========================================
async function loadStaffSummary(period) {
  ["weekly","daily"].forEach(p => {
    document.getElementById(`sbtn-${p}`)?.classList.toggle("active", p === period);
  });
  try {
    const data = await apiFetch(`/attendance/summary?period=${period}`);
    const stats = document.getElementById("staff-summary-stats");
    if (data.summaries.length === 0) {
      stats.innerHTML = "<p class='hint'>No attendance data for this period.</p>";
    } else {
      const s = data.summaries[0];
      const gradeColor = { A:"#6dd28f", B:"#3fc1c9", C:"#f0c040", D:"#ff9f43", F:"#ff6b6b" }[s.grade] || "#fff";
      stats.innerHTML = `
        <div class="summary-stat"><div class="summary-val">${s.total_hours}h</div><div class="summary-lbl">Hours</div></div>
        <div class="summary-stat"><div class="summary-val">${s.days_present}</div><div class="summary-lbl">Days Present</div></div>
        <div class="summary-stat"><div class="summary-val" style="color:${gradeColor}">${s.grade}</div><div class="summary-lbl">Grade</div></div>
        <div class="summary-stat"><div class="summary-val">${s.pct}%</div><div class="summary-lbl">of Expected</div></div>
      `;
    }

    // Attendance table
    const records = await apiFetch("/attendance");
    const tbody   = document.querySelector("#staff-att-table tbody");
    tbody.innerHTML = "";
    records.slice(0, 30).forEach(r => {
      const date = new Date(r.timestamp + "Z");
      const row  = document.createElement("tr");
      [
        date.toLocaleDateString(),
        r.action === "check_in" ? "✅ Clock In" : "🚪 Clock Out",
        date.toLocaleTimeString()
      ].forEach(val => {
        const td = document.createElement("td");
        td.textContent = val;
        row.appendChild(td);
      });
      tbody.appendChild(row);
    });
  } catch (err) {
    showToast(`Summary error: ${err.message}`, "error");
  }
}

// ===== QR Code ==============================================================
function showQrForStaff(staffId) {
  const qrPreview = document.getElementById("qr-preview");
  qrPreview.innerHTML = "";
  const wrapper = document.createElement("div");
  qrPreview.appendChild(wrapper);
  new QRCode(wrapper, {
    text: staffId, width: 280, height: 280,
    colorDark: "#000000", colorLight: "#ffffff",
    correctLevel: QRCode.CorrectLevel.H
  });
  setTimeout(() => {
    const img    = wrapper.querySelector("img");
    const canvas = wrapper.querySelector("canvas");
    const dl     = document.getElementById("download-qr");
    if (img?.src)  dl.href = img.src;
    else if (canvas) dl.href = canvas.toDataURL("image/png");
    dl.download = `qr-${staffId}.png`;
  }, 300);
  openModal("qr-modal");
}

// ===== QR Scanner ===========================================================
let html5Scanner = null;
function startScan(type) {
  document.getElementById("scanner-title").textContent =
    type === "check_in" ? "📷 Scan QR – Check In" : "📷 Scan QR – Check Out";
  openModal("scanner-modal");
  const container = document.getElementById("scanner-container");
  container.innerHTML = '<div id="qr-reader" style="width:100%"></div>';
  html5Scanner = new Html5Qrcode("qr-reader");
  html5Scanner.start(
    { facingMode: "environment" },
    { fps: 10, qrbox: { width: 250, height: 250 } },
    async decodedText => {
      const staffId = sanitize(decodedText, 20);
      closeModal();
      try { await recordAttendance(type, staffId, null, null); }
      catch (err) { showToast(err.message, "error"); }
    }
  ).catch(() => {
    showToast("Unable to start camera. Check permissions.", "error");
    closeModal();
  });
}

// ===== Modal Helpers ========================================================
function closeModal() {
  document.getElementById("modal-overlay").classList.add("hidden");
  document.querySelectorAll(".modal").forEach(m => m.classList.add("hidden"));
  if (html5Scanner) {
    html5Scanner.stop().catch(() => null);
    html5Scanner = null;
  }
}

function openModal(id) {
  document.getElementById("modal-overlay").classList.remove("hidden");
  document.getElementById(id).classList.remove("hidden");
}

document.getElementById("modal-overlay").addEventListener("click", e => {
  if (!document.getElementById("pin-modal").classList.contains("hidden")) return;
  closeModal();
});
document.getElementById("btn-close-scanner").addEventListener("click", closeModal);
document.getElementById("btn-close-qr").addEventListener("click",      closeModal);
document.getElementById("btn-stop-scanner").addEventListener("click",  closeModal);
document.addEventListener("keydown", e => {
  if (e.key === "Escape" && document.getElementById("pin-modal").classList.contains("hidden")) closeModal();
});

// ===== Context Menu =========================================================
const staffTableBody = document.querySelector("#staff-table tbody");
const contextMenu    = document.getElementById("context-menu");
let contextTargetId  = null;

function showContextMenu(x, y, row) {
  staffTableBody.querySelectorAll("tr").forEach(r => r.classList.remove("selected"));
  row.classList.add("selected");
  contextTargetId = row.children[0].textContent;
  contextMenu.style.top  = `${Math.min(y, window.innerHeight - 160)}px`;
  contextMenu.style.left = `${Math.min(x, window.innerWidth  - 190)}px`;
  contextMenu.classList.remove("hidden");
}

staffTableBody.addEventListener("contextmenu", e => {
  e.preventDefault();
  const row = e.target.closest("tr");
  if (!row) return;
  showContextMenu(e.pageX, e.pageY, row);
});

let longPressTimer = null;
staffTableBody.addEventListener("touchstart", e => {
  const row = e.target.closest("tr");
  if (!row) return;
  longPressTimer = setTimeout(() => {
    const touch = e.touches[0];
    showContextMenu(touch.pageX, touch.pageY, row);
  }, 600);
}, { passive: true });
staffTableBody.addEventListener("touchend", () => clearTimeout(longPressTimer), { passive: true });

document.addEventListener("click", e => {
  if (!contextMenu.contains(e.target)) contextMenu.classList.add("hidden");
});

document.querySelectorAll("#context-menu button").forEach(btn => {
  btn.addEventListener("click", async e => {
    const action = e.currentTarget.dataset.action;
    const id     = contextTargetId;
    contextMenu.classList.add("hidden");
    if (!id) return;

    if (action === "update") {
      try {
        const staff  = await listStaff();
        const person = staff.find(s => s.id === id);
        if (person) {
          enterUpdateMode(person.id, person.name, person.email, person.phone);
          document.getElementById("staff-form").scrollIntoView({ behavior: "smooth" });
        }
      } catch (err) { showToast(err.message, "error"); }
    }
    if (action === "remove") {
      await withPin(async () => { await removeStaff(id); });
    }
    if (action === "qr") showQrForStaff(id);
  });
});

// ===== Staff Form ===========================================================
document.getElementById("btn-submit-staff").addEventListener("click", async () => {
  const name  = sanitize(document.getElementById("staff-name").value,  80);
  const email = sanitize(document.getElementById("staff-email").value, 120);
  const phone = sanitize(document.getElementById("staff-phone").value, 30);
  if (!name) { showToast("Please enter a name.", "error"); return; }
  const btn = document.getElementById("btn-submit-staff");
  btn.disabled = true;
  try {
    if (updateMode) {
      await withPin(async () => {
        await updateStaff(updateTargetId, name, email, phone);
        exitUpdateMode();
      });
    } else {
      await withPin(async () => {
        await addStaff(name, email, phone);
        document.getElementById("staff-name").value  = "";
        document.getElementById("staff-email").value = "";
        document.getElementById("staff-phone").value = "";
      });
    }
  } catch (err) {
    if (err.message !== "PIN cancelled") showToast(err.message, "error");
  } finally {
    btn.disabled = false;
  }
});

document.getElementById("btn-cancel-update").addEventListener("click", exitUpdateMode);
document.getElementById("btn-view-staff").addEventListener("click", async () => {
  await refreshDisplay();
  loadDashboard();
  showToast("Data refreshed!", "success");
});

// ===== Scan / Manual Buttons ================================================
document.getElementById("btn-scan-checkin").addEventListener("click",   () => startScan("check_in"));
document.getElementById("btn-scan-checkout").addEventListener("click",  () => startScan("check_out"));
document.getElementById("btn-manual-checkin").addEventListener("click", () => {
  const staffId = document.getElementById("attendance-staff").value;
  if (!staffId) { showToast("Please select a staff member.", "error"); return; }
  recordAttendance("check_in", staffId, null, null);
});
document.getElementById("btn-manual-checkout").addEventListener("click", () => {
  const staffId = document.getElementById("attendance-staff").value;
  if (!staffId) { showToast("Please select a staff member.", "error"); return; }
  recordAttendance("check_out", staffId, null, null);
});

// ===== Update Mode ==========================================================
let updateMode     = false;
let updateTargetId = null;

function enterUpdateMode(staffId, name, email, phone) {
  updateMode     = true;
  updateTargetId = staffId;
  document.getElementById("staff-name").value  = name  || "";
  document.getElementById("staff-email").value = email || "";
  document.getElementById("staff-phone").value = phone || "";
  document.getElementById("staff-id").value    = staffId;
  document.getElementById("update-banner-id").textContent = staffId;
  document.getElementById("update-banner").classList.remove("hidden");
  document.getElementById("btn-submit-staff").textContent = "Save Changes";
  document.getElementById("staff-name").focus();
  switchMainTab("staff");
}

function exitUpdateMode() {
  updateMode     = false;
  updateTargetId = null;
  ["staff-name","staff-email","staff-phone","staff-id"].forEach(id =>
    document.getElementById(id).value = ""
  );
  document.getElementById("update-banner").classList.add("hidden");
  document.getElementById("btn-submit-staff").textContent = "Add Staff";
}

// ===== Enter key shortcuts ==================================================
document.getElementById("login-password").addEventListener("keydown",   e => { if (e.key === "Enter") handleLogin(); });
document.getElementById("reg-pin").addEventListener("keydown",          e => { if (e.key === "Enter") handleRegister(); });
document.getElementById("slogin-password")?.addEventListener("keydown", e => { if (e.key === "Enter") handleStaffLogin(); });

// ===== Set default report dates =============================================
(function setReportDefaults() {
  const now  = new Date();
  const to   = now.toISOString().slice(0, 10);
  const from = new Date(now - 30*86400000).toISOString().slice(0, 10);
  const f = document.getElementById("report-from");
  const t = document.getElementById("report-to");
  if (f) f.value = from;
  if (t) t.value = to;
})();

// ===== Init =================================================================
if (Auth.isLoggedIn()) {
  if (Auth.role === "staff") showStaffShell();
  else showAppShell();
} else {
  showAuthShell();
}

// Keep Render awake
setInterval(() => fetch(`${API_URL}/ping`).catch(() => {}), 240000);

// Real-time refresh every 60s if admin is on dashboard/attendance tab
setInterval(() => {
  if (!Auth.isLoggedIn() || Auth.role === "staff") return;
  if (currentMainTab === "dashboard")  loadDashboard();
  if (currentMainTab === "attendance") renderAttendanceTable();
}, 60000);