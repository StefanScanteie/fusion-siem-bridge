const THEME_KEY = "fusion-siem-theme";

function $(id) {
  return document.getElementById(id);
}

function setTheme(theme) {
  const next = theme === "dark" || theme === "high-contrast" ? "dark" : "light";
  document.documentElement.dataset.theme = next;
  localStorage.setItem(THEME_KEY, next);
  const toggle = $("theme-toggle");
  const dark = next === "dark";
  toggle.setAttribute("aria-pressed", dark ? "true" : "false");
  toggle.textContent = dark ? "Light" : "Dark";
}

function showTab(name) {
  const status = name === "status";
  $("tab-status").setAttribute("aria-selected", status ? "true" : "false");
  $("tab-settings").setAttribute("aria-selected", status ? "false" : "true");
  $("panel-status").hidden = !status;
  $("panel-settings").hidden = status;
}

async function loadStatus() {
  const response = await fetch("/ui/status");
  const body = await response.json();
  const live = $("ingest-live");
  live.textContent = body.ingest_live ? "Live" : "Down";
  live.classList.toggle("live", body.ingest_live);
  live.classList.toggle("down", !body.ingest_live);
  $("outbox-lines").textContent = String(body.outbox_lines);
  $("last-ingest").textContent = body.last_ingest_at || "never";
  $("webhook-url").value = body.webhook_url;
}

function showDestination(name) {
  document.querySelectorAll(".dest-fields").forEach((block) => {
    block.hidden = block.dataset.dest !== name;
  });
}

async function loadSettings() {
  const response = await fetch("/ui/settings");
  const body = await response.json();
  $("ingest-token").placeholder = body.ingest_token || "leave blank to keep";
  $("ingest-token").value = "";
  $("data-dir").value = body.data_dir || "";
  $("destination").value = body.destination || "none";
  $("splunk-hec-url").value = body.splunk_hec_url || "";
  $("splunk-hec-token").placeholder = body.splunk_hec_token || "leave blank to keep";
  $("splunk-hec-token").value = "";
  $("splunk-index").value = body.splunk_index || "";
  $("splunk-sourcetype").value = body.splunk_sourcetype || "fusion_siem:v1";
  $("qradar-host").value = body.qradar_host || "";
  $("qradar-port").value = body.qradar_port || 514;
  $("rapid7-url").value = body.rapid7_url || "";
  $("rapid7-token").placeholder = body.rapid7_token || "leave blank to keep";
  $("rapid7-token").value = "";
  $("forward-url").value = body.forward_url || "";
  $("forward-token").placeholder = body.forward_token || "leave blank to keep";
  $("forward-token").value = "";
  $("bind-host").value = body.host || "0.0.0.0";
  $("bind-port").value = body.port || 8080;
  $("public-host").value = body.public_host || "";
  showDestination($("destination").value);
}

async function saveSettings(event) {
  event.preventDefault();
  const status = $("save-status");
  status.textContent = "";
  const payload = {
    ingest_token: $("ingest-token").value,
    data_dir: $("data-dir").value,
    destination: $("destination").value,
    splunk_hec_url: $("splunk-hec-url").value,
    splunk_hec_token: $("splunk-hec-token").value,
    splunk_index: $("splunk-index").value,
    splunk_sourcetype: $("splunk-sourcetype").value,
    qradar_host: $("qradar-host").value,
    qradar_port: Number($("qradar-port").value) || 514,
    rapid7_url: $("rapid7-url").value,
    rapid7_token: $("rapid7-token").value,
    forward_url: $("forward-url").value,
    forward_token: $("forward-token").value,
    host: $("bind-host").value,
    port: Number($("bind-port").value),
    public_host: $("public-host").value,
  };
  const response = await fetch("/ui/settings", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    status.textContent = "Could not save settings.";
    return;
  }
  status.textContent = "Saved. Restart fusion-siem serve to apply.";
}

$("tab-status").addEventListener("click", () => showTab("status"));
$("tab-settings").addEventListener("click", () => showTab("settings"));
$("destination").addEventListener("change", () => showDestination($("destination").value));
$("theme-toggle").addEventListener("click", () => {
  const current = document.documentElement.dataset.theme;
  setTheme(current === "dark" ? "light" : "dark");
});
$("copy-url").addEventListener("click", async () => {
  await navigator.clipboard.writeText($("webhook-url").value);
  $("copy-url").textContent = "Copied";
  setTimeout(() => {
    $("copy-url").textContent = "Copy";
  }, 1200);
});
$("settings-form").addEventListener("submit", saveSettings);

setTheme(localStorage.getItem(THEME_KEY) || "light");
showTab("status");
loadStatus();
loadSettings();
