import "./style.css";
import * as bridge from "./bridge";
import { field, openDeviceDialog, secretFields } from "./dialog";
import { collectSignals, patchLive } from "./live";
import { validateDevice, validateNotifications, validatePassword } from "./validation";
import {
  devicesPage,
  escape,
  historyPage,
  notificationsPage,
  overview,
  scanPage,
  scanResults,
  setupBanner,
  shell,
} from "./render";
import type { HistoryFilter } from "./render";
import { appVersion, findUpdate, showChangelog, showUpdate } from "./update";
import { emptySnapshot } from "./types";
import type {
  Advertisement,
  DeviceSignal,
  ObservedDevice,
  PairedDevice,
  Page,
  PairingStatus,
  RuntimeStatus,
  SetupStatus,
  Snapshot,
} from "./types";

let data: Snapshot = emptySnapshot();
let status: RuntimeStatus = { backend_available: false, daemon_running: false };
// Checked at start and after setup actions only: each check runs reg.exe and schtasks.exe.
let setup: SetupStatus | null = null;
let observed: ObservedDevice[] = [];
let signals: DeviceSignal[] = [];
let scanning = false;
let pairing = false;
let pairingStatus: PairingStatus | null = null;
let backendError = "";
let toastTimer = 0;
let refreshing = false;
let paired: PairedDevice[] | null = null;
let pairedBefore = new Set<string>();
let autoBindPending = false;
/** Set when Windows' paired list showed the new watch before the pairing window reported it. */
let pairedByWindows = false;
let lastPairedCheck = 0;
/** Set by "去填写密码" so the next page render focuses the account password field. */
let passwordFocusPending = false;
/** A watch was bound after the current pairing window opened. */
let boundThisPairing = false;
let version = "";
/** An update found at start; the sidebar button then opens it instead of the changelog. */
let pendingUpdate: Awaited<ReturnType<typeof findUpdate>> = null;
const seenKey = "watch-unlock.changelog-seen";

function changelogSeen(): boolean {
  try { return localStorage.getItem(seenKey) === version; } catch { return true; }
}
let binding = false;
let historyFilter: HistoryFilter = "all";

const pages: Page[] = [
  "overview",
  "scan",
  "devices",
  "history",
  "notifications",
];
const currentPage = (): Page =>
  pages.find((p) => p === location.hash.slice(1)) || "overview";

function toast(message: string): void {
  const element = document.querySelector<HTMLDivElement>("#toast")!;
  element.textContent = message;
  element.classList.add("visible");
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(
    () => element.classList.remove("visible"),
    6000,
  );
}

async function act(action: () => Promise<void>): Promise<void> {
  try {
    await action();
  } catch (error) {
    toast(error instanceof Error ? error.message : "操作未完成，请检查后端。");
  }
}

async function refresh(): Promise<void> {
  const result = await Promise.allSettled([
    bridge.snapshot(),
    bridge.runtime(),
  ]);
  if (result[0].status === "fulfilled") {
    data = result[0].value;
    signals = collectSignals(data, signals, observed);
    backendError = "";
  } else {
    backendError = "尚未连接本地后端。请构建 watchd，并检查固定后端路径。";
    data = { ...data, backend_running: false, runtime: { running: false } };
    signals = [];
  }
  status = result[1].status === "fulfilled"
    ? result[1].value : { backend_available: false, daemon_running: false };
}

/** Shows only what currently stops unlocking; hidden when everything is in place. */
function renderBanner(): void {
  const banner = document.querySelector<HTMLDivElement>("#mode-banner");
  if (!banner) return;
  const html = !bridge.native
    ? "<span>浏览器界面预览：不连接蓝牙，不保存设置。请运行桌面应用使用真实功能。</span>"
    : backendError ? `<span>${backendError}</span>` : setupBanner(setup);
  if (banner.dataset.html === html) return;
  banner.dataset.html = html;
  banner.className = "mode-banner";
  banner.hidden = !html;
  banner.innerHTML = html;
}

function render(): void {
  const page = currentPage();
  document.querySelector<HTMLDivElement>("#app")!.innerHTML = shell(page);
  renderBanner();
  const content = document.querySelector<HTMLDivElement>("#page-content")!;
  if (page === "overview") content.innerHTML = overview(data, status, signals, setup);
  if (page === "scan")
    content.innerHTML = scanPage(observed, scanning, pairing, pairingStatus, paired, binding, pairingBound());
  if (page === "devices") content.innerHTML = devicesPage(data, signals);
  if (page === "history") content.innerHTML = historyPage(data, historyFilter);
  if (page === "notifications") content.innerHTML = notificationsPage(data);
  bind();
}

function bindChangelog(): void {
  document.querySelectorAll<HTMLButtonElement>("[data-changelog]").forEach((button) => {
    const text = button.querySelector<HTMLElement>(".version-text");
    const dot = button.querySelector<HTMLElement>(".version-dot");
    if (text && pendingUpdate) text.textContent = `有新版本 v${pendingUpdate.version}`;
    else if (text && version) text.textContent = `v${version} · 更新记录`;
    // A dot until this version's notes are opened, or while an update waits.
    if (dot) dot.hidden = !pendingUpdate && (!version || changelogSeen());
    button.classList.toggle("has-update", !!pendingUpdate);
    button.onclick = () => {
      if (pendingUpdate) { showUpdate(pendingUpdate, toast); return; }
      try { localStorage.setItem(seenKey, version); } catch { /* the dot just stays */ }
      if (dot) dot.hidden = true;
      void showChangelog(toast);
    };
  });
}

function bind(): void {
  bindChangelog();
  document.querySelectorAll<HTMLElement>("[data-link]").forEach((element) => {
    element.onclick = (event) => {
      event.preventDefault();
      const link = element.dataset.link;
      if (link === "repo" || link === "bark" || link === "bluetooth") void act(() => bridge.openLink(link));
    };
  });
  document
    .querySelectorAll<HTMLButtonElement>("#go-scan, #empty-scan")
    .forEach((b) => {
      b.onclick = () => {
        location.hash = "scan";
      };
    });
  document
    .querySelector<HTMLButtonElement>("#add-device")
    ?.addEventListener("click", () => showDevice());
  document.querySelectorAll<HTMLButtonElement>("[data-edit]").forEach((b) => {
    b.onclick = () => showDevice(b.dataset.edit);
  });
  document.querySelectorAll<HTMLButtonElement>("[data-remove]").forEach((b) => {
    b.onclick = () => removeDevice(b.dataset.remove || "");
  });
  bindScanRows();
  bindPairedRows();
  document.querySelector<HTMLButtonElement>("#scan-toggle")?.addEventListener(
    "click",
    () =>
      void act(async () => {
        const shouldStart = !scanning;
        await bridge.scan(shouldStart);
        scanning = shouldStart;
        if (shouldStart) observed = [];
        render();
      }),
  );
  document.querySelector<HTMLInputElement>("#autostart")?.addEventListener("change", (event) => {
    const input = event.currentTarget as HTMLInputElement;
    const enabled = input.checked;
    input.disabled = true;
    void act(async () => {
      try {
        setup = await bridge.setAutostart(enabled);
        toast(enabled ? "已开启：以后每次登录 Windows 都会自动启动后台。" : "已关闭开机自启；需要时请手动启动后台。");
      } finally {
        render();
      }
    });
  });
  document.querySelector<HTMLButtonElement>("#daemon-toggle")?.addEventListener(
    "click",
    () =>
      void act(async () => {
        // The heartbeat reflects any running background, including one started at logon.
        const stopping = data.backend_running || status.daemon_running;
        status = await bridge.daemon(!stopping);
        await refresh();
        render();
        toast(
          stopping
            ? "已请求停止后台，对所有窗口与开机任务启动的后台都生效。"
            : "后台已启动，关闭窗口后仍会继续运行。几秒后可看到心跳。",
        );
      }),
  );
  document
    .querySelector<HTMLButtonElement>("#pairing-toggle")
    ?.addEventListener(
      "click",
      () =>
        void act(async () => {
          const shouldStart = !pairing;
          if (shouldStart) {
            pairingStatus = null;
            // Remember who was already paired, so only the watch paired now is bound automatically.
            pairedBefore = new Set((paired ?? []).map((device) => device.address));
            autoBindPending = true;
            pairedByWindows = false;
            boundThisPairing = false;
          }
          await bridge.pair(shouldStart);
          pairing = shouldStart;
          render();
        }),
    );
  document.querySelectorAll<HTMLButtonElement>("[data-goto-password]").forEach((button) => {
    button.onclick = goToPassword;
  });
  document
    .querySelector<HTMLButtonElement>("#copy-diagnostics")
    ?.addEventListener("click", () => void act(copyDiagnostics));
  document
    .querySelector<HTMLButtonElement>("#export-diagnostics")
    ?.addEventListener(
      "click",
      () =>
        void act(async () => {
          const path = await bridge.exportDiagnostics();
          toast(`诊断信息已保存到“下载”文件夹：${path.split("\\").pop()}`);
        }),
    );
  document
    .querySelector<HTMLButtonElement>("#refresh-history")
    ?.addEventListener(
      "click",
      () =>
        void act(async () => {
          await refresh();
          render();
        }),
    );
  document
    .querySelector<HTMLSelectElement>("#history-filter")
    ?.addEventListener("change", (event) => {
      historyFilter = (event.target as HTMLSelectElement).value as HistoryFilter;
      render();
    });
  document
    .querySelector<HTMLButtonElement>("#clear-history")
    ?.addEventListener(
      "click",
      () =>
        void act(async () => {
          if (!confirm("清空全部解锁记录？清空操作本身会留下一条记录。")) return;
          data = await bridge.request<Snapshot>({ op: "clear_history" });
          render();
          toast("解锁记录已清空。");
        }),
    );
  document
    .querySelector<HTMLButtonElement>("#notify-test")
    ?.addEventListener(
      "click",
      (event) =>
        void act(async () => {
          const button = event.currentTarget as HTMLButtonElement;
          button.disabled = true;
          try {
            data = await bridge.request<Snapshot>({ op: "notify_test" });
            toast("测试通知已被 Bark 接受，请检查手机或手表。");
          } finally {
            button.disabled = false;
          }
        }),
    );
  document
    .querySelector<HTMLFormElement>("#credential-form")
    ?.addEventListener("submit", saveCredential);
  document
    .querySelector<HTMLButtonElement>("#clear-credential")
    ?.addEventListener(
      "click",
      () =>
        void act(async () => {
          if (!confirm("清除当前 Windows 账户的已保存解锁凭据？")) return;
          await bridge.request({ op: "clear_credential" });
          await refresh();
          render();
          toast("已清除保存的凭据。");
        }),
    );
  document
    .querySelector<HTMLFormElement>("#notifications-form")
    ?.addEventListener("submit", saveNotifications);
}

/**
 * Binds the one watch that this pairing window added. With several new entries the user picks
 * one in the paired list instead, so a nearby stranger's device is never bound by guess.
 */
function autoBindNewWatch(): void {
  if (!autoBindPending || binding) return;
  const fresh = freshPaired();
  if (!fresh.length) return;
  autoBindPending = false;
  if (fresh.length === 1) void bindPairedDevice(fresh[0].address);
  else toast("配对完成。请在“Windows 已配对设备”中选择你的手表并点击绑定。");
}

/** Step 4 of the guide: the watch from this pairing is bound, here or by an earlier bind of the new entry. */
function pairingBound(): boolean {
  return boundThisPairing
    || (pairingStatus !== null && (paired ?? []).some((device) => device.bound && !pairedBefore.has(device.address)));
}

/** Unbound devices Windows paired after this pairing window opened. */
function freshPaired(): PairedDevice[] {
  return (paired ?? []).filter((device) => !device.bound && !pairedBefore.has(device.address));
}

/**
 * Windows' own paired list is the fallback pairing signal: a watch can bond without the
 * encrypted read the pairing window watches for. A new entry ends the window early.
 */
function checkPairedList(event: PairingStatus): void {
  const connected = event.subscriptions > 0 || event.encrypted_reads > 0;
  const due = connected && Date.now() - lastPairedCheck >= 3000;
  if (!event.paired && event.status !== "stopped" && !due) return;
  lastPairedCheck = Date.now();
  void loadPaired().then(() => {
    if (!pairedByWindows && freshPaired().length) {
      pairedByWindows = true;
      if (pairingStatus) pairingStatus = { ...pairingStatus, paired: true };
      if (pairing) void bridge.pair(false).catch(() => undefined);
    }
    rerenderScanPage();
    autoBindNewWatch();
    // A watch Windows paired earlier never shows up as new; it only needs binding.
    if (event.status === "stopped" && !pairedByWindows && event.reason !== "cancelled"
      && (paired ?? []).some((device) => !device.bound))
      toast("如果你的手表已经在下方“Windows 已配对设备”里，直接点「绑定此设备」即可，不用重新配对。");
  });
}

/** Reads Windows' paired list. Failure shows an empty list instead of stale names. */
async function loadPaired(): Promise<void> {
  try {
    paired = await bridge.pairedDevices();
  } catch {
    paired = [];
    toast("未能读取 Windows 已配对设备，请检查蓝牙与后端记录。");
  }
}

function rerenderScanPage(): void {
  if (currentPage() === "scan" && !document.querySelector<HTMLDialogElement>("#device-dialog")?.open)
    render();
}

function bindPairedRows(): void {
  document.querySelectorAll<HTMLButtonElement>("[data-bind-paired]").forEach((b) => {
    b.onclick = () => void bindPairedDevice(b.dataset.bindPaired || "");
  });
}

/**
 * Elevated, one-time identity read. The UAC prompt and the 30 s verification scan both happen
 * in the backend, so the UI stays in the binding state until the request returns.
 */
async function bindPairedDevice(address: string): Promise<void> {
  const target = paired?.find((d) => d.address === address);
  if (!target || binding) return;
  binding = true;
  rerenderScanPage();
  toast("正在绑定：如果弹出 Windows 管理员确认，点「是」；让手表靠近电脑，验证最长约 30 秒。");
  let boundId: string | null = null;
  try {
    // Quotes are rejected by the request validator; the name is editable afterwards.
    const name = (target.name || "").replace(/["\u0000-\u001f]/g, "").trim();
    await bridge.bindPaired(address, name || "Apple Watch");
    await refresh();
    boundId = data.devices.find((d) => d.address === address)?.id ?? null;
    if (boundId && pairingStatus) boundThisPairing = true;
  } catch (error) {
    toast(error instanceof Error ? error.message : "绑定未完成，请重试。");
  } finally {
    binding = false;
  }
  await loadPaired();
  render();
  if (boundId) showBound(boundId);
}

/** After binding: say what is still missing, so the user is not left on the scan page. */
function showBound(id: string): void {
  const dialog = document.querySelector<HTMLDialogElement>("#info-dialog")!;
  const ready = data.credential_configured;
  dialog.innerHTML = `<div class="dialog-heading"><div><div class="eyebrow">PAIRED</div><h2 id="info-dialog-title">手表已绑定</h2></div><button type="button" class="close-button" data-close-dialog aria-label="关闭">×</button></div>
    <p class="form-hint">${ready
      ? "账户密码已保存，现在锁屏后走远再回来就能解锁。可以按实际信号调整靠近和远离距离。"
      : "还差一步：保存 Windows 账户密码。没有密码时，手表走远再回来也无法解锁。"}</p>
    <div class="form-actions"><span class="spacer"></span><button type="button" class="button secondary" id="bound-adjust">调整距离</button><button type="button" class="button primary" id="bound-next">${ready ? "查看我的设备" : "去填写密码"}</button></div>`;
  dialog.querySelector<HTMLButtonElement>("[data-close-dialog]")!.onclick = () => dialog.close();
  dialog.querySelector<HTMLButtonElement>("#bound-adjust")!.onclick = () => { dialog.close(); showDevice(id); };
  dialog.querySelector<HTMLButtonElement>("#bound-next")!.onclick = () => {
    dialog.close();
    if (ready) location.hash = "devices";
    else goToPassword();
  };
  dialog.showModal();
}

/** Opens 我的设备 with the account password field focused. */
function goToPassword(): void {
  if (currentPage() === "devices") { focusPassword(); return; }
  passwordFocusPending = true;
  location.hash = "devices";
}

/**
 * The report takes a few seconds; handing the clipboard a pending item keeps the click's user
 * activation, which a plain writeText after the wait would have lost.
 */
async function copyDiagnostics(): Promise<void> {
  const summary = bridge.diagnosticsSummary();
  try {
    await navigator.clipboard.write([new ClipboardItem({
      "text/plain": summary.then((text) => new Blob([text], { type: "text/plain" })),
    })]);
    toast("诊断信息已复制，直接粘贴到微信等聊天里发给开发者即可。");
  } catch {
    // Fall back to a selectable copy the user can take with Ctrl + C.
    showSummary(await summary);
  }
}

function showSummary(text: string): void {
  const dialog = document.querySelector<HTMLDialogElement>("#info-dialog")!;
  dialog.innerHTML = `<div class="dialog-heading"><div><div class="eyebrow">DIAGNOSTICS</div><h2 id="info-dialog-title">复制诊断信息</h2></div><button type="button" class="close-button" data-close-dialog aria-label="关闭对话框">×</button></div>
    <p class="form-hint">没能自动复制。下面的内容已全部选中，按 Ctrl + C 复制，再粘贴发给开发者。</p>
    <textarea class="diagnostics-text" readonly rows="14">${escape(text)}</textarea>
    <div class="form-actions"><span class="spacer"></span><button type="button" class="button primary" data-close-dialog>关闭</button></div>`;
  dialog.querySelectorAll<HTMLButtonElement>("[data-close-dialog]").forEach((button) => {
    button.onclick = () => dialog.close();
  });
  dialog.showModal();
  dialog.querySelector<HTMLTextAreaElement>("textarea")?.select();
}

function focusPassword(): void {
  const input = document.querySelector<HTMLInputElement>("#windows-password");
  input?.scrollIntoView({ block: "center" });
  input?.focus();
}

function bindScanRows(): void {
  document.querySelectorAll<HTMLButtonElement>("[data-bind]").forEach((b) => {
    b.onclick = () =>
      showDevice(
        undefined,
        observed.find((o) => o.address === b.dataset.bind)?.name,
      );
  });
}

function showDevice(id?: string, name?: string | null): void {
  const device = data.devices.find((d) => d.id === id);
  const dialog = openDeviceDialog(device, name);
  dialog
    .querySelector<HTMLFormElement>("#device-form")!
    .addEventListener("submit", (event) => {
      event.preventDefault();
      const form = event.currentTarget as HTMLFormElement;
      void act(async () => {
        const values = new FormData(form);
        const near = Number(field(values, "near_rssi"));
        const far = Number(field(values, "far_rssi"));
        try {
          validateDevice(field(values, "name"), near, far, field(values, "irk"),
            field(values, "irk_blob_path"), Boolean(device?.identity_configured));
          await bridge.request({
            op: "save_device",
            device: {
              ...(device ? { id: device.id } : {}),
              name: field(values, "name"),
              adapter: "apple-ble",
              ...(field(values, "irk") ? { irk: field(values, "irk") } : {}),
              ...(field(values, "irk_blob_path") ? { irk_blob_path: field(values, "irk_blob_path") } : {}),
              near_rssi: near,
              far_rssi: far,
              return_window_seconds: Number(field(values, "return_window_seconds")),
              enabled: values.has("enabled"),
              auto_unlock_on_return: values.has("auto_unlock_on_return"),
            },
          });
        } finally {
          secretFields(form);
        }
        dialog.close();
        await refresh();
        render();
        toast("设备配置已保存；这不代表已经完成系统配对。");
      });
    });
  dialog.querySelector<HTMLButtonElement>("#remove-device")?.addEventListener(
    "click",
    () => removeDevice(id || "", dialog),
  );
}

function removeDevice(id: string, dialog?: HTMLDialogElement): void {
  const device = data.devices.find((d) => d.id === id);
  if (!device) return;
  void act(async () => {
    if (!confirm(`移除「${device.name}」及其保存的身份材料？移除后要重新绑定才能解锁。`)) return;
    await bridge.request({ op: "remove_device", id });
    dialog?.close();
    await refresh();
    render();
    toast("设备已移除。");
  });
}

function saveCredential(event: SubmitEvent): void {
  event.preventDefault();
  const form = event.currentTarget as HTMLFormElement;
  void act(async () => {
    try {
      const input = form.querySelector<HTMLInputElement>('[name="password"]')!;
      validatePassword(input.value, data.devices.some((device) => device.identity_configured));
      await bridge.request({ op: "save_credential", password: input.value });
    } finally {
      secretFields(form);
    }
    await refresh();
    render();
    toast("账户密码已验证并加密保存。");
  });
}

function saveNotifications(event: SubmitEvent): void {
  event.preventDefault();
  const form = event.currentTarget as HTMLFormElement;
  void act(async () => {
    const values = new FormData(form);
    const endpoint = field(values, "endpoint");
    try {
      validateNotifications(endpoint, field(values, "device_key"));
      await bridge.request({
        op: "save_notifications",
        endpoint,
        enabled: values.has("enabled"),
        notify_on_unlock: values.has("notify_on_unlock"),
        ...(field(values, "device_key")
          ? { device_key: field(values, "device_key") }
          : {}),
      });
    } finally {
      secretFields(form);
    }
    await refresh();
    render();
    toast("通知设置已保存；可用“发送测试通知”验证。");
  });
}

function receive(advertisement: Advertisement): void {
  if (!Number.isFinite(advertisement.rssi) || !advertisement.address) return;
  const sameDevice = (candidate: ObservedDevice): boolean =>
    candidate.address === advertisement.address ||
    Boolean(
      advertisement.matched_device_id &&
      candidate.matched_device_id === advertisement.matched_device_id,
    );
  const previous = observed.find(sameDevice);
  const next: ObservedDevice = {
    ...advertisement,
    samples: [...(previous?.samples || []), advertisement.rssi].slice(-30),
    lastSeen: Date.now(),
  };
  observed = [...observed.filter((o) => !sameDevice(o)), next].slice(-200);
  if (currentPage() === "scan") {
    const results = document.querySelector<HTMLDivElement>("#scan-results");
    if (results) {
      results.innerHTML = scanResults(observed);
      bindScanRows();
    }
    const count = document.querySelector<HTMLElement>(".panel-title h2 > span");
    if (count) count.textContent = String(observed.length);
  } else if (currentPage() === "overview" || currentPage() === "devices") {
    signals = collectSignals(data, signals, observed);
    patchLive(data, status, signals, currentPage(), showDevice, removeDevice);
  }
}

window.addEventListener("hashchange", () => {
  render();
  document.querySelector<HTMLElement>("#main")?.focus();
  if (passwordFocusPending) { passwordFocusPending = false; focusPassword(); }
  if (currentPage() === "scan") void loadPaired().then(rerenderScanPage);
});
window.addEventListener("beforeunload", () => {
  document
    .querySelectorAll<HTMLInputElement>('input[type="password"]')
    .forEach((input) => {
      input.value = "";
    });
});
// Known before the first paint, so the banner and autostart switch render correctly.
setup = await bridge.setupStatus().catch(() => null);
render();
await refresh();
// Right after setup.exe nobody has logged on since, so the logon entry has not run yet. The
// installer kills the background without a final status write, so `backend_running` can still
// look fresh here; the supervisor is single-instance, so starting it again is harmless.
if (setup?.running_installed && setup.autostart && !status.daemon_running) {
  status = await bridge.daemon(true).catch(() => status);
  await refresh();
}
version = await appVersion();
render();
// Only the installed copy updates itself; a failed check stays silent.
if (setup?.running_installed)
  void findUpdate().then((update) => {
    if (!update) return;
    pendingUpdate = update;
    bindChangelog();
    showUpdate(update, toast);
  });
void loadPaired().then(rerenderScanPage);
await bridge.subscribe(
  receive,
  (scanStatus) => {
    scanning = scanStatus === "running";
    if (
      currentPage() === "scan" &&
      !document.querySelector<HTMLDialogElement>("#device-dialog")?.open
    )
      render();
    if (scanStatus === "failed")
      toast("扫描未完成，请检查蓝牙适配器与后端记录。");
  },
  (event) => {
    pairingStatus = pairedByWindows ? { ...event, paired: true } : event;
    pairing = event.status !== "stopped";
    // A completed Windows pairing or a closed window can change the paired list.
    checkPairedList(event);
    rerenderScanPage();
  },
  () => {
    pairing = false;
    toast(
      "配对进程意外结束，请重试。仍然失败的话，在「解锁记录」页点「复制诊断信息」，粘贴发给开发者。",
    );
  },
);

if (bridge.native)
  window.setInterval(() => {
    if (refreshing) return;
    refreshing = true;
    void refresh()
      .then(() => {
        patchLive(data, status, signals, currentPage(), showDevice, removeDevice);
        renderBanner();
      })
      .finally(() => {
        refreshing = false;
      });
  }, 2000);
