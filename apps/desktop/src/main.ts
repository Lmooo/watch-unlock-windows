import "./style.css";
import * as bridge from "./bridge";
import { field, openDeviceDialog, secretFields } from "./dialog";
import { collectSignals, patchLive } from "./live";
import { validateDevice, validateNotifications, validatePassword } from "./validation";
import {
  devicesPage,
  historyPage,
  notificationsPage,
  overview,
  scanPage,
  scanResults,
  setupBanner,
  shell,
} from "./render";
import type { HistoryFilter } from "./render";
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
    content.innerHTML = scanPage(observed, scanning, pairing, pairingStatus, paired, binding);
  if (page === "devices") content.innerHTML = devicesPage(data, signals);
  if (page === "history") content.innerHTML = historyPage(data, historyFilter);
  if (page === "notifications") content.innerHTML = notificationsPage(data);
  bind();
}

function bind(): void {
  document.querySelectorAll<HTMLElement>("[data-link]").forEach((element) => {
    element.onclick = (event) => {
      event.preventDefault();
      const link = element.dataset.link;
      if (link === "repo" || link === "bark") void act(() => bridge.openLink(link));
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
          if (shouldStart) pairingStatus = null;
          await bridge.pair(shouldStart);
          pairing = shouldStart;
          render();
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
  toast("请批准 Windows 管理员确认框，并让手表靠近电脑；验证最长约 30 秒。");
  let boundId: string | null = null;
  try {
    // Quotes are rejected by the request validator; the name is editable afterwards.
    const name = (target.name || "").replace(/["\u0000-\u001f]/g, "").trim();
    await bridge.bindPaired(address, name || "Apple Watch");
    await refresh();
    boundId = data.devices.find((d) => d.address === address)?.id ?? null;
  } catch (error) {
    toast(error instanceof Error ? error.message : "绑定未完成，请重试。");
  } finally {
    binding = false;
  }
  await loadPaired();
  render();
  if (boundId) {
    toast("已绑定此手表。请按实际信号调整靠近和远离阈值。");
    showDevice(boundId);
  }
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
    () =>
      void act(async () => {
        if (!confirm("移除此设备及其保存的身份材料？")) return;
        await bridge.request({ op: "remove_device", id });
        dialog.close();
        await refresh();
        render();
        toast("设备已移除。");
      }),
  );
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
    patchLive(data, status, signals, currentPage(), showDevice);
  }
}

window.addEventListener("hashchange", () => {
  render();
  document.querySelector<HTMLElement>("#main")?.focus();
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
// Right after setup.exe nobody has logged on since, so the logon entry has not run yet.
if (setup?.running_installed && setup.autostart && !data.backend_running && !status.daemon_running) {
  status = await bridge.daemon(true).catch(() => status);
  await refresh();
}
render();
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
    pairingStatus = event;
    pairing = event.status !== "stopped";
    // A completed Windows pairing or a closed window can change the paired list.
    if (event.paired || event.status === "stopped")
      void loadPaired().then(rerenderScanPage);
    rerenderScanPage();
  },
  () => {
    pairing = false;
    toast(
      "配对窗口未完成，请检查蓝牙外设能力及后端记录。未把广播或连接认作配对成功。",
    );
  },
);

if (bridge.native)
  window.setInterval(() => {
    if (refreshing) return;
    refreshing = true;
    void refresh()
      .then(() => {
        patchLive(data, status, signals, currentPage(), showDevice);
        renderBanner();
      })
      .finally(() => {
        refreshing = false;
      });
  }, 2000);
