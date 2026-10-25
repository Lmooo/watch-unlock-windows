import { icon } from "./icons";
import { native } from "./bridge";
import type {
  Device,
  DeviceSignal,
  HistoryEntry,
  ObservedDevice,
  PairedDevice,
  PairingStatus,
  Page,
  RuntimeStatus,
  SetupStatus,
  Snapshot,
  Signal,
} from "./types";

export const escape = (value: unknown): string =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[c] as string,
  );

export function sparkline(samples: number[]): string {
  if (!samples.length) return '<div class="chart-empty">等待真实信号</div>';
  const points = samples
    .map(
      (rssi, i) =>
        `${8 + (i * 284) / Math.max(samples.length - 1, 1)},${68 - ((Math.max(-100, Math.min(-30, rssi)) + 100) / 70) * 54}`,
    )
    .join(" ");
  return `<svg class="sparkline" viewBox="0 0 300 80" role="img" aria-label="最近 ${samples.length} 次广播信号趋势"><path class="grid-line" d="M0 22h300M0 50h300M0 78h300"/><polyline points="${points}"/></svg>`;
}

export function signalValue(observed?: Signal): string {
  return `${observed ? escape(observed.rssi) : "—"}<small>dBm</small><span>${observed ? `更新于 ${escape(new Date(observed.lastSeen).toLocaleTimeString("zh-CN", { hour12: false }))}` : "尚无实时信号"}</span>`;
}

export function deviceCard(device: Device, observed?: Signal): string {
  return `<article class="device-card" data-device-id="${escape(device.id)}">
    <div class="device-head"><div class="watch-icon">${icon("devices")}</div><span class="badge ${device.enabled ? "green" : ""}">${device.enabled ? "已启用" : "已停用"}</span></div>
    <h3>${escape(device.name)}</h3><p class="muted">Apple BLE · ${device.identity_configured ? "身份材料已保存" : "待登记身份材料"}</p>
    <div class="signal-value">${signalValue(observed)}</div>
    <div class="signal-chart">${sparkline(observed?.samples || [])}</div>
    <div class="card-meta"><span>靠近 <strong>${device.near_rssi} dBm</strong></span><span>远离 <strong>${device.far_rssi} dBm</strong></span></div>
    <div class="card-footer"><span>${device.auto_unlock_on_return ? "无感解锁" : "返回后动键鼠解锁"}</span><button class="text-button" data-edit="${escape(device.id)}">配置 ${icon("arrow")}</button></div>
  </article>`;
}

/**
 * The background is controlled for the whole session: stopping works no matter which window,
 * logon task or supervisor started it. The heartbeat is the source of truth, not window ownership.
 */
export function backendLabel(
  data: Snapshot,
  status: RuntimeStatus,
): { action: string; note: string; disabled: boolean } {
  if (data.backend_running)
    return { action: "停止后台", note: "后台正在运行 · 停止对所有窗口生效", disabled: false };
  if (status.daemon_running)
    return { action: "停止后台", note: "后台进程已启动 · 等待首次心跳", disabled: false };
  return { action: "启动后台", note: "后台未运行 · 启动后关闭窗口仍会继续运行", disabled: !status.backend_available };
}

/** Log codes stay English and stable on disk; the UI shows these names. */
const eventNames: Record<string, string> = {
  backend_started: "后台启动",
  backend_stopped: "后台停止",
  scanner_reset: "扫描器重建",
  scanner_unavailable: "扫描器中断",
  session_locked: "电脑已锁屏",
  session_unlocked: "电脑已解锁",
  session_reconciled: "会话状态核对",
  far_threshold_crossed: "越过远离阈值",
  return_detected: "检测到返回",
  return_authorization_expired: "返回授权过期",
  provider_connected: "登录界面已就绪",
  display_woke: "锁屏后屏幕唤醒",
  lock_screen_input: "锁屏后检测到操作",
  legacy_cleanup_failed: "旧确认数据清理失败",
  pipe_client_connected: "登录组件已连接管道",
  pipe_session_mismatch: "登录组件会话不符",
  pipe_hello_timeout: "登录组件握手超时",
  pipe_client_dropped: "登录组件握手前断开",
  pipe_peer_rejected: "登录组件身份未通过",
  pipe_peer_not_system: "握手方不是 SYSTEM",
  pipe_peer_not_logonui: "握手方不是登录界面",
  pipe_peer_unknown: "无法识别握手方",
  pipe_create_failed: "管道创建失败",
  unlock_submitted: "已提交解锁",
  device_saved: "设备已保存",
  device_removed: "设备已解绑",
  credential_saved: "账户凭据已保存",
  credential_removed: "账户凭据已移除",
  notifications_saved: "通知设置已保存",
  notification_test: "测试通知",
  configuration_reloaded: "配置重新加载",
  history_cleared: "记录已清空",
};

export const eventName = (code: string): string => eventNames[code] || code;

export type HistoryFilter = "all" | "unlock" | "config" | "backend";

const historyGroups: Record<Exclude<HistoryFilter, "all">, string[]> = {
  unlock: ["session_locked", "session_unlocked", "session_reconciled", "far_threshold_crossed",
    "return_detected", "return_authorization_expired", "provider_connected", "display_woke", "lock_screen_input", "unlock_submitted"],
  config: ["device_saved", "device_removed", "credential_saved", "credential_removed",
    "notifications_saved", "notification_test", "configuration_reloaded", "history_cleared"],
  backend: ["backend_started", "backend_stopped", "scanner_reset", "scanner_unavailable",
    "pipe_client_connected", "pipe_session_mismatch", "pipe_hello_timeout", "pipe_client_dropped",
    "pipe_peer_rejected", "pipe_peer_not_system", "pipe_peer_not_logonui", "pipe_peer_unknown",
    "pipe_create_failed"],
};

export function filterHistory(entries: HistoryEntry[], filter: HistoryFilter): HistoryEntry[] {
  return filter === "all" ? entries : entries.filter((e) => historyGroups[filter].includes(e.event));
}

export function historyPage(data: Snapshot, filter: HistoryFilter): string {
  const options: [HistoryFilter, string][] = [
    ["all", "全部"], ["unlock", "锁屏与解锁"], ["config", "设备与配置"], ["backend", "后台与扫描"],
  ];
  const shown = filterHistory(data.history, filter);
  const select = `<label class="inline-select">筛选<select id="history-filter">${options
    .map(([value, label]) => `<option value="${value}" ${value === filter ? "selected" : ""}>${label}</option>`)
    .join("")}</select></label>`;
  const actions = `${select}<button class="button secondary" id="refresh-history">刷新记录</button><button class="button secondary danger" id="clear-history" ${data.history.length ? "" : "disabled"}>清空记录</button>`;
  return `${header("ACTIVITY LOG", "每次解锁，都有迹可循", `显示最近 ${data.history.length} 条中的 ${shown.length} 条。记录来自本机后端，不含密码或密钥。`, actions)}<section class="panel" id="activity-content">${historyTable(shown, data.devices)}</section>`;
}

export function historyTable(
  entries: HistoryEntry[],
  devices: Device[],
  limit = entries.length,
): string {
  if (!entries.length)
    return `<div class="empty compact">${icon("history")}<h3>还没有操作记录</h3><p>保存配置、授权请求与后台事件将在这里显示。</p></div>`;
  return `<div class="table-wrap"><table><thead><tr><th>时间</th><th>事件</th><th>设备</th><th>说明</th></tr></thead><tbody>${entries
    .slice()
    .sort((a, b) => b.at_ms - a.at_ms)
    .slice(0, limit)
    .map(
      (e) =>
        `<tr><td class="nowrap">${escape(new Date(e.at_ms).toLocaleString("zh-CN", { hour12: false }))}</td><td><span class="event-label" title="${escape(e.event)}">${escape(eventName(e.event))}</span></td><td>${escape(devices.find((d) => d.id === e.device_id)?.name || "—")}</td><td>${escape(e.detail)}</td></tr>`,
    )
    .join("")}</tbody></table></div>`;
}

export function shell(page: Page): string {
  const nav: [Page, string, string][] = [
    ["overview", "概览", "01"],
    ["scan", "附近扫描", "02"],
    ["devices", "我的设备", "03"],
    ["history", "解锁记录", "04"],
    ["notifications", "通知设置", "05"],
  ];
  return `<aside class="sidebar"><a href="#overview" class="brand"><span class="brand-logo" aria-hidden="true"></span><span>Watch Unlock<small>让靠近，成为连接</small></span></a><div class="nav-label">工作空间</div><nav aria-label="主要导航">${nav.map(([id, title, count]) => `<a href="#${id}" class="nav-item ${page === id ? "active" : ""}" ${page === id ? 'aria-current="page"' : ""}>${icon(id)}<span>${title}</span><small>${count}</small></a>`).join("")}</nav><div class="sidebar-bottom"><div class="sidebar-meta"><a class="repo-link" href="https://github.com/whyy1/watch-unlock-windows" data-link="repo" title="在 GitHub 查看源码" aria-label="在 GitHub 查看源码">${icon("github")}</a><span class="version-label">AGPL-3.0 · 不提供任何担保</span></div><div class="local-status"><span class="status-dot"></span>本地处理 · 密钥加密存储</div></div></aside>
  <main id="main" tabindex="-1"><header class="topbar"><span>个人工作空间 <span class="breadcrumb">/</span> ${nav.find((n) => n[0] === page)?.[1]}</span><div class="topbar-right"><span class="status-dot amber"></span>${native ? "桌面应用" : "浏览器预览"}</div></header><div class="content"><div id="mode-banner"></div><div id="page-content"></div><footer>WATCH UNLOCK <span>公开广播只提供接近线索。当前 Apple 接入无法确认手表锁定或佩戴状态。</span></footer></div></main><div id="toast" role="status" aria-live="polite"></div><dialog id="device-dialog" aria-labelledby="device-dialog-title"></dialog>`;
}

export function header(
  eyebrow: string,
  title: string,
  description: string,
  action = "",
): string {
  return `<div class="page-header"><div><div class="eyebrow">${eyebrow}</div><h1>${title}</h1><p>${description}</p></div>${action}</div>`;
}

/** Shown only when something stops the lock screen from unlocking. */
export function setupBanner(setup: SetupStatus | null): string {
  if (!setup) return "";
  if (!setup.running_installed)
    return "<span>当前运行的不是安装版本，后台无法解锁。请运行 setup.exe 安装，之后从开始菜单打开 Watch Unlock。</span>";
  if (!setup.provider_registered)
    return "<span>登录组件未注册，锁屏时无法解锁。请重新运行 setup.exe。</span>";
  return "";
}

export function overview(
  data: Snapshot,
  status: RuntimeStatus,
  observed: DeviceSignal[],
  setup: SetupStatus | null,
): string {
  const ready =
    data.credential_configured &&
    data.devices.some((d) => d.enabled && d.identity_configured);
  return `${header("YOUR EVERYDAY CONNECTION", "每一次靠近，都有回应。", "在这里管理设备、查看信号，让解锁保持清晰可控。", '<button class="button primary" id="go-scan">' + icon("plus") + " 添加设备</button>")}
    <section class="hero"><div><span class="eyebrow" id="backend-state">${data.backend_running ? "后台运行中" : "后台尚未就绪"}</span><h2>${ready ? "配置已登记，等待后台验证" : "准备好，连接你的第一块手表"}</h2><p>${ready ? "设备与账户密码已就绪。锁屏后走远再回来即可解锁。" : "从附近扫描开始，再登记设备身份与 Windows 账户密码。"}</p><div class="hero-actions"><button class="button dark" id="daemon-toggle" ${backendLabel(data, status).disabled ? "disabled" : ""}>${backendLabel(data, status).action}</button><span class="hero-note">${backendLabel(data, status).note}</span></div><label class="toggle-row autostart-toggle"><input type="checkbox" id="autostart" ${setup?.autostart ? "checked" : ""} ${setup?.running_installed ? "" : "disabled"}/><span><strong>登录 Windows 后自动启动后台</strong><small>开机后第一次登录仍需输入密码；之后锁屏即可靠近解锁。</small></span></label></div><div class="hero-logo" aria-hidden="true"></div></section>
    <section class="stats-grid"><article class="stat"><span>已登记设备</span><strong>${data.devices.length.toString().padStart(2, "0")}</strong><small>每块设备独立配置阈值</small></article><article class="stat"><span>Windows 凭据</span><strong class="text-stat">${data.credential_configured ? "已保存" : "未设置"}</strong><small>CurrentUser DPAPI 本机加密</small></article><article class="stat"><span>通知通道</span><strong class="text-stat">${data.notifications.configured ? "已配置" : "未配置"}</strong><small>Bark 推送解锁提醒</small></article></section>
    <div class="section-heading"><div><h2>我的设备 <span>${data.devices.length}</span></h2><p>后台运行时每 2 秒更新信号，也可主动扫描附近广播。</p></div><a href="#devices">管理全部 ${icon("arrow")}</a></div>
    ${
      data.devices.length
        ? `<section class="device-grid">${data.devices
            .slice(0, 3)
            .map((d) =>
              deviceCard(
                d,
                observed.find((o) => o.deviceId === d.id),
              ),
            )
            .join("")}</section>`
        : `<section class="empty device-empty">${icon("devices")}<h3>还没有登记手表</h3><p>扫描可查看附近信号；完成身份登记后才可参与解锁。</p><button class="button secondary" id="empty-scan">开始附近扫描 ${icon("arrow")}</button></section>`
    }
    <div class="section-heading"><div><h2>最近活动</h2><p>如实记录配置与授权事件。</p></div><a href="#history">查看记录 ${icon("arrow")}</a></div><section class="panel" id="activity-content">${historyTable(data.history, data.devices, 5)}</section>`;
}

function pairingProgress(pairing: boolean, state: PairingStatus | null): string {
  if (!state) return pairing ? "等待后端开启配对广播窗口。" : "尚未开启配对窗口。现有系统配对不会由本页自动更改。";
  const advertising: Record<string, string> = {
    created: "准备中", started: "已开启", limited: "部分广播已开启",
    aborted: "广播中断", stopped: "已停止", unknown: "未知",
  };
  const reasons: Record<string, string> = {
    cancelled: "配对窗口已取消。", timeout: "配对窗口已到期。",
    unavailable: "配对窗口不可用，请检查蓝牙及外设模式支持。",
  };
  const summary = state.paired
    ? "Windows 已完成配对。请在下方「Windows 已配对设备」中点击绑定，应用会自动读取并验证身份。"
    : state.status === "stopped"
      ? (reasons[state.reason] || "配对窗口已关闭，本次未验证配对完成。")
      : "配对窗口已开启，等待手表连接与系统确认。";
  return `${summary} 广播：${advertising[state.advertising] || "未知"}；剩余 ${state.remaining_seconds} 秒；订阅 ${state.subscriptions}；加密读取 ${state.encrypted_reads}。广播、订阅和读取次数均不能确认手表身份。`;
}

export function pairedPanel(paired: PairedDevice[] | null, binding: boolean): string {
  if (!paired)
    return `<section class="panel"><p class="muted">正在读取 Windows 已配对的蓝牙设备…</p></section>`;
  if (!paired.length)
    return `<section class="panel"><div class="panel-title"><h2>Windows 已配对设备</h2></div><p class="muted">尚无已配对设备。完成上方配对后，这里会显示手表名称并可直接绑定。</p></section>`;
  const rows = paired
    .map(
      (d) =>
        `<tr><td><strong>${escape(d.name || "未命名设备")}</strong></td><td class="mono">${escape(d.address)}</td><td>${d.bound ? '<span class="badge green">已绑定</span>' : '<span class="muted">未绑定</span>'}</td><td>${d.bound ? "" : `<button class="text-button" data-bind-paired="${escape(d.address)}" ${binding ? "disabled" : ""}>绑定此设备 ${icon("arrow")}</button>`}</td></tr>`,
    )
    .join("");
  return `<section class="panel"><div class="panel-title"><h2>Windows 已配对设备 <span>${paired.length}</span></h2><span class="muted">${binding ? "正在请求管理员确认…" : "无需手填 IRK"}</span></div><div class="table-wrap"><table><thead><tr><th>名称</th><th>地址</th><th>状态</th><th></th></tr></thead><tbody>${rows}</tbody></table></div></section>`;
}

export function scanPage(
  observed: ObservedDevice[],
  scanning: boolean,
  pairing: boolean,
  pairingStatus: PairingStatus | null,
  paired: PairedDevice[] | null = null,
  binding = false,
): string {
  return `${header("NEARBY DISCOVERY", "发现附近的信号", "扫描持续 30 秒。设备可能不广播名称，Apple 广播也可能来自手机。", `<button class="button ${scanning ? "secondary" : "primary"}" id="scan-toggle">${icon("scan")}${scanning ? "停止扫描" : "开始扫描"}</button>`)}
    <div class="notice">${icon("shield")}<div><strong>扫描不等于配对或身份验证</strong><p>Apple Watch 需要先在系统完成配对并取得 IRK，再登记到本应用。蓝牙地址可能轮换；请勿仅凭名称绑定。</p></div></div>
    <section class="panel pairing-panel"><div><h2>第一次连接 Apple Watch？</h2><p>打开 120 秒配对窗口后，在手表「设置 → 蓝牙」中寻找这台电脑，并亲自确认 Windows 系统配对弹窗。</p><p id="pairing-progress" aria-live="polite">${escape(pairingProgress(pairing, pairingStatus))}</p></div><button class="button secondary" id="pairing-toggle">${pairing ? "停止配对窗口" : "开始 Windows 配对"}</button></section>
    ${pairedPanel(paired, binding)}
    <section class="panel"><div class="panel-title"><h2>附近广播 <span>${observed.length}</span></h2><span class="badge ${scanning ? "green" : ""}">${scanning ? "正在扫描" : "扫描未运行"}</span></div><div id="scan-results">${scanResults(observed)}</div></section>`;
}

export function scanResults(observed: ObservedDevice[]): string {
  if (!observed.length)
    return `<div class="empty">${icon("signal")}<h3>等待真实蓝牙广播</h3><p>点击“开始扫描”，确保电脑蓝牙已开启且手表位于附近。</p></div>`;
  return `<div class="table-wrap"><table><thead><tr><th>广播名称</th><th>当前地址</th><th>信号</th><th>识别结果</th><th></th></tr></thead><tbody>${observed
    .slice()
    .sort((a, b) => b.rssi - a.rssi)
    .map(
      (d) =>
        `<tr><td><strong>${escape(d.matched_name || d.name?.trim() || (d.apple ? "Apple 设备（未广播名称）" : "未知（未广播名称）"))}</strong><small class="cell-note">${d.apple ? "Apple 厂商广播 · 未确定设备类型" : "BLE 广播"}</small></td><td class="mono">${escape(d.address)}</td><td><span class="rssi">${icon("signal")}${d.rssi} dBm</span></td><td>${d.matched_device_id ? '<span class="badge green">命中已登记身份</span>' : '<span class="muted">未登记</span>'}</td><td><button class="text-button" data-bind="${escape(d.address)}">登记设备 ${icon("arrow")}</button></td></tr>`,
    )
    .join("")}</tbody></table></div>`;
}

export function devicesPage(data: Snapshot, observed: DeviceSignal[]): string {
  const hasIdentity = data.devices.some((device) => device.identity_configured);
  return `${header("DEVICE LIBRARY", "每块手表，各有边界", "多设备独立管理，Windows 登录凭据仅为当前账户保存一份。", `<button class="button primary" id="add-device">${icon("plus")}登记设备</button>`)}
    <section class="device-grid">${
      data.devices
        .map((d) =>
          deviceCard(
            d,
            observed.find((o) => o.deviceId === d.id),
          ),
        )
        .join("") ||
      '<div class="empty"><h3>尚未登记设备</h3><p>可以从附近扫描开始，也可使用已取得的 IRK 登记。</p></div>'
    }</section>
    <section class="panel credential-panel"><div><div class="eyebrow">WINDOWS CREDENTIAL</div><h2>账户解锁密码</h2><p>输入 Windows 账户密码，不支持用 Hello PIN 代替。密码经本机后端验证与加密保存。</p><p id="credential-requirement">${hasIdentity ? "设备身份已绑定，可以设置当前账户密码。" : "请先绑定设备身份，再设置当前账户密码。"}</p><span class="badge ${data.credential_configured ? "green" : ""}">${data.credential_configured ? "已保存 · 可更新" : "未设置"}</span></div><form id="credential-form"><label for="windows-password">Windows 账户密码</label><input id="windows-password" name="password" type="password" autocomplete="new-password" maxlength="1024" required ${hasIdentity ? "" : "disabled"} placeholder="仅保存在本机加密凭据库"/><div class="form-actions"><button class="button secondary" id="save-credential" type="submit" ${hasIdentity ? "" : "disabled"}>${data.credential_configured ? "更新密码" : "验证并保存"}</button>${data.credential_configured ? '<button class="text-button danger" type="button" id="clear-credential">清除凭据</button>' : ""}</div></form></section>`;
}

export function notificationsPage(data: Snapshot): string {
  const n = data.notifications;
  return `${header("NOTIFICATIONS", "让提醒，抵达手腕", "通过 Bark 推送解锁提醒；通知只用于告知，不参与解锁。")}
    <form id="notifications-form" class="panel settings-panel"><div class="settings-heading"><div class="setting-icon">${icon("notifications")}</div><div><h2>Bark 通知</h2><p>在 iPhone 安装 Bark App，复制其中的设备密钥填到这里。密钥留空会保留已有设置，保存后不会回显。<button type="button" class="text-button" data-link="bark">在 App Store 下载 Bark</button></p></div><span class="badge ${n.configured ? "green" : ""}">${n.configured ? "已配置密钥" : "待配置"}</span></div><div class="form-grid"><label>推送 API 地址<input name="endpoint" type="url" value="${escape(n.endpoint)}" required placeholder="https://api.day.app/push"/></label><label>Bark 设备密钥<input name="device_key" type="password" autocomplete="new-password" maxlength="256" placeholder="${n.configured ? "已保存；留空保留" : "输入设备密钥"}"/></label></div><label class="toggle-row"><input name="enabled" type="checkbox" ${n.enabled ? "checked" : ""}/><span><strong>启用通知</strong><small>测试通知使用已保存的地址与密钥，修改后请先保存。</small></span></label><label class="toggle-row"><input name="notify_on_unlock" type="checkbox" ${n.notify_on_unlock === false ? "" : "checked"}/><span><strong>解锁后通知</strong><small>由本应用解锁后推送一条提醒。关闭后只记录日志。</small></span></label><div class="form-actions"><button type="submit" class="button primary">保存通知设置</button><button type="button" class="button secondary" id="notify-test" ${n.configured ? "" : "disabled"} title="使用已保存的地址与密钥发送">发送测试通知</button><span class="muted">所有秘密通过桌面 IPC 传输，不写浏览器存储。</span></div></form>`;
}
