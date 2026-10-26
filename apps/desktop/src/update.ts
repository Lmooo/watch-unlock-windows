import changelog from "../../../CHANGELOG.md?raw";
import { getVersion } from "@tauri-apps/api/app";
import { relaunch } from "@tauri-apps/plugin-process";
import { check, type Update } from "@tauri-apps/plugin-updater";
import { native } from "./bridge";
import { escape } from "./render";

/** Renders the changelog's `##` version headings and `-` items; any other line is a paragraph. */
export function changelogHtml(source: string = changelog): string {
  const blocks: string[] = [];
  let items: string[] = [];
  const flush = () => {
    if (items.length) blocks.push(`<ul>${items.map((item) => `<li>${escape(item)}</li>`).join("")}</ul>`);
    items = [];
  };
  for (const raw of source.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("# ")) { flush(); continue; }
    if (line.startsWith("## ")) { flush(); blocks.push(`<h3>${escape(line.slice(3))}</h3>`); continue; }
    if (line.startsWith("- ")) { items.push(line.slice(2)); continue; }
    flush();
    blocks.push(`<p>${escape(line)}</p>`);
  }
  flush();
  return blocks.join("");
}

export async function appVersion(): Promise<string> {
  return native ? getVersion().catch(() => "") : "";
}

/** A failed check is silent: it must never block or nag the app, and the user can retry. */
export async function findUpdate(): Promise<Update | null> {
  if (!native) return null;
  try { return await check(); } catch { return null; }
}

function dialog(): HTMLDialogElement {
  return document.querySelector<HTMLDialogElement>("#info-dialog")!;
}

function closeButton(): string {
  return '<button type="button" class="close-button" data-close-dialog aria-label="关闭">×</button>';
}

function bindClose(target: HTMLDialogElement): void {
  target.querySelectorAll<HTMLButtonElement>("[data-close-dialog]").forEach((button) => {
    button.onclick = () => target.close();
  });
}

/** Shows a found update; installing hands over to the setup program, which restarts the app. */
export function showUpdate(update: Update, toast: (message: string) => void): void {
  const target = dialog();
  const notes = update.body ? changelogHtml(update.body) : "<p>本次更新没有附带说明。</p>";
  target.innerHTML = `<div class="dialog-heading"><div><div class="eyebrow">UPDATE</div><h2 id="info-dialog-title">发现新版本 ${escape(update.version)}</h2></div>${closeButton()}</div>
    <div class="changelog">${notes}</div>
    <p class="form-hint" id="update-progress" aria-live="polite">更新会下载并运行安装程序，需要批准一次管理员确认；设备、密码和设置都会保留。</p>
    <div class="form-actions"><span class="spacer"></span><button type="button" class="button secondary" data-close-dialog>稍后</button><button type="button" class="button primary" id="install-update">立即更新</button></div>`;
  bindClose(target);
  const install = target.querySelector<HTMLButtonElement>("#install-update")!;
  const progress = target.querySelector<HTMLElement>("#update-progress")!;
  install.onclick = async () => {
    install.disabled = true;
    let total = 0;
    let received = 0;
    try {
      await update.downloadAndInstall((event) => {
        if (event.event === "Started") total = event.data.contentLength ?? 0;
        if (event.event === "Progress") {
          received += event.data.chunkLength;
          progress.textContent = total ? `正在下载 ${Math.min(100, Math.round((received / total) * 100))}%` : "正在下载…";
        }
        if (event.event === "Finished") progress.textContent = "下载完成，正在启动安装程序…";
      });
      await relaunch();
    } catch {
      install.disabled = false;
      progress.textContent = "更新失败：下载中断或安装包签名校验未通过。请稍后重试。";
      toast("更新没有完成，当前版本不受影响。");
    }
  };
  target.showModal();
}

/** The changelog, the running version, and a manual update check. */
export async function showChangelog(toast: (message: string) => void): Promise<void> {
  const target = dialog();
  const version = await appVersion();
  target.innerHTML = `<div class="dialog-heading"><div><div class="eyebrow">CHANGELOG</div><h2 id="info-dialog-title">更新记录</h2></div>${closeButton()}</div>
    <p class="form-hint">当前版本 ${escape(version || "未知")}</p>
    <div class="changelog">${changelogHtml()}</div>
    <div class="form-actions"><span class="spacer"></span><button type="button" class="button secondary" id="check-update" ${native ? "" : "disabled"}>检查更新</button></div>`;
  bindClose(target);
  const button = target.querySelector<HTMLButtonElement>("#check-update")!;
  button.onclick = async () => {
    button.disabled = true;
    button.textContent = "正在检查…";
    const update = await findUpdate();
    if (update) { target.close(); showUpdate(update, toast); return; }
    button.disabled = false;
    button.textContent = "检查更新";
    toast("已经是最新版本，或暂时连不上更新服务器。");
  };
  target.showModal();
}
