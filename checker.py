# checker.py
import os
import re
import json
import time
import queue
import asyncio
import threading
from dataclasses import dataclass
from typing import List, Optional, Dict, Set
from datetime import datetime, timedelta

import customtkinter as ctk
from tkinter import messagebox, filedialog

try:
    import aiohttp
    from aiohttp_socks import ProxyConnector
    HAS_AIO = True
except ImportError:
    HAS_AIO = False


# ---------- Конфигурация 2026 ----------
CHECK_URL = "https://api.ipify.org?format=json"
FALLBACK_URL = "http://httpbin.org/ip"
CHECK_TIMEOUT = 10
MAX_CONCURRENT = 500
TOP_N = 500
RETRIES = 2
SMART_TARGET_ALIVE = 500
SMART_BATCH_SIZE = 2000
SMART_MAX_ROUNDS = 6

# Куда автоматически сохранять каждый скачанный прокси (.txt)
AUTO_SAVE_DIR = os.path.join(os.path.expanduser("~"), "Chekdido_Downloads")

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Chekdido/2026"
)

# ---------- Источники 2026 ----------
SOURCE_URLS = {
    "http": [
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://raw.githubusercontent.com/proxyscrape/free-proxy-list/main/proxies/protocols/http/data.txt",
        "https://raw.githubusercontent.com/gfpcom/free-proxy-list/main/lists/http.txt",
        "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/http.txt",
        "https://raw.githubusercontent.com/proxmint/free-proxy-list/main/proxies/http.txt",
    ],
    "socks4": [
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
        "https://raw.githubusercontent.com/proxyscrape/free-proxy-list/main/proxies/protocols/socks4/data.txt",
        "https://raw.githubusercontent.com/gfpcom/free-proxy-list/main/lists/socks4.txt",
        "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/socks4.txt",
        "https://raw.githubusercontent.com/proxmint/free-proxy-list/main/proxies/socks4.txt",
    ],
    "socks5": [
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
        "https://raw.githubusercontent.com/proxyscrape/free-proxy-list/main/proxies/protocols/socks5/data.txt",
        "https://raw.githubusercontent.com/gfpcom/free-proxy-list/main/lists/socks5.txt",
        "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/socks5.txt",
        "https://raw.githubusercontent.com/proxmint/free-proxy-list/main/proxies/socks5.txt",
    ],
}

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


# ---------- Модель ----------
@dataclass
class ProxyItem:
    host: str
    port: int
    ptype: str
    alive: bool = False
    ping: float = 0.0
    checked: bool = False
    anonymity: str = "-"
    exit_ip: str = "-"
    protocol: str = "-"

    @property
    def addr(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def filename(self) -> str:
        """Имя .txt файла для одного прокси."""
        safe = f"{self.ptype}_{self.host}_{self.port}"
        return re.sub(r"[^\w\.\-]", "_", safe)


# ---------- Парсер ----------
PROXY_LINE_RE = re.compile(
    r"^(?:(?P<scheme>https?|socks4|socks5)://)?"
    r"(?:(?:[\w\.\-]+:[\w\.\-]+@))?"
    r"(?P<host>[\w\.\-]+):(?P<port>\d{1,5})$",
    re.IGNORECASE,
)


def parse_proxy_line(line: str, default_type: str = "http") -> Optional[ProxyItem]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    m = PROXY_LINE_RE.match(line)
    if not m:
        return None
    host = m.group("host")
    try:
        port = int(m.group("port"))
    except ValueError:
        return None
    if not (0 < port < 65536):
        return None
    scheme = (m.group("scheme") or default_type).lower()
    if scheme == "https":
        scheme = "http"
    if scheme not in ("http", "socks4", "socks5"):
        scheme = default_type
    return ProxyItem(host=host, port=port, ptype=scheme)


# ---------- Автосохранение каждого прокси в .txt ----------
_auto_save_lock = threading.Lock()


def ensure_auto_save_dir() -> str:
    try:
        os.makedirs(AUTO_SAVE_DIR, exist_ok=True)
    except Exception:
        pass
    return AUTO_SAVE_DIR


def auto_save_single(p: ProxyItem) -> Optional[str]:
    """
    Сохраняет один прокси в отдельный .txt файл.
    Имя файла: <type>_<host>_<port>.txt  (например http_1.2.3.4_8080.txt)
    Содержимое: 'http://1.2.3.4:8080'
    """
    ensure_auto_save_dir()
    path = os.path.join(AUTO_SAVE_DIR, f"{p.filename}.txt")
    try:
        with _auto_save_lock:
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"{p.ptype}://{p.addr}\n")
        return path
    except Exception as e:
        print("auto_save_single error:", e)
        return None


def auto_save_many(items: List[ProxyItem]) -> int:
    """Сохраняет каждый прокси в отдельный .txt. Возвращает количество."""
    count = 0
    for p in items:
        if auto_save_single(p):
            count += 1
    return count


# ---------- Скачивание ----------
async def fetch_source(session: aiohttp.ClientSession, url: str, ptype: str,
                       sem: asyncio.Semaphore) -> List[ProxyItem]:
    async with sem:
        try:
            timeout = aiohttp.ClientTimeout(total=20)
            async with session.get(url, timeout=timeout, ssl=False) as resp:
                if resp.status != 200:
                    return []
                text = await resp.text()
                items = []
                for line in text.splitlines():
                    item = parse_proxy_line(line, default_type=ptype)
                    if item:
                        items.append(item)
                return items
        except Exception:
            return []


async def download_all_sources(progress_cb, selected_type: str = "all",
                               stop_event: Optional[threading.Event] = None,
                               exclude_keys: Optional[Set[str]] = None,
                               save_single_cb=None) -> List[ProxyItem]:
    if exclude_keys is None:
        exclude_keys = set()

    sem = asyncio.Semaphore(20)
    source_info = []
    for ptype, urls in SOURCE_URLS.items():
        if selected_type != "all" and ptype != selected_type:
            continue
        for url in urls:
            source_info.append((url, ptype))

    timeout = aiohttp.ClientTimeout(total=30)
    headers = {"User-Agent": USER_AGENT}
    results = []

    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        tasks = [asyncio.create_task(fetch_source(session, url, ptype, sem))
                 for url, ptype in source_info]

        done = 0
        total = len(tasks)
        for coro in asyncio.as_completed(tasks):
            if stop_event and stop_event.is_set():
                break
            items = await coro
            results.append(items)
            done += 1
            progress_cb(done, total)

        for t in tasks:
            if not t.done():
                t.cancel()

    seen: Set[str] = set()
    merged: List[ProxyItem] = []
    for items in results:
        for it in items:
            key = f"{it.ptype}://{it.host}:{it.port}"
            if key in seen or key in exclude_keys:
                continue
            seen.add(key)
            merged.append(it)

            # АВТОСОХРАНЕНИЕ каждого скачанного прокси в .txt
            if save_single_cb:
                save_single_cb(it)

    return merged


class DownloaderThread(threading.Thread):
    def __init__(self, progress_cb, done_cb, stop_event,
                 selected_type="all", exclude_keys=None, save_single_cb=None):
        super().__init__(daemon=True)
        self.progress_cb = progress_cb
        self.done_cb = done_cb
        self.stop_event = stop_event
        self.selected_type = selected_type
        self.exclude_keys = exclude_keys or set()
        self.save_single_cb = save_single_cb

    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            items = loop.run_until_complete(
                download_all_sources(
                    self.progress_cb,
                    self.selected_type,
                    self.stop_event,
                    self.exclude_keys,
                    self.save_single_cb,
                )
            )
            loop.close()
            self.done_cb(items)
        except Exception as e:
            print("DownloaderThread error:", e)
            self.done_cb([])


# ---------- Живой прогресс ----------
class LiveProgress:
    def __init__(self, total: int):
        self.total = total
        self.done = 0
        self.alive = 0
        self.dead = 0
        self.start_time = time.time()
        self.lock = threading.Lock()

    def tick(self, is_alive: bool):
        with self.lock:
            self.done += 1
            if is_alive:
                self.alive += 1
            else:
                self.dead += 1

    def snapshot(self):
        with self.lock:
            done = self.done
            alive = self.alive
            dead = self.dead
        elapsed = max(time.time() - self.start_time, 0.001)
        speed = done / elapsed
        remaining = self.total - done
        eta = remaining / speed if speed > 0 else 0
        percent = done / self.total if self.total else 0
        return {
            "done": done, "total": self.total,
            "alive": alive, "dead": dead,
            "speed": speed, "eta": eta, "percent": percent,
        }


# ---------- Проверка ----------
async def _try_request(item: ProxyItem) -> Optional[Dict]:
    try:
        connector = ProxyConnector.from_url(
            f"{item.ptype}://{item.host}:{item.port}",
            rdns=True,
        )
    except Exception:
        return None

    timeout = aiohttp.ClientTimeout(total=CHECK_TIMEOUT)
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json,*/*"}

    try:
        async with aiohttp.ClientSession(
            connector=connector, timeout=timeout, headers=headers
        ) as s:
            for url in (CHECK_URL, FALLBACK_URL):
                try:
                    async with s.get(url, ssl=False) as resp:
                        if resp.status == 200:
                            data = await resp.text()
                            m = re.search(r'"ip"\s*:\s*"([^"]+)"', data)
                            exit_ip = m.group(1) if m else "-"
                            return {"exit_ip": exit_ip}
                except Exception:
                    continue
    except Exception:
        return None
    return None


async def check_one(item: ProxyItem, sem: asyncio.Semaphore, live: LiveProgress,
                    save_single_cb=None):
    async with sem:
        start = time.perf_counter()
        result = None
        for _ in range(RETRIES):
            result = await _try_request(item)
            if result:
                break

        if result:
            item.ping = (time.perf_counter() - start) * 1000
            item.alive = True
            item.exit_ip = result.get("exit_ip", "-")
            if item.exit_ip != "-" and item.exit_ip != item.host:
                item.anonymity = "elite"
            else:
                item.anonymity = "transparent"
            item.protocol = "HTTPS" if item.ptype == "http" else item.ptype.upper()
            live.tick(True)

            # Если передан колбэк — сохраняем живой прокси отдельным .txt
            if save_single_cb:
                save_single_cb(item)
        else:
            item.alive = False
            live.tick(False)
        item.checked = True


async def check_batch(items: List[ProxyItem], live: LiveProgress,
                      stop_event: threading.Event, save_single_cb=None):
    sem = asyncio.Semaphore(MAX_CONCURRENT)
    tasks = [asyncio.create_task(check_one(it, sem, live, save_single_cb))
             for it in items]

    while tasks:
        if stop_event.is_set():
            for t in tasks:
                t.cancel()
            break
        _, pending = await asyncio.wait(tasks, timeout=0.25)
        tasks = list(pending)
    await asyncio.gather(*tasks, return_exceptions=True)


class CheckerThread(threading.Thread):
    def __init__(self, items, live: LiveProgress, done_cb, stop_event,
                 save_single_cb=None):
        super().__init__(daemon=True)
        self.items = items
        self.live = live
        self.done_cb = done_cb
        self.stop_event = stop_event
        self.save_single_cb = save_single_cb

    def run(self):
        try:
            asyncio.run(check_batch(self.items, self.live, self.stop_event,
                                    self.save_single_cb))
        except Exception as e:
            print("CheckerThread error:", e)
        self.done_cb()


# ---------- Умный режим ----------
class SmartModeThread(threading.Thread):
    def __init__(self, app_ref, stop_event, selected_type, target_alive,
                 batch_size, max_rounds):
        super().__init__(daemon=True)
        self.app = app_ref
        self.stop_event = stop_event
        self.selected_type = selected_type
        self.target_alive = target_alive
        self.batch_size = batch_size
        self.max_rounds = max_rounds

    def _download_round(self, exclude_keys: Set[str]) -> List[ProxyItem]:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            items = loop.run_until_complete(
                download_all_sources(
                    self.app._smart_download_progress,
                    self.selected_type,
                    self.stop_event,
                    exclude_keys,
                    self.app._auto_save_single_safe,
                )
            )
        finally:
            loop.close()
        return items

    def _check_round(self, items: List[ProxyItem]):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            live = LiveProgress(total=len(items))
            self.app._smart_live_progress = live

            async def runner():
                await check_batch(items, live, self.stop_event,
                                  self.app._auto_save_single_safe)

            loop.run_until_complete(runner())
        finally:
            loop.close()

    def run(self):
        try:
            all_checked: List[ProxyItem] = []
            used_keys: Set[str] = set()
            alive_total: List[ProxyItem] = []

            for rnd in range(1, self.max_rounds + 1):
                if self.stop_event.is_set():
                    break

                self.app._smart_event(
                    f"Раунд {rnd}/{self.max_rounds}: скачивание...", "download")
                self.app._smart_round_start(rnd, self.max_rounds)

                batch = self._download_round(used_keys)
                if self.stop_event.is_set():
                    break
                if not batch:
                    self.app._smart_event(
                        f"Раунд {rnd}: новых прокси не найдено", "info")
                    break

                batch = batch[:self.batch_size]
                for it in batch:
                    used_keys.add(f"{it.ptype}://{it.host}:{it.port}")

                self.app._smart_event(
                    f"Раунд {rnd}: проверка {len(batch)} прокси...", "check")

                self._check_round(batch)
                all_checked.extend(batch)

                round_alive = [p for p in batch if p.alive]
                alive_total.extend(round_alive)

                self.app._smart_update_items(all_checked)

                self.app._smart_event(
                    f"Раунд {rnd}: ✅ {len(round_alive)} живых / всего {len(alive_total)}",
                    "round_done")

                if len(alive_total) >= self.target_alive:
                    self.app._smart_event(
                        f"🎯 Цель достигнута: {len(alive_total)} ≥ {self.target_alive}",
                        "done")
                    break
            else:
                self.app._smart_event(
                    f"⚠ Достигнут лимит раундов. Живых: {len(alive_total)}",
                    "info")

            self.app._smart_finish(alive_total)
        except Exception as e:
            print("SmartModeThread error:", e)
            self.app._smart_event(f"Ошибка умного режима: {e}", "error")
            self.app._smart_finish([])


# ---------- GUI ----------
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Chekdido — Proxy Checker 2026")
        self.geometry("1240x860")
        self.minsize(1080, 740)

        self.proxies: List[ProxyItem] = []
        self.checker_thread: Optional[CheckerThread] = None
        self.downloader_thread: Optional[DownloaderThread] = None
        self.smart_thread: Optional[SmartModeThread] = None
        self.stop_event = threading.Event()
        self.ui_queue = queue.Queue()
        self.live_progress: Optional[LiveProgress] = None

        self._smart_live_progress: Optional[LiveProgress] = None
        self.smart_mode = ctk.BooleanVar(value=False)
        self.smart_target = ctk.IntVar(value=SMART_TARGET_ALIVE)

        # счётчики автосохранения
        self._saved_downloaded = 0
        self._saved_alive = 0

        self._build_ui()
        self.after(60, self._process_ui_queue)

    # ---------- БАННЕР ----------
    def _build_banner(self):
        banner = ctk.CTkFrame(self, corner_radius=0, height=110,
                              fg_color=("#0b1220", "#050a17"))
        banner.pack(fill="x")
        banner.pack_propagate(False)

        left = ctk.CTkFrame(banner, fg_color="transparent")
        left.pack(side="left", fill="y", padx=28)

        logo_frame = ctk.CTkFrame(left, fg_color="transparent")
        logo_frame.pack(side="left", pady=20)

        ctk.CTkLabel(
            logo_frame, text="◤", font=ctk.CTkFont(size=38, weight="bold"),
            text_color="#22d3ee"
        ).pack(side="left", padx=(0, 4))

        text_box = ctk.CTkFrame(logo_frame, fg_color="transparent")
        text_box.pack(side="left")

        ctk.CTkLabel(
            text_box, text="Chekdido",
            font=ctk.CTkFont(family="Segoe UI", size=34, weight="bold"),
            text_color="#22d3ee"
        ).pack(anchor="w")

        ctk.CTkLabel(
            text_box, text="PROXY CHECKER  ·  2026 EDITION",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color="#64748b"
        ).pack(anchor="w")

        right = ctk.CTkFrame(banner, fg_color="transparent")
        right.pack(side="right", fill="y", padx=28)

        self.status_label = ctk.CTkLabel(
            right, text="● Готов к работе",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#22c55e"
        )
        self.status_label.pack(pady=(28, 2), anchor="e")

        ctk.CTkLabel(
            right, text=f"💾 Автосохранение: {AUTO_SAVE_DIR}",
            font=ctk.CTkFont(size=10), text_color="#64748b"
        ).pack(anchor="e")

        ctk.CTkFrame(self, height=2, fg_color="#22d3ee").pack(fill="x")

    # ---------- UI ----------
    def _build_ui(self):
        self._build_banner()

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True)

        # --- Левая панель (скролл) ---
        control_wrap = ctk.CTkFrame(body, corner_radius=14, width=300)
        control_wrap.pack(side="left", fill="y", padx=(14, 7), pady=14)
        control_wrap.pack_propagate(False)

        control = ctk.CTkScrollableFrame(control_wrap, fg_color="transparent")
        control.pack(fill="both", expand=True, padx=4, pady=4)

        # ===== УМНЫЙ РЕЖИМ =====
        ctk.CTkLabel(control, text="🧠  Умный режим",
                     font=ctk.CTkFont(size=17, weight="bold"),
                     text_color="#a78bfa").pack(padx=12, pady=(10, 4), anchor="w")

        ctk.CTkLabel(
            control,
            text="Скачивает → чекает → отбирает лучшие\nпока не наберёт цель живых",
            font=ctk.CTkFont(size=11), text_color="#64748b",
            justify="left"
        ).pack(padx=12, pady=(0, 6), anchor="w")

        self.switch_smart = ctk.CTkSwitch(
            control, text="Включить умный режим",
            variable=self.smart_mode,
            font=ctk.CTkFont(size=13, weight="bold"),
            progress_color="#a78bfa")
        self.switch_smart.pack(anchor="w", padx=12, pady=(0, 4))

        target_row = ctk.CTkFrame(control, fg_color="transparent")
        target_row.pack(fill="x", padx=12, pady=2)
        ctk.CTkLabel(target_row, text="Цель живых:",
                     font=ctk.CTkFont(size=12)).pack(side="left")
        self.target_entry = ctk.CTkEntry(
            target_row, width=80, justify="center")
        self.target_entry.insert(0, str(SMART_TARGET_ALIVE))
        self.target_entry.pack(side="right")

        ctk.CTkLabel(
            control, text=f"Порция: {SMART_BATCH_SIZE} · Раундов: {SMART_MAX_ROUNDS}",
            font=ctk.CTkFont(size=10), text_color="#64748b"
        ).pack(padx=12, pady=(2, 6), anchor="w")

        self.type_var = ctk.StringVar(value="all")
        for label, val in [("Все типы", "all"), ("HTTP", "http"),
                           ("SOCKS4", "socks4"), ("SOCKS5", "socks5")]:
            ctk.CTkRadioButton(control, text=label, value=val,
                               variable=self.type_var).pack(anchor="w", padx=16, pady=2)

        self.btn_smart = ctk.CTkButton(
            control, text="🧠  Запустить умный режим", height=44,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#8b5cf6", hover_color="#7c3aed",
            command=self.start_smart_mode)
        self.btn_smart.pack(fill="x", padx=12, pady=(10, 4))

        ctk.CTkFrame(control, height=1, fg_color="#374151").pack(fill="x", padx=12, pady=8)

        # ===== РУЧНОЙ РЕЖИМ =====
        ctk.CTkLabel(control, text="Ручной режим",
                     font=ctk.CTkFont(size=15, weight="bold"),
                     text_color="#22d3ee").pack(padx=12, pady=(4, 4), anchor="w")

        self.btn_download = ctk.CTkButton(
            control, text="⬇  Скачать прокси 2026", height=38,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#0ea5e9", hover_color="#0284c7",
            command=self.start_download)
        self.btn_download.pack(fill="x", padx=12, pady=(0, 4))

        self.btn_check = ctk.CTkButton(
            control, text="⚡  Проверить", height=38,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#16a34a", hover_color="#15803d",
            state="disabled",
            command=self.start_check)
        self.btn_check.pack(fill="x", padx=12, pady=4)

        self.btn_stop = ctk.CTkButton(
            control, text="⏹  Стоп", height=36,
            fg_color="#dc2626", hover_color="#b91c1c",
            state="disabled", command=self.stop_all)
        self.btn_stop.pack(fill="x", padx=12, pady=4)

        ctk.CTkButton(control, text="🧹  Очистить", height=34,
                      fg_color="#4b5563", hover_color="#374151",
                      command=self.clear_all).pack(fill="x", padx=12, pady=(4, 12))

        ctk.CTkFrame(control, height=1, fg_color="#374151").pack(fill="x", padx=12, pady=6)

        ctk.CTkLabel(control, text="Сохранение",
                     font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w", padx=12, pady=(4, 4))

        ctk.CTkButton(control, text="📁  Открыть папку автосейва", height=34,
                      fg_color="#334155", hover_color="#1e293b",
                      command=self.open_auto_save_dir).pack(fill="x", padx=12, pady=3)

        ctk.CTkButton(control, text="💾  Все живые (один файл)", height=32,
                      command=self.save_alive).pack(fill="x", padx=12, pady=3)
        ctk.CTkButton(control, text=f"🏆  Топ {TOP_N} (один файл)", height=32,
                      fg_color="#d97706", hover_color="#b45309",
                      command=self.save_top).pack(fill="x", padx=12, pady=3)
        ctk.CTkButton(control, text="📦  Экспорт в JSON", height=32,
                      fg_color="#0891b2", hover_color="#0e7490",
                      command=self.save_json).pack(fill="x", padx=12, pady=3)

        ctk.CTkFrame(control, height=1, fg_color="#374151").pack(fill="x", padx=12, pady=8)

        ctk.CTkButton(control, text="💾  Только HTTP", height=30,
                      command=lambda: self.save_by_type("http")).pack(fill="x", padx=12, pady=2)
        ctk.CTkButton(control, text="💾  Только SOCKS4", height=30,
                      command=lambda: self.save_by_type("socks4")).pack(fill="x", padx=12, pady=2)
        ctk.CTkButton(control, text="💾  Только SOCKS5", height=30,
                      command=lambda: self.save_by_type("socks5")).pack(fill="x", padx=12, pady=(2, 14))

        # --- Правая панель ---
        right = ctk.CTkFrame(body, corner_radius=14)
        right.pack(side="right", fill="both", expand=True, padx=(7, 14), pady=14)

        stats = ctk.CTkFrame(right, fg_color="transparent")
        stats.pack(fill="x", padx=14, pady=(14, 6))

        self.stat_total = self._stat_card(stats, "Всего", "0", "#3b82f6")
        self.stat_done  = self._stat_card(stats, "Проверено", "0", "#8b5cf6")
        self.stat_alive = self._stat_card(stats, "Живых", "0", "#22c55e")
        self.stat_dead  = self._stat_card(stats, "Мёртвых", "0", "#ef4444")
        self.stat_avg   = self._stat_card(stats, "Средний ping", "—", "#eab308")

        # Прогресс
        pbar_card = ctk.CTkFrame(right, fg_color=("#1f2937", "#0f172a"), corner_radius=12)
        pbar_card.pack(fill="x", padx=14, pady=8)

        pbar_header = ctk.CTkFrame(pbar_card, fg_color="transparent")
        pbar_header.pack(fill="x", padx=14, pady=(10, 2))
        self.progress_title = ctk.CTkLabel(pbar_header, text="📊  Прогресс",
                                           font=ctk.CTkFont(size=13, weight="bold"))
        self.progress_title.pack(side="left")
        self.percent_label = ctk.CTkLabel(
            pbar_header, text="0.0%",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#22c55e")
        self.percent_label.pack(side="right")

        self.progress = ctk.CTkProgressBar(pbar_card, height=16, corner_radius=8,
                                           progress_color="#22d3ee")
        self.progress.set(0)
        self.progress.pack(fill="x", padx=14, pady=(4, 8))

        info_row = ctk.CTkFrame(pbar_card, fg_color="transparent")
        info_row.pack(fill="x", padx=14, pady=(0, 12))

        self.progress_label = ctk.CTkLabel(
            info_row, text="0 / 0",
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color="#9ca3af")
        self.progress_label.pack(side="left")

        self.speed_label = ctk.CTkLabel(
            info_row, text="⚡ 0 /с",
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color="#38bdf8")
        self.speed_label.pack(side="left", padx=20)

        self.live_alive_label = ctk.CTkLabel(
            info_row, text="✅ 0",
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color="#22c55e")
        self.live_alive_label.pack(side="left", padx=8)

        self.live_dead_label = ctk.CTkLabel(
            info_row, text="❌ 0",
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color="#ef4444")
        self.live_dead_label.pack(side="left", padx=8)

        self.eta_label = ctk.CTkLabel(
            info_row, text="⏱ ETA —",
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color="#fbbf24")
        self.eta_label.pack(side="right")

        # Smart лог + счётчик автосейва
        bottom_row = ctk.CTkFrame(right, fg_color="transparent")
        bottom_row.pack(fill="x", padx=14, pady=(0, 4))

        self.smart_log = ctk.CTkLabel(
            bottom_row, text="",
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color="#a78bfa", anchor="w", justify="left")
        self.smart_log.pack(side="left")

        self.autosave_label = ctk.CTkLabel(
            bottom_row, text="💾 сохранено: 0",
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color="#22d3ee")
        self.autosave_label.pack(side="right")

        self.table = ctk.CTkTextbox(right, font=ctk.CTkFont(family="Consolas", size=12))
        self.table.pack(fill="both", expand=True, padx=14, pady=(6, 14))
        self.table.configure(state="disabled")

    def _stat_card(self, parent, title, value, color):
        card = ctk.CTkFrame(parent, fg_color=("#1f2937", "#0f172a"), corner_radius=10)
        card.pack(side="left", expand=True, fill="x", padx=4)
        ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=11),
                     text_color="#9ca3af").pack(pady=(8, 0))
        lbl = ctk.CTkLabel(card, text=value,
                           font=ctk.CTkFont(size=18, weight="bold"),
                           text_color=color)
        lbl.pack(pady=(0, 8))
        return lbl

    # ---------- Автосохранение ----------
    def _auto_save_single_safe(self, p: ProxyItem):
        """Колбэк для скачивания — сохранить скачанный прокси в .txt"""
        path = auto_save_single(p)
        if path:
            self._saved_downloaded += 1
            # обновляем UI нечасто (каждые 25)
            if self._saved_downloaded % 25 == 0:
                self.ui_queue.put(("autosave_update", None))

    def _auto_save_alive_safe(self, p: ProxyItem):
        """Колбэк для проверки — сохранить живой прокси в .txt"""
        path = auto_save_single(p)
        if path:
            self._saved_alive += 1
            if self._saved_alive % 25 == 0:
                self.ui_queue.put(("autosave_update", None))

    def open_auto_save_dir(self):
        ensure_auto_save_dir()
        try:
            if os.name == "nt":
                os.startfile(AUTO_SAVE_DIR)  # type: ignore
            elif os.name == "posix":
                import subprocess
                subprocess.Popen(["xdg-open", AUTO_SAVE_DIR])
        except Exception as e:
            messagebox.showinfo(
                "Папка автосохранения",
                f"{AUTO_SAVE_DIR}\n\n(не удалось открыть автоматически: {e})")

    # ---------- УМНЫЙ РЕЖИМ ----------
    def start_smart_mode(self):
        if (self.smart_thread and self.smart_thread.is_alive()) or \
           (self.checker_thread and self.checker_thread.is_alive()) or \
           (self.downloader_thread and self.downloader_thread.is_alive()):
            messagebox.showwarning("Внимание", "Процесс уже запущен.")
            return

        try:
            target = int(self.target_entry.get().strip())
            if target < 1:
                raise ValueError
        except ValueError:
            messagebox.showerror("Ошибка", "Введите корректное число живых прокси.")
            return

        self.smart_target.set(target)
        ensure_auto_save_dir()

        self.proxies.clear()
        self.live_progress = None
        self._smart_live_progress = None
        self._saved_downloaded = 0
        self._saved_alive = 0
        self._refresh_table()
        self._update_stats()
        self._update_autosave_label()

        self.stop_event.clear()
        self.progress.set(0)
        self.percent_label.configure(text="0.0%", text_color="#a78bfa")
        self.progress_label.configure(text="0 / 0")
        self.speed_label.configure(text="⚡ 0 /с")
        self.live_alive_label.configure(text="✅ 0")
        self.live_dead_label.configure(text="❌ 0")
        self.eta_label.configure(text="⏱ ETA —")
        self.progress_title.configure(text="🧠  Умный режим")
        self.smart_log.configure(text="Запуск умного режима...")
        self.status_label.configure(text="● Умный режим", text_color="#a78bfa")

        self.btn_smart.configure(state="disabled", text="⏳  Работает...")
        self.btn_download.configure(state="disabled")
        self.btn_check.configure(state="disabled")
        self.btn_stop.configure(state="normal")

        self.smart_thread = SmartModeThread(
            app_ref=self,
            stop_event=self.stop_event,
            selected_type=self.type_var.get(),
            target_alive=target,
            batch_size=SMART_BATCH_SIZE,
            max_rounds=SMART_MAX_ROUNDS,
        )
        self.smart_thread.start()
        self._update_smart_progress()

    # ---- колбэки умного режима ----
    def _smart_event(self, text: str, kind: str = "info"):
        self.ui_queue.put(("smart_event", (text, kind)))

    def _smart_round_start(self, rnd: int, total: int):
        self.ui_queue.put(("smart_round_start", (rnd, total)))

    def _smart_download_progress(self, done: int, total: int):
        self.ui_queue.put(("smart_download_progress", (done, total)))

    def _smart_update_items(self, items: List[ProxyItem]):
        self.ui_queue.put(("smart_update_items", list(items)))

    def _smart_finish(self, alive_items: List[ProxyItem]):
        self.ui_queue.put(("smart_finish", list(alive_items)))

    def _update_smart_progress(self):
        if not (self.smart_thread and self.smart_thread.is_alive()):
            return
        lp = self._smart_live_progress
        if lp:
            snap = lp.snapshot()
            self.progress.set(snap["percent"])
            self.percent_label.configure(text=f"{snap['percent'] * 100:.1f}%")
            self.progress_label.configure(text=f"{snap['done']} / {snap['total']}")
            self.speed_label.configure(text=f"⚡ {snap['speed']:.1f} /с")
            self.live_alive_label.configure(text=f"✅ {snap['alive']}")
            self.live_dead_label.configure(text=f"❌ {snap['dead']}")
            if snap["eta"] > 0 and snap["done"] < snap["total"]:
                self.eta_label.configure(
                    text=f"⏱ ETA {str(timedelta(seconds=int(snap['eta'])))}")
        if not self.stop_event.is_set():
            self.after(150, self._update_smart_progress)

    # ---------- Ручное скачивание ----------
    def start_download(self):
        if self.downloader_thread and self.downloader_thread.is_alive():
            messagebox.showwarning("Внимание", "Скачивание уже идёт.")
            return
        if self.checker_thread and self.checker_thread.is_alive():
            messagebox.showwarning("Внимание", "Дождитесь окончания проверки.")
            return
        if self.smart_thread and self.smart_thread.is_alive():
            messagebox.showwarning("Внимание", "Умный режим уже работает.")
            return

        ensure_auto_save_dir()
        self.proxies.clear()
        self._saved_downloaded = 0
        self._saved_alive = 0
        self._refresh_table()
        self._update_stats()
        self._update_autosave_label()

        self.progress.set(0)
        self.percent_label.configure(text="0.0%", text_color="#22c55e")
        self.progress_label.configure(text="0 / 0")
        self.speed_label.configure(text="⚡ загрузка")
        self.live_alive_label.configure(text="✅ 0")
        self.live_dead_label.configure(text="❌ 0")
        self.eta_label.configure(text="⏱ ETA —")
        self.progress_title.configure(text="📊  Прогресс")
        self.smart_log.configure(text="")
        self.status_label.configure(text="● Скачивание...", text_color="#fbbf24")

        self.btn_download.configure(state="disabled", text="⏳  Скачивание...")
        self.btn_check.configure(state="disabled")
        self.btn_smart.configure(state="disabled")
        self.btn_stop.configure(state="normal")

        self.stop_event.clear()
        self.live_progress = None

        self.downloader_thread = DownloaderThread(
            progress_cb=self._download_progress_cb,
            done_cb=lambda items: self.ui_queue.put(("download_done", items)),
            stop_event=self.stop_event,
            selected_type=self.type_var.get(),
            save_single_cb=self._auto_save_single_safe,
        )
        self.downloader_thread.start()

    def _download_progress_cb(self, done: int, total: int):
        self.ui_queue.put(("download_progress", (done, total)))

    # ---------- Ручная проверка ----------
    def start_check(self):
        if self.checker_thread and self.checker_thread.is_alive():
            messagebox.showwarning("Внимание", "Проверка уже идёт.")
            return
        if not self.proxies:
            messagebox.showwarning("Внимание", "Список пуст. Сначала скачайте.")
            return

        selected_type = self.type_var.get()
        if selected_type == "all":
            to_check = list(self.proxies)
        else:
            to_check = [p for p in self.proxies if p.ptype == selected_type]

        if not to_check:
            messagebox.showinfo("Инфо", "Нет прокси выбранного типа.")
            return

        for p in to_check:
            p.alive = False
            p.checked = False
            p.ping = 0.0
            p.anonymity = "-"
            p.exit_ip = "-"
            p.protocol = "-"

        ensure_auto_save_dir()
        self.stop_event.clear()
        self.progress.set(0)
        self.percent_label.configure(text="0.0%", text_color="#22c55e")
        self.progress_label.configure(text=f"0 / {len(to_check)}")
        self.speed_label.configure(text="⚡ 0 /с")
        self.live_alive_label.configure(text="✅ 0")
        self.live_dead_label.configure(text="❌ 0")
        self.eta_label.configure(text="⏱ ETA —")
        self.progress_title.configure(text="📊  Прогресс")
        self.status_label.configure(text="● Проверка...", text_color="#fbbf24")

        self.btn_check.configure(state="disabled")
        self.btn_download.configure(state="disabled")
        self.btn_smart.configure(state="disabled")
        self.btn_stop.configure(state="normal")

        self.live_progress = LiveProgress(total=len(to_check))

        self.checker_thread = CheckerThread(
            items=to_check,
            live=self.live_progress,
            done_cb=lambda: self.ui_queue.put(("done", None)),
            stop_event=self.stop_event,
            save_single_cb=self._auto_save_alive_safe,
        )
        self.checker_thread.start()
        self._update_live_progress()

    def stop_all(self):
        self.stop_event.set()
        self._log("⏹ Запрошена остановка всех процессов...")
        self.status_label.configure(text="● Остановка...", text_color="#ef4444")

    # ---------- Живое обновление ручной проверки ----------
    def _update_live_progress(self):
        if not self.live_progress:
            return
        snap = self.live_progress.snapshot()
        self.progress.set(snap["percent"])
        self.percent_label.configure(text=f"{snap['percent'] * 100:.1f}%")

        if snap["percent"] < 0.33:
            color = "#ef4444"
        elif snap["percent"] < 0.66:
            color = "#fbbf24"
        else:
            color = "#22c55e"
        self.percent_label.configure(text_color=color)

        self.progress_label.configure(text=f"{snap['done']} / {snap['total']}")
        self.speed_label.configure(text=f"⚡ {snap['speed']:.1f} /с")
        self.live_alive_label.configure(text=f"✅ {snap['alive']}")
        self.live_dead_label.configure(text=f"❌ {snap['dead']}")

        if snap["eta"] > 0 and snap["done"] < snap["total"]:
            eta_str = str(timedelta(seconds=int(snap["eta"])))
        elif snap["done"] >= snap["total"]:
            eta_str = "—"
        else:
            eta_str = "…"
        self.eta_label.configure(text=f"⏱ ETA {eta_str}")

        self.stat_alive.configure(text=str(snap["alive"]))
        self.stat_dead.configure(text=str(snap["dead"]))
        self.stat_done.configure(text=str(snap["done"]))
        self._update_autosave_label()

        if self.checker_thread and self.checker_thread.is_alive() and not self.stop_event.is_set():
            self.after(120, self._update_live_progress)

    def _update_autosave_label(self):
        self.autosave_label.configure(
            text=f"💾 {AUTO_SAVE_DIR}  ·  скачано: {self._saved_downloaded}  ·  живых: {self._saved_alive}"
        )

    # ---------- Очередь ----------
    def _process_ui_queue(self):
        try:
            while True:
                kind, payload = self.ui_queue.get_nowait()

                if kind == "download_progress":
                    done, total = payload
                    self.progress.set(done / total if total else 0)
                    self.percent_label.configure(
                        text=f"{done / total * 100:.1f}%" if total else "0%")
                    self.progress_label.configure(text=f"источников {done} / {total}")
                elif kind == "download_done":
                    self._on_download_finished(payload)
                elif kind == "done":
                    self._on_check_finished()
                elif kind == "autosave_update":
                    self._update_autosave_label()

                # --- умный режим ---
                elif kind == "smart_event":
                    text, _ = payload
                    self.smart_log.configure(text=text)
                    self._log(f"🧠 {text}")
                elif kind == "smart_round_start":
                    rnd, total = payload
                    self.smart_log.configure(text=f"Раунд {rnd}/{total}")
                elif kind == "smart_download_progress":
                    done, total = payload
                    self.progress.set(done / total if total else 0)
                    self.percent_label.configure(
                        text=f"{done / total * 100:.1f}%" if total else "0%",
                        text_color="#a78bfa")
                    self.progress_label.configure(text=f"источников {done} / {total}")
                elif kind == "smart_update_items":
                    self.proxies = payload
                    self._refresh_table()
                    self._update_stats()
                    self._update_autosave_label()
                elif kind == "smart_finish":
                    self._on_smart_finished(payload)
        except queue.Empty:
            pass
        self.after(60, self._process_ui_queue)

    def _on_download_finished(self, items: List[ProxyItem]):
        self.btn_download.configure(state="normal", text="⬇  Скачать прокси 2026")
        self.btn_smart.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.proxies = items

        selected = self.type_var.get()
        if selected != "all":
            self.proxies = [p for p in self.proxies if p.ptype == selected]

        self._refresh_table()
        self._update_stats()
        self._update_autosave_label()

        self.progress.set(1)
        self.percent_label.configure(text="100.0%", text_color="#22c55e")
        self.progress_label.configure(text=f"загружено {len(self.proxies)}")
        self.speed_label.configure(text="⚡ готово")
        self.eta_label.configure(text="⏱ ETA —")

        self._log(f"⬇ Скачано {len(self.proxies)} прокси. Каждый сохранён в {AUTO_SAVE_DIR}")
        self.status_label.configure(text="● Прокси загружены", text_color="#22c55e")

        if self.proxies:
            self.btn_check.configure(state="normal")
            messagebox.showinfo(
                "Готово",
                f"Скачано {len(self.proxies)} прокси.\n\n"
                f"Каждый сохранён отдельным .txt файлом:\n{AUTO_SAVE_DIR}\n\n"
                f"Нажмите «⚡ Проверить» для проверки.")
        else:
            self.btn_check.configure(state="disabled")
            messagebox.showwarning("Пусто",
                                   "Не удалось скачать прокси.\n"
                                   "Проверьте интернет-соединение.")

    def _on_check_finished(self):
        self.btn_check.configure(state="normal")
        self.btn_download.configure(state="normal", text="⬇  Скачать прокси 2026")
        self.btn_smart.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self._refresh_table()
        self._update_stats()
        self._update_autosave_label()

        if self.live_progress:
            snap = self.live_progress.snapshot()
            self.progress.set(snap["percent"])
            self.percent_label.configure(
                text=f"{snap['percent'] * 100:.1f}%", text_color="#22c55e")
            self.progress_label.configure(text=f"{snap['done']} / {snap['total']}")
            self.eta_label.configure(text="⏱ ETA —")
        self.status_label.configure(text="● Готово ✔", text_color="#22c55e")
        self._log(f"✅ Проверка завершена. Живых автосохранено: {self._saved_alive}")

    def _on_smart_finished(self, alive_items: List[ProxyItem]):
        self.btn_smart.configure(state="normal", text="🧠  Запустить умный режим")
        self.btn_download.configure(state="normal", text="⬇  Скачать прокси 2026")
        self.btn_stop.configure(state="disabled")

        alive_items.sort(key=lambda x: x.ping)
        target = self.smart_target.get()
        selected = self.type_var.get()
        if selected == "all":
            final = alive_items[:target]
        else:
            final = [p for p in alive_items if p.ptype == selected][:target]

        self.proxies = final
        self._refresh_table()
        self._update_stats()
        self._update_autosave_label()

        self.progress.set(1)
        self.percent_label.configure(text="100.0%", text_color="#22c55e")
        self.progress_label.configure(text=f"живых {len(final)}")
        self.speed_label.configure(text="⚡ готово")
        self.eta_label.configure(text="⏱ ETA —")
        self.progress_title.configure(text="🧠  Умный режим — готово")
        self.status_label.configure(text="● Умный режим ✔", text_color="#22c55e")

        self.btn_check.configure(state="normal" if self.proxies else "disabled")

        self._log(f"🧠 Умный режим завершён: отобрано {len(final)} лучших живых")
        messagebox.showinfo(
            "Умный режим завершён",
            (f"Отобрано {len(final)} лучших живых прокси.\n"
             f"Средний ping: {(sum(p.ping for p in final) / len(final)):.0f} мс\n\n"
             f"Все скачанные сохранены в:\n{AUTO_SAVE_DIR}")
            if final else
            "Живых прокси не найдено. Попробуйте ещё раз или смените тип."
        )

    # ---------- Сохранение (сводные файлы) ----------
    def _alive_items(self) -> List[ProxyItem]:
        return [p for p in self.proxies if p.alive and p.checked]

    def save_alive(self):
        alive = self._alive_items()
        if not alive:
            messagebox.showinfo("Инфо", "Живых прокси нет.")
            return
        alive.sort(key=lambda x: x.ping)
        self._save_to_file(alive, "alive_proxies.txt")

    def save_top(self):
        alive = self._alive_items()
        if not alive:
            messagebox.showinfo("Инфо", "Живых прокси нет.")
            return
        alive.sort(key=lambda x: x.ping)
        self._save_to_file(alive[:TOP_N], f"top_{TOP_N}_proxies.txt")

    def save_by_type(self, ptype: str):
        items = [p for p in self._alive_items() if p.ptype == ptype]
        if not items:
            messagebox.showinfo("Инфо", f"Живых {ptype.upper()} прокси нет.")
            return
        items.sort(key=lambda x: x.ping)
        self._save_to_file(items, f"alive_{ptype}.txt")

    def save_json(self):
        alive = self._alive_items()
        if not alive:
            messagebox.showinfo("Инфо", "Живых прокси нет.")
            return
        alive.sort(key=lambda x: x.ping)
        path = filedialog.asksaveasfilename(
            title="Сохранить JSON",
            defaultextension=".json",
            initialfile="chekdido_alive.json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._json_payload(alive), f, ensure_ascii=False, indent=2)
            self._log(f"📦 JSON сохранён: {len(alive)} прокси → {os.path.basename(path)}")
            messagebox.showinfo("Готово", f"JSON сохранён: {len(alive)} прокси\n{path}")
        except Exception as e:
            messagebox.showerror("Ошибка сохранения", str(e))

    def _save_to_file(self, items: List[ProxyItem], default_name: str):
        path = filedialog.asksaveasfilename(
            title="Сохранить как",
            defaultextension=".txt",
            initialfile=default_name,
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                for p in items:
                    f.write(f"{p.ptype}://{p.addr}\n")
            self._log(f"💾 Сохранено {len(items)} прокси → {os.path.basename(path)}")
            messagebox.showinfo("Готово", f"Сохранено {len(items)} прокси в:\n{path}")
        except Exception as e:
            messagebox.showerror("Ошибка сохранения", str(e))

    def _json_payload(self, items: List[ProxyItem]) -> dict:
        return {
            "source": "Chekdido 2026",
            "count": len(items),
            "proxies": [{
                "type": p.ptype,
                "host": p.host,
                "port": p.port,
                "addr": p.addr,
                "ping_ms": round(p.ping, 1),
                "anonymity": p.anonymity,
                "exit_ip": p.exit_ip,
                "protocol": p.protocol,
                "checked_at": datetime.utcnow().isoformat() + "Z",
            } for p in items],
        }

    def clear_all(self):
        if self.checker_thread and self.checker_thread.is_alive():
            messagebox.showwarning("Внимание", "Сначала остановите проверку.")
            return
        if self.downloader_thread and self.downloader_thread.is_alive():
            messagebox.showwarning("Внимание", "Дождитесь окончания скачивания.")
            return
        if self.smart_thread and self.smart_thread.is_alive():
            messagebox.showwarning("Внимание", "Дождитесь окончания умного режима.")
            return
        self.proxies.clear()
        self.live_progress = None
        self._smart_live_progress = None
        self._refresh_table()
        self._update_stats()
        self.progress.set(0)
        self.percent_label.configure(text="0.0%", text_color="#22c55e")
        self.progress_label.configure(text="0 / 0")
        self.speed_label.configure(text="⚡ 0 /с")
        self.live_alive_label.configure(text="✅ 0")
        self.live_dead_label.configure(text="❌ 0")
        self.eta_label.configure(text="⏱ ETA —")
        self.progress_title.configure(text="📊  Прогресс")
        self.smart_log.configure(text="")
        self.btn_check.configure(state="disabled")
        self.status_label.configure(text="● Готов к работе", text_color="#22c55e")
        self._log("🧹 Список очищен (файлы в папке автосейва не удаляются).")

    def _update_stats(self):
        total = len(self.proxies)
        alive = sum(1 for p in self.proxies if p.alive and p.checked)
        dead = sum(1 for p in self.proxies if p.checked and not p.alive)
        done = alive + dead
        alive_items = [p for p in self.proxies if p.alive and p.checked]
        avg = (f"{sum(p.ping for p in alive_items) / len(alive_items):.0f} мс"
               if alive_items else "—")

        self.stat_total.configure(text=str(total))
        self.stat_done.configure(text=str(done))
        self.stat_alive.configure(text=str(alive))
        self.stat_dead.configure(text=str(dead))
        self.stat_avg.configure(text=avg)

    def _refresh_table(self):
        self.table.configure(state="normal")
        self.table.delete("1.0", "end")

        lines = []
        header = (f"{'#':<5}{'ТИП':<8}{'АДРЕС':<24}{'СТАТУС':<10}"
                  f"{'PING':<10}{'АНОН':<14}{'EXIT IP':<18}\n")
        lines.append(header)
        lines.append("─" * 92 + "\n")

        def sort_key(p):
            if p.alive and p.checked:
                return (0, p.ping)
            if not p.checked:
                return (1, 0)
            return (2, 0)

        for i, p in enumerate(sorted(self.proxies, key=sort_key), 1):
            if p.checked and p.alive:
                status, ping = "✅ LIVE", f"{p.ping:.0f} мс"
                anon = p.anonymity
                exit_ip = p.exit_ip
            elif p.checked:
                status, ping, anon, exit_ip = "❌ DEAD", "—", "-", "-"
            else:
                status, ping, anon, exit_ip = "⏳ ...", "—", "-", "-"
            lines.append(f"{i:<5}{p.ptype.upper():<8}{p.addr:<24}{status:<10}"
                         f"{ping:<10}{anon:<14}{exit_ip:<18}\n")

        self.table.insert("1.0", "".join(lines))
        self.table.configure(state="disabled")

    def _log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] {msg}")


# ---------- main ----------
if __name__ == "__main__":
    if not HAS_AIO:
        print("Установите: pip install aiohttp aiohttp-socks")
        raise SystemExit(1)
    App().mainloop()