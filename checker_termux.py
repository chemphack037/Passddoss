#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Chekdido 2026 — CLI Edition
Прокси-чекер для Termux и серверов без GUI.

Установка в Termux:
    pkg update && pkg upgrade -y
    pkg install python -y
    pip install aiohttp aiohttp-socks
    python checker_cli.py

ВАЖНО: все результаты сохраняются РЯДОМ со скриптом,
в подпапку "Chekdido_Downloads" в формате .txt
"""

import os
import re
import sys
import json
import time
import asyncio
import threading
from dataclasses import dataclass
from typing import List, Optional, Dict, Set
from datetime import datetime, timedelta

try:
    import aiohttp
    from aiohttp_socks import ProxyConnector
except ImportError:
    print("\n[!] Установите зависимости:")
    print("    pip install aiohttp aiohttp-socks\n")
    sys.exit(1)


# ======================= КОНФИГ =======================
CHECK_URL = "https://api.ipify.org?format=json"
FALLBACK_URL = "http://httpbin.org/ip"
CHECK_TIMEOUT = 10
MAX_CONCURRENT = 200
RETRIES = 2

SMART_TARGET_ALIVE = 500
SMART_BATCH_SIZE = 2000
SMART_MAX_ROUNDS = 6

# ===== ПАПКА АВТОСЕЙВА — РЯДОМ СО СКРИПТОМ =====
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
AUTO_SAVE_DIR = os.path.join(SCRIPT_DIR, "Chekdido_Downloads")

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Chekdido/2026"
)

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


# ======================= ЦВЕТА ANSI =======================
class C:
    R = "\033[0m"
    B = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GRN = "\033[92m"
    YEL = "\033[93m"
    BLU = "\033[94m"
    MAG = "\033[95m"
    CYA = "\033[96m"
    WHT = "\033[97m"
    GRAY = "\033[90m"


def clr():
    os.system("cls" if os.name == "nt" else "clear")


def banner():
    print(f"""{C.CYA}{C.B}
  ╔═══════════════════════════════════════════════════════════╗
  ║   ◤ Chekdido — PROXY CHECKER · 2026 EDITION (CLI)         ║
  ╚═══════════════════════════════════════════════════════════╝{C.R}
  {C.GRAY}Автоскачивание · Автопроверка · Автосохранение в .txt{C.R}
  {C.GRN}📁 Папка автосейва (рядом со скриптом):{C.R}
  {C.CYA}   {AUTO_SAVE_DIR}{C.R}
""")


# ======================= МОДЕЛЬ =======================
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
        safe = f"{self.ptype}_{self.host}_{self.port}"
        return re.sub(r"[^\w\.\-]", "_", safe)


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


# ======================= АВТОСОХРАНЕНИЕ =======================
_auto_lock = threading.Lock()


def ensure_dir():
    try:
        os.makedirs(AUTO_SAVE_DIR, exist_ok=True)
    except Exception as e:
        print(f"  {C.RED}⚠ Не могу создать папку {AUTO_SAVE_DIR}: {e}{C.R}")


def auto_save_single(p: ProxyItem) -> bool:
    """Сохраняет один живой прокси в отдельный .txt рядом со скриптом."""
    ensure_dir()
    path = os.path.join(AUTO_SAVE_DIR, f"{p.filename}.txt")
    try:
        with _auto_lock:
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"{p.ptype}://{p.addr}\n")
        return True
    except Exception:
        return False


def auto_save_raw_batch(items: List[ProxyItem], prefix: str) -> str:
    """Сохраняет СВЕЖЕСКАЧАННЫЕ прокси в один .txt рядом со скриптом."""
    ensure_dir()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(AUTO_SAVE_DIR, f"{prefix}_{ts}.txt")
    try:
        with open(path, "w", encoding="utf-8") as f:
            for p in items:
                f.write(f"{p.ptype}://{p.addr}\n")
        return path
    except Exception as e:
        print(f"  {C.RED}Ошибка сохранения {path}: {e}{C.R}")
        return ""


# ======================= ПРОГРЕСС-БАР =======================
class ProgressBar:
    def __init__(self, total: int, label: str = "", width: int = 30):
        self.total = max(total, 1)
        self.done = 0
        self.alive = 0
        self.dead = 0
        self.label = label
        self.width = width
        self.start = time.time()
        self.lock = threading.Lock()
        self._last_render = 0

    def tick(self, is_alive: bool):
        with self.lock:
            self.done += 1
            if is_alive:
                self.alive += 1
            else:
                self.dead += 1

    def _fmt_eta(self, sec: float) -> str:
        if sec <= 0 or sec > 360000:
            return "—"
        return str(timedelta(seconds=int(sec)))

    def render(self, force: bool = False):
        now = time.time()
        if not force and now - self._last_render < 0.15:
            return
        self._last_render = now

        with self.lock:
            done = self.done
            alive = self.alive
            dead = self.dead

        percent = done / self.total
        filled = int(self.width * percent)
        bar = "█" * filled + "░" * (self.width - filled)

        elapsed = max(now - self.start, 0.001)
        speed = done / elapsed
        eta = (self.total - done) / speed if speed > 0 else 0

        if percent < 0.33:
            color = C.RED
        elif percent < 0.66:
            color = C.YEL
        else:
            color = C.GRN

        line = (
            f"\r  {self.label} {color}[{bar}]{C.R} "
            f"{percent * 100:5.1f}%  "
            f"{done}/{self.total}  "
            f"{C.GRN}✅ {alive}{C.R} "
            f"{C.RED}❌ {dead}{C.R}  "
            f"{C.CYA}⚡{speed:5.1f}/с{C.R}  "
            f"{C.YEL}⏱ {self._fmt_eta(eta)}{C.R}"
        )
        try:
            term_w = os.get_terminal_size().columns
        except Exception:
            term_w = 100
        sys.stdout.write(line[:term_w].ljust(term_w - 1))
        sys.stdout.flush()

    def finish(self):
        self.render(force=True)
        sys.stdout.write("\n")
        sys.stdout.flush()


# ======================= СКАЧИВАНИЕ =======================
async def fetch_source(session, url, ptype, sem):
    async with sem:
        try:
            timeout = aiohttp.ClientTimeout(total=20)
            async with session.get(url, timeout=timeout, ssl=False) as resp:
                if resp.status != 200:
                    return []
                text = await resp.text()
                out = []
                for line in text.splitlines():
                    it = parse_proxy_line(line, default_type=ptype)
                    if it:
                        out.append(it)
                return out
        except Exception:
            return []


async def download_all(selected_type: str, exclude_keys: Set[str],
                       show_progress: bool = True):
    sem = asyncio.Semaphore(20)
    sources = []
    for ptype, urls in SOURCE_URLS.items():
        if selected_type != "all" and ptype != selected_type:
            continue
        for u in urls:
            sources.append((u, ptype))

    timeout = aiohttp.ClientTimeout(total=30)
    headers = {"User-Agent": USER_AGENT}

    print(f"\n  {C.CYA}⬇  Скачивание из {len(sources)} источников...{C.R}")
    pb = ProgressBar(len(sources), label="источники", width=25)

    results = []
    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as s:
        tasks = [asyncio.create_task(fetch_source(s, u, t, sem))
                 for u, t in sources]
        for coro in asyncio.as_completed(tasks):
            items = await coro
            results.append(items)
            pb.tick(True)
            pb.render()
    pb.finish()

    # объединяем + дедуп
    seen: Set[str] = set()
    merged: List[ProxyItem] = []
    for items in results:
        for it in items:
            key = f"{it.ptype}://{it.host}:{it.port}"
            if key in seen or key in exclude_keys:
                continue
            seen.add(key)
            merged.append(it)

    # сохраняем ВСЕ скачанные одним файлом рядом со скриптом
    prefix = f"raw_{selected_type}" if selected_type != "all" else "raw_all"
    saved_path = auto_save_raw_batch(merged, prefix)

    print(f"  {C.GRN}✅ Уникальных прокси: {len(merged)}{C.R}")
    if saved_path:
        print(f"  {C.CYA}💾 Сохранено в .txt:{C.R} {saved_path}")
    return merged


# ======================= ПРОВЕРКА =======================
async def _try_request(item: ProxyItem):
    try:
        connector = ProxyConnector.from_url(
            f"{item.ptype}://{item.host}:{item.port}", rdns=True)
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
                            return {"exit_ip": m.group(1) if m else "-"}
                except Exception:
                    continue
    except Exception:
        return None
    return None


async def check_one(item, sem, pb, save_alive_cb=None):
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
            item.anonymity = ("elite" if item.exit_ip not in ("-", item.host)
                              else "transparent")
            item.protocol = "HTTPS" if item.ptype == "http" else item.ptype.upper()
            pb.tick(True)
            if save_alive_cb:
                save_alive_cb(item)
        else:
            item.alive = False
            pb.tick(False)
        item.checked = True


async def check_batch(items, pb, stop_event):
    sem = asyncio.Semaphore(MAX_CONCURRENT)
    tasks = [asyncio.create_task(check_one(it, sem, pb, auto_save_single))
             for it in items]
    while tasks:
        if stop_event.is_set():
            for t in tasks:
                t.cancel()
            break
        _, pending = await asyncio.wait(tasks, timeout=0.25)
        tasks = list(pending)
        pb.render()
    await asyncio.gather(*tasks, return_exceptions=True)


# ======================= УМНЫЙ РЕЖИМ =======================
def smart_mode(selected_type: str, target_alive: int):
    print(f"\n  {C.MAG}{C.B}🧠  УМНЫЙ РЕЖИМ{C.R}")
    print(f"  {C.GRAY}Тип: {selected_type} · Цель: {target_alive} живых · "
          f"Порция: {SMART_BATCH_SIZE} · Раундов: {SMART_MAX_ROUNDS}{C.R}\n")

    alive_total: List[ProxyItem] = []
    used_keys: Set[str] = set()
    stop_event = threading.Event()

    try:
        for rnd in range(1, SMART_MAX_ROUNDS + 1):
            print(f"\n  {C.MAG}━━━ Раунд {rnd}/{SMART_MAX_ROUNDS} ━━━{C.R}")

            batch = asyncio.run(download_all(selected_type, used_keys))
            if not batch:
                print(f"  {C.YEL}⚠ Новых прокси нет — стоп.{C.R}")
                break

            batch = batch[:SMART_BATCH_SIZE]
            for it in batch:
                used_keys.add(f"{it.ptype}://{it.host}:{it.port}")

            print(f"  {C.CYA}⚡ Проверка {len(batch)} прокси...{C.R}")
            pb = ProgressBar(len(batch), label=f"раунд {rnd}")
            asyncio.run(check_batch(batch, pb, stop_event))
            pb.finish()

            round_alive = [p for p in batch if p.alive]
            alive_total.extend(round_alive)

            print(f"  {C.GRN}✅ Живых в раунде: {len(round_alive)}  ·  "
                  f"Всего: {len(alive_total)}/{target_alive}{C.R}")

            if len(alive_total) >= target_alive:
                print(f"  {C.GRN}{C.B}🎯 Цель достигнута!{C.R}")
                break
    except KeyboardInterrupt:
        print(f"\n  {C.RED}⏹ Прервано пользователем.{C.R}")
        stop_event.set()

    alive_total.sort(key=lambda x: x.ping)
    final = alive_total[:target_alive]

    if final:
        avg = sum(p.ping for p in final) / len(final)
        print(f"\n  {C.GRN}🏁 Итог: {len(final)} лучших живых · "
              f"Средний ping: {avg:.0f} мс{C.R}")
        save_list(final, os.path.join(AUTO_SAVE_DIR, "_smart_alive.txt"))
        save_list(final[:500], os.path.join(AUTO_SAVE_DIR, "_smart_top500.txt"))
        save_json(final, os.path.join(AUTO_SAVE_DIR, "_smart_alive.json"))
    else:
        print(f"\n  {C.RED}Живых прокси не найдено.{C.R}")
    return final


# ======================= СОХРАНЕНИЕ СВОДНЫХ =======================
def save_list(items: List[ProxyItem], path: str):
    try:
        with open(path, "w", encoding="utf-8") as f:
            for p in items:
                f.write(f"{p.ptype}://{p.addr}\n")
        print(f"  {C.CYA}💾 Сохранено {len(items)} → {path}{C.R}")
    except Exception as e:
        print(f"  {C.RED}Ошибка сохранения {path}: {e}{C.R}")


def save_json(items: List[ProxyItem], path: str):
    payload = {
        "source": "Chekdido 2026 CLI",
        "count": len(items),
        "proxies": [{
            "type": p.ptype, "host": p.host, "port": p.port,
            "addr": p.addr, "ping_ms": round(p.ping, 1),
            "anonymity": p.anonymity, "exit_ip": p.exit_ip,
            "protocol": p.protocol,
            "checked_at": datetime.utcnow().isoformat() + "Z",
        } for p in items],
    }
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        print(f"  {C.CYA}📦 JSON сохранён: {path}{C.R}")
    except Exception as e:
        print(f"  {C.RED}Ошибка JSON: {e}{C.R}")


# ======================= МЕНЮ =======================
def ask_type() -> str:
    print(f"\n  {C.B}Выберите тип прокси:{C.R}")
    print(f"    {C.CYA}1{C.R}) Все типы")
    print(f"    {C.CYA}2{C.R}) HTTP")
    print(f"    {C.CYA}3{C.R}) SOCKS4")
    print(f"    {C.CYA}4{C.R}) SOCKS5")
    while True:
        try:
            v = input(f"  {C.CYA}>{C.R} ").strip()
        except (KeyboardInterrupt, EOFError):
            return "all"
        if v == "1" or v == "":
            return "all"
        if v == "2":
            return "http"
        if v == "3":
            return "socks4"
        if v == "4":
            return "socks5"
        print(f"  {C.RED}Введите 1-4{C.R}")


def ask_int(prompt: str, default: int) -> int:
    try:
        v = input(f"  {prompt} [{C.GRN}{default}{C.R}]: ").strip()
        return int(v) if v else default
    except (ValueError, KeyboardInterrupt, EOFError):
        return default


def main_menu():
    while True:
        clr()
        banner()
        print(f"  {C.B}{C.WHT}МЕНЮ{C.R}\n")
        print(f"    {C.MAG}1{C.R}) 🧠  Умный режим (скачать → чекать → цель живых)")
        print(f"    {C.CYA}2{C.R}) ⬇  Скачать прокси 2026 (сохраняет каждый в .txt)")
        print(f"    {C.GRN}3{C.R}) ⚡  Проверить скачанные прокси")
        print(f"    {C.YEL}4{C.R}) 📁  Показать путь к папке автосейва")
        print(f"    {C.GRAY}5{C.R}) 🧹  Очистить папку автосейва")
        print(f"    {C.RED}0{C.R}) 🚪  Выход\n")

        try:
            choice = input(f"  {C.B}Выбор:{C.R} ").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n\n  {C.CYA}Пока! 👋{C.R}\n")
            return

        if choice == "1":
            selected = ask_type()
            target = ask_int("Сколько живых набрать", SMART_TARGET_ALIVE)
            smart_mode(selected, target)
            input(f"\n  {C.GRAY}Нажмите Enter для возврата в меню...{C.R}")

        elif choice == "2":
            selected = ask_type()
            items = asyncio.run(download_all(selected, set()))
            print(f"\n  {C.GRN}Всего скачано: {len(items)}{C.R}")
            input(f"\n  {C.GRAY}Нажмите Enter...{C.R}")

        elif choice == "3":
            ensure_dir()
            try:
                files = [f for f in os.listdir(AUTO_SAVE_DIR)
                         if f.endswith(".txt") and not f.startswith("_")
                         and not f.startswith("raw_")]
            except Exception:
                files = []

            if not files:
                print(f"\n  {C.YEL}⚠ Папка автосейва пуста. Сначала скачайте прокси.{C.R}")
                print(f"  {C.GRAY}Папка: {AUTO_SAVE_DIR}{C.R}")
                input(f"\n  {C.GRAY}Нажмите Enter...{C.R}")
                continue

            print(f"\n  {C.CYA}Найдено {len(files)} .txt файлов.{C.R}")
            limit = ask_int("Сколько проверить (0 = все)", 500)
            if limit <= 0:
                limit = len(files)

            items: List[ProxyItem] = []
            for fname in files[:limit]:
                try:
                    with open(os.path.join(AUTO_SAVE_DIR, fname),
                              encoding="utf-8") as f:
                        line = f.read().strip()
                    it = parse_proxy_line(line)
                    if it:
                        items.append(it)
                except Exception:
                    pass

            if not items:
                print(f"  {C.RED}Не удалось прочитать ни один прокси.{C.R}")
                input(f"\n  {C.GRAY}Нажмите Enter...{C.R}")
                continue

            pb = ProgressBar(len(items), label="проверка", width=30)
            stop_event = threading.Event()
            try:
                asyncio.run(check_batch(items, pb, stop_event))
            except KeyboardInterrupt:
                stop_event.set()
            pb.finish()

            alive = [p for p in items if p.alive and p.checked]
            alive.sort(key=lambda x: x.ping)
            print(f"\n  {C.GRN}✅ Живых: {len(alive)} из {len(items)}{C.R}")
            if alive:
                save_list(alive, os.path.join(AUTO_SAVE_DIR, "_alive_all.txt"))
                save_list(alive[:500], os.path.join(AUTO_SAVE_DIR, "_alive_top500.txt"))
                for t in ("http", "socks4", "socks5"):
                    sub = [p for p in alive if p.ptype == t]
                    if sub:
                        save_list(sub, os.path.join(AUTO_SAVE_DIR, f"_alive_{t}.txt"))
                save_json(alive, os.path.join(AUTO_SAVE_DIR, "_alive.json"))

                print(f"\n  {C.B}Топ-10 по ping:{C.R}")
                for p in alive[:10]:
                    print(f"    {C.GRN}✅{C.R} {p.ptype.upper():<7} "
                          f"{p.addr:<22} {p.ping:6.0f} мс  "
                          f"{C.GRAY}{p.anonymity:<12} {p.exit_ip}{C.R}")

            input(f"\n  {C.GRAY}Нажмите Enter...{C.R}")

        elif choice == "4":
            ensure_dir()
            print(f"\n  {C.GRN}📁 Папка автосейва:{C.R}")
            print(f"  {C.CYA}{AUTO_SAVE_DIR}{C.R}\n")
            files = []
            try:
                files = [f for f in os.listdir(AUTO_SAVE_DIR)
                         if f.endswith(".txt")]
            except Exception:
                pass
            print(f"  {C.WHT}Файлов .txt: {len(files)}{C.R}")

            # В Termux можно открыть через файловый менеджер вручную
            if files:
                print(f"\n  {C.B}Последние 10 файлов:{C.R}")
                for f in sorted(files)[-10:]:
                    print(f"    {C.GRAY}•{C.R} {f}")

            print(f"\n  {C.YEL}Как открыть в Android:{C.R}")
            print(f"  {C.GRAY}Откройте проводник и перейдите в:{C.R}")
            print(f"  {C.CYA}{AUTO_SAVE_DIR}{C.R}")
            print(f"  {C.GRAY}(начните путь с /data/data/com.termux/...){C.R}")

            input(f"\n  {C.GRAY}Нажмите Enter...{C.R}")

        elif choice == "5":
            ensure_dir()
            confirm = input(
                f"  {C.RED}Удалить все .txt и .json в {AUTO_SAVE_DIR}? (y/N):{C.R} "
            ).strip().lower()
            if confirm == "y":
                cnt = 0
                try:
                    for f in os.listdir(AUTO_SAVE_DIR):
                        if f.endswith(".txt") or f.endswith(".json"):
                            try:
                                os.remove(os.path.join(AUTO_SAVE_DIR, f))
                                cnt += 1
                            except Exception:
                                pass
                except Exception:
                    pass
                print(f"  {C.GRN}Удалено файлов: {cnt}{C.R}")
            input(f"\n  {C.GRAY}Нажмите Enter...{C.R}")

        elif choice == "0":
            print(f"\n  {C.CYA}До встречи! 👋{C.R}\n")
            print(f"  {C.GRAY}Все файлы сохранены в:{C.R}")
            print(f"  {C.CYA}{AUTO_SAVE_DIR}{C.R}\n")
            return


# ======================= СТАРТ =======================
if __name__ == "__main__":
    # Создаём папку автосейва сразу при запуске
    ensure_dir()
    print(f"{C.GRN}📁 Папка автосейва: {AUTO_SAVE_DIR}{C.R}")
    time.sleep(0.5)

    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n  {C.CYA}Прервано. Пока! 👋{C.R}\n")