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

Все результаты сохраняются РЯДОМ со скриптом:
    socks5.txt   — все живые SOCKS5 (построчно)
    socks4.txt   — все живые SOCKS4
    http.txt     — все живые HTTP
    raw_*.txt    — свежескачанные одним файлом
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
  {C.GRN}📁 Папка со скриптом (сюда сохраняются .txt):{C.R}
  {C.CYA}   {SCRIPT_DIR}{C.R}
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
    confirmed: bool = False
    checks_passed: int = 0
    checks_total: int = 0

    @property
    def addr(self) -> str:
        return f"{self.host}:{self.port}"


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


# ======================= СОХРАНЕНИЕ ПО ТИПАМ =======================
_type_locks: Dict[str, threading.Lock] = {
    "http": threading.Lock(),
    "socks4": threading.Lock(),
    "socks5": threading.Lock(),
}


def _type_file(ptype: str) -> str:
    """Путь к общему файлу для данного типа, рядом со скриптом."""
    return os.path.join(SCRIPT_DIR, f"{ptype}.txt")


def append_alive(p: ProxyItem) -> bool:
    """Дописывает живой прокси в общий файл его типа (http.txt / socks4.txt / socks5.txt)."""
    path = _type_file(p.ptype)
    lock = _type_locks.get(p.ptype) or threading.Lock()
    try:
        with lock:
            # защита от дубликатов: читаем текущие строки
            existing = set()
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        for line in f:
                            existing.add(line.strip())
                except Exception:
                    pass
            entry = f"{p.ptype}://{p.addr}"
            if entry in existing:
                return True
            with open(path, "a", encoding="utf-8") as f:
                f.write(entry + "\n")
        return True
    except Exception:
        return False


def append_raw_batch(items: List[ProxyItem], prefix: str) -> str:
    """Сохраняет свежескачанные прокси одним файлом рядом со скриптом."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(SCRIPT_DIR, f"{prefix}_{ts}.txt")
    try:
        with open(path, "w", encoding="utf-8") as f:
            for p in items:
                f.write(f"{p.ptype}://{p.addr}\n")
        return path
    except Exception as e:
        print(f"  {C.RED}Ошибка сохранения {path}: {e}{C.R}")
        return ""


def write_summary(items: List[ProxyItem], name: str) -> str:
    """Пишет сводный файл (перезаписывает) рядом со скриптом."""
    path = os.path.join(SCRIPT_DIR, name)
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

    seen: Set[str] = set()
    merged: List[ProxyItem] = []
    for items in results:
        for it in items:
            key = f"{it.ptype}://{it.host}:{it.port}"
            if key in seen or key in exclude_keys:
                continue
            seen.add(key)
            merged.append(it)

    prefix = f"raw_{selected_type}" if selected_type != "all" else "raw_all"
    saved_path = append_raw_batch(merged, prefix)

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
    tasks = [asyncio.create_task(check_one(it, sem, pb, append_alive))
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


# ======================= БЫСТРЫЙ ЧЕК С ТОЧНОСТЬЮ =======================
async def _quick_probe(item: ProxyItem) -> bool:
    res = await _try_request(item)
    return res is not None


async def precision_check_one(item: ProxyItem, sem, pb,
                              passes: int = 3,
                              pause_between: float = 0.8):
    async with sem:
        ok_count = 0
        total_ping = 0.0
        for i in range(passes):
            start = time.perf_counter()
            ok = await _quick_probe(item)
            if ok:
                ok_count += 1
                total_ping += (time.perf_counter() - start) * 1000
            if i < passes - 1:
                await asyncio.sleep(pause_between)

        item.checks_passed = ok_count
        item.checks_total = passes
        if ok_count == passes:
            item.alive = True
            item.confirmed = True
            item.ping = total_ping / ok_count
            item.exit_ip = "-"
            item.anonymity = "elite"
            item.protocol = "HTTPS" if item.ptype == "http" else item.ptype.upper()
            pb.tick(True)
            append_alive(item)
        else:
            item.alive = False
            item.confirmed = False
            pb.tick(False)
        item.checked = True


async def precision_check_batch(items, pb, stop_event,
                                passes: int = 3,
                                pause_between: float = 0.8):
    sem = asyncio.Semaphore(max(MAX_CONCURRENT // 2, 50))
    tasks = [
        asyncio.create_task(
            precision_check_one(it, sem, pb, passes, pause_between)
        ) for it in items
    ]
    while tasks:
        if stop_event.is_set():
            for t in tasks:
                t.cancel()
            break
        _, pending = await asyncio.wait(tasks, timeout=0.25)
        tasks = list(pending)
        pb.render()
    await asyncio.gather(*tasks, return_exceptions=True)


def collect_proxy_files() -> List[str]:
    """Возвращает список .txt с одиночными прокси (без сводных и raw_*)."""
    try:
        files = []
        for f in os.listdir(SCRIPT_DIR):
            if not f.endswith(".txt"):
                continue
            if f.startswith("_") or f.startswith("raw_"):
                continue
            if f in ("http.txt", "socks4.txt", "socks5.txt",
                     "alive.txt", "alive_top500.txt"):
                continue
            files.append(os.path.join(SCRIPT_DIR, f))
        return files
    except Exception:
        return []


def load_proxies_from_files(files: List[str], limit: int) -> List[ProxyItem]:
    """Читает прокси из переданных .txt файлов (построчно)."""
    items: List[ProxyItem] = []
    seen: Set[str] = set()
    for path in files:
        if limit > 0 and len(items) >= limit:
            break
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    it = parse_proxy_line(line)
                    if not it:
                        continue
                    key = f"{it.ptype}://{it.host}:{it.port}"
                    if key in seen:
                        continue
                    seen.add(key)
                    items.append(it)
                    if limit > 0 and len(items) >= limit:
                        break
        except Exception:
            continue
    return items


def quick_precision_mode():
    """Пункт меню: быстрый чек живых с точностью."""
    # Собираем .txt с одиночными прокси
    proxy_files = collect_proxy_files()

    # Плюс общие файлы http.txt / socks4.txt / socks5.txt, если в них что-то есть
    for f in ("http.txt", "socks4.txt", "socks5.txt"):
        p = os.path.join(SCRIPT_DIR, f)
        if os.path.exists(p) and os.path.getsize(p) > 0:
            proxy_files.append(p)

    if not proxy_files:
        print(f"\n  {C.YEL}⚠ Нет .txt с прокси. Сначала скачайте прокси.{C.R}")
        print(f"  {C.GRAY}Папка: {SCRIPT_DIR}{C.R}")
        input(f"\n  {C.GRAY}Нажмите Enter...{C.R}")
        return

    print(f"\n  {C.MAG}{C.B}🎯 БЫСТРЫЙ ЧЕК ЖИВЫХ С ТОЧНОСТЬЮ{C.R}")
    print(f"  {C.GRAY}Папка: {SCRIPT_DIR}{C.R}")
    print(f"  {C.GRAY}Найдено {len(proxy_files)} .txt файлов с прокси.{C.R}\n")

    limit = ask_int("Сколько проверить (0 = все)", 500)
    if limit < 0:
        limit = 0

    passes = ask_int("Сколько проходов на каждый прокси (2-5)", 3)
    if passes < 2:
        passes = 2
    if passes > 5:
        passes = 5

    pause_ms = ask_int("Пауза между проходами, мс (0-2000)", 800)
    pause_s = max(0, min(pause_ms, 2000)) / 1000.0

    items = load_proxies_from_files(proxy_files, limit)

    if not items:
        print(f"  {C.RED}Не удалось прочитать ни один прокси.{C.R}")
        input(f"\n  {C.GRAY}Нажмите Enter...{C.R}")
        return

    print(f"\n  {C.CYA}⚡ Точная проверка {len(items)} прокси...{C.R}")
    print(f"  {C.GRAY}Проходов: {passes} · Пауза: {pause_ms} мс · "
          f"Потоков: {max(MAX_CONCURRENT // 2, 50)}{C.R}\n")

    pb = ProgressBar(len(items), label="точный чек", width=30)
    stop_event = threading.Event()
    try:
        asyncio.run(precision_check_batch(
            items, pb, stop_event, passes=passes, pause_between=pause_s
        ))
    except KeyboardInterrupt:
        stop_event.set()
    pb.finish()

    alive = [p for p in items if p.confirmed]
    alive.sort(key=lambda x: x.ping)

    total = len(items)
    confirmed = len(alive)
    accuracy = (confirmed / total * 100) if total else 0.0

    partial = [p for p in items
               if p.checked and not p.confirmed and p.checks_passed > 0]
    partial_rate = (len(partial) / total * 100) if total else 0.0

    print(f"\n  {C.B}{C.WHT}📊 РЕЗУЛЬТАТЫ ТОЧНОЙ ПРОВЕРКИ{C.R}")
    print(f"  {C.GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.R}")
    print(f"  Всего проверено:        {C.WHT}{total}{C.R}")
    print(f"  {C.GRN}✅ 100% подтверждены:   {confirmed} "
          f"({accuracy:.1f}%){C.R}")
    print(f"  {C.YEL}⚠  Прошли частично:     {len(partial)} "
          f"({partial_rate:.1f}%){C.R}")
    print(f"  {C.RED}❌ Мёртвые:              "
          f"{total - confirmed - len(partial)}{C.R}")
    print(f"  {C.GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.R}")

    if alive:
        avg_ping = sum(p.ping for p in alive) / len(alive)
        print(f"  Средний ping:           {C.CYA}{avg_ping:.0f} мс{C.R}")

        # Сводный файл только с 100% подтверждёнными
        write_summary(alive, "confirmed.txt")

        # JSON с метаданными
        payload = {
            "source": "Chekdido 2026 CLI",
            "mode": "precision",
            "passes": passes,
            "pause_ms": pause_ms,
            "count": len(alive),
            "proxies": [{
                "type": p.ptype, "host": p.host, "port": p.port,
                "addr": p.addr, "ping_ms": round(p.ping, 1),
                "checks_passed": p.checks_passed,
                "checks_total": p.checks_total,
                "confirmed": p.confirmed,
                "checked_at": datetime.utcnow().isoformat() + "Z",
            } for p in alive],
        }
        try:
            with open(os.path.join(SCRIPT_DIR, "confirmed.json"),
                      "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            print(f"  {C.CYA}📦 JSON: confirmed.json{C.R}")
        except Exception as e:
            print(f"  {C.RED}Ошибка JSON: {e}{C.R}")

        print(f"\n  {C.B}Топ-15 по ping (100% точность):{C.R}")
        for p in alive[:15]:
            print(f"    {C.GRN}✅{C.R} {p.ptype.upper():<7} "
                  f"{p.addr:<22} {p.ping:6.0f} мс  "
                  f"{C.GRAY}проходов: {p.checks_passed}/{p.checks_total}{C.R}")

        print(f"\n  {C.GRN}💾 100% подтверждённые дописаны в:{C.R}")
        print(f"  {C.CYA}   {os.path.join(SCRIPT_DIR, 'confirmed.txt')}{C.R}")
    else:
        print(f"\n  {C.RED}Ни один прокси не прошёл все проходы.{C.R}")

    input(f"\n  {C.GRAY}Нажмите Enter...{C.R}")


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
        write_summary(final, "smart_alive.txt")
        write_summary(final[:500], "smart_top500.txt")
    else:
        print(f"\n  {C.RED}Живых прокси не найдено.{C.R}")
    return final


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
        print(f"    {C.CYA}2{C.R}) ⬇  Скачать прокси 2026 (raw_*.txt)")
        print(f"    {C.GRN}3{C.R}) ⚡  Проверить скачанные прокси → {C.WHT}socks5.txt / http.txt / socks4.txt{C.R}")
        print(f"    {C.YEL}4{C.R}) 🎯  Быстрый чек живых с точностью")
        print(f"    {C.BLU}5{C.R}) 📁  Показать путь и файлы")
        print(f"    {C.GRAY}6{C.R}) 🧹  Очистить все .txt")
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
            proxy_files = collect_proxy_files()
            if not proxy_files:
                print(f"\n  {C.YEL}⚠ Нет .txt с прокси. Сначала скачайте прокси.{C.R}")
                print(f"  {C.GRAY}Папка: {SCRIPT_DIR}{C.R}")
                input(f"\n  {C.GRAY}Нажмите Enter...{C.R}")
                continue

            print(f"\n  {C.CYA}Найдено {len(proxy_files)} .txt файлов.{C.R}")
            limit = ask_int("Сколько проверить (0 = все)", 500)
            if limit < 0:
                limit = 0

            items = load_proxies_from_files(proxy_files, limit)

            if not items:
                print(f"  {C.RED}Не удалось прочитать ни один прокси.{C.R}")
                input(f"\n  {C.GRAY}Нажмите Enter...{C.R}")
                continue

            print(f"\n  {C.CYA}⚡ Проверка {len(items)} прокси...{C.R}")
            print(f"  {C.GRAY}Живые будут дописаны в socks5.txt / http.txt / socks4.txt{C.R}\n")

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
                # Сводные файлы (перезаписываются)
                write_summary(alive, "alive.txt")
                write_summary(alive[:500], "alive_top500.txt")
                for t in ("http", "socks4", "socks5"):
                    sub = [p for p in alive if p.ptype == t]
                    if sub:
                        write_summary(sub, f"alive_{t}.txt")

                # Сколько живых теперь в общих socks5.txt / http.txt / socks4.txt
                print(f"\n  {C.GRN}💾 Дописано в общие файлы:{C.R}")
                for t in ("http", "socks4", "socks5"):
                    p = os.path.join(SCRIPT_DIR, f"{t}.txt")
                    cnt = 0
                    if os.path.exists(p):
                        try:
                            with open(p, encoding="utf-8") as f:
                                cnt = sum(1 for _ in f)
                        except Exception:
                            pass
                    print(f"    {C.CYA}{t}.txt{C.R}  →  {cnt} строк")

                print(f"\n  {C.B}Топ-10 по ping:{C.R}")
                for p in alive[:10]:
                    print(f"    {C.GRN}✅{C.R} {p.ptype.upper():<7} "
                          f"{p.addr:<22} {p.ping:6.0f} мс  "
                          f"{C.GRAY}{p.anonymity:<12} {p.exit_ip}{C.R}")

            input(f"\n  {C.GRAY}Нажмите Enter...{C.R}")

        elif choice == "4":
            quick_precision_mode()

        elif choice == "5":
            print(f"\n  {C.GRN}📁 Папка со скриптом:{C.R}")
            print(f"  {C.CYA}{SCRIPT_DIR}{C.R}\n")
            files = []
            try:
                files = [f for f in os.listdir(SCRIPT_DIR) if f.endswith(".txt")]
            except Exception:
                pass
            print(f"  {C.WHT}Файлов .txt: {len(files)}{C.R}")
            for f in sorted(files):
                try:
                    size = os.path.getsize(os.path.join(SCRIPT_DIR, f))
                    if size < 1024:
                        s = f"{size} B"
                    elif size < 1024 * 1024:
                        s = f"{size / 1024:.1f} KB"
                    else:
                        s = f"{size / 1024 / 1024:.1f} MB"
                    print(f"    {C.GRAY}•{C.R} {f:<30} {C.CYA}{s}{C.R}")
                except Exception:
                    print(f"    {C.GRAY}•{C.R} {f}")
            print(f"\n  {C.YEL}Как открыть в Android:{C.R}")
            print(f"  {C.GRAY}Проводник → начните путь с /data/data/com.termux/...{C.R}")
            input(f"\n  {C.GRAY}Нажмите Enter...{C.R}")

        elif choice == "6":
            confirm = input(
                f"  {C.RED}Удалить ВСЕ .txt и .json в {SCRIPT_DIR}? (y/N):{C.R} "
            ).strip().lower()
            if confirm == "y":
                cnt = 0
                try:
                    for f in os.listdir(SCRIPT_DIR):
                        if f.endswith(".txt") or f.endswith(".json"):
                            try:
                                os.remove(os.path.join(SCRIPT_DIR, f))
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
            print(f"  {C.CYA}{SCRIPT_DIR}{C.R}\n")
            return


# ======================= СТАРТ =======================
if __name__ == "__main__":
    print(f"{C.GRN}📁 Папка со скриптом: {SCRIPT_DIR}{C.R}")
    time.sleep(0.5)

    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n  {C.CYA}Прервано. Пока! 👋{C.R}\n")