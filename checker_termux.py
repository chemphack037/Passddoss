#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Chekdido 2026 — CLI Edition
Прокси-чекер для Termux и серверов без GUI.

Логика:
    1) Скачивание → ВСЕ прокси падают в socks5.txt (или http.txt / socks4.txt)
    2) Проверка   → из этого же файла удаляются мёртвые, остаются только живые
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
  {C.GRAY}Скачать → всё в socks5.txt · Проверить → оставить живые{C.R}
  {C.GRN}📁 Папка со скриптом:{C.R}
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

    @property
    def uri(self) -> str:
        return f"{self.ptype}://{self.host}:{self.port}"


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


# ======================= ФАЙЛЫ ПО ТИПАМ =======================
_type_locks: Dict[str, threading.Lock] = {
    "http": threading.Lock(),
    "socks4": threading.Lock(),
    "socks5": threading.Lock(),
}


def type_file(ptype: str) -> str:
    """Путь к общему файлу типа рядом со скриптом: socks5.txt / http.txt / socks4.txt"""
    return os.path.join(SCRIPT_DIR, f"{ptype}.txt")


def read_all_from_file(ptype: str) -> List[ProxyItem]:
    """Читает все прокси из socks5.txt (или http.txt / socks4.txt)."""
    path = type_file(ptype)
    if not os.path.exists(path):
        return []
    items: List[ProxyItem] = []
    seen: Set[str] = set()
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                it = parse_proxy_line(line, default_type=ptype)
                if not it:
                    continue
                key = f"{it.ptype}://{it.host}:{it.port}"
                if key in seen:
                    continue
                seen.add(key)
                items.append(it)
    except Exception:
        pass
    return items


def write_all_to_file(ptype: str, items: List[ProxyItem]) -> str:
    """Перезаписывает файл типа (например socks5.txt) списком прокси."""
    path = type_file(ptype)
    lock = _type_locks.get(ptype) or threading.Lock()
    try:
        with lock:
            with open(path, "w", encoding="utf-8") as f:
                for p in items:
                    f.write(f"{p.ptype}://{p.addr}\n")
        return path
    except Exception as e:
        print(f"  {C.RED}Ошибка записи {path}: {e}{C.R}")
        return ""


def append_to_type_file(ptype: str, items: List[ProxyItem]) -> int:
    """Дописывает прокси в socks5.txt, пропуская дубликаты. Возвращает сколько добавлено."""
    if not items:
        return 0
    path = type_file(ptype)
    lock = _type_locks.get(ptype) or threading.Lock()
    added = 0
    try:
        with lock:
            existing: Set[str] = set()
            if os.path.exists(path):
                try:
                    with open(path, encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                existing.add(line)
                except Exception:
                    pass
            with open(path, "a", encoding="utf-8") as f:
                for p in items:
                    entry = f"{p.ptype}://{p.addr}"
                    if entry in existing:
                        continue
                    existing.add(entry)
                    f.write(entry + "\n")
                    added += 1
    except Exception as e:
        print(f"  {C.RED}Ошибка дописывания {path}: {e}{C.R}")
    return added


def count_lines(ptype: str) -> int:
    """Сколько строк в socks5.txt."""
    path = type_file(ptype)
    if not os.path.exists(path):
        return 0
    try:
        with open(path, encoding="utf-8") as f:
            return sum(1 for line in f if line.strip())
    except Exception:
        return 0


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


async def download_all(selected_type: str, exclude_keys: Set[str]):
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

    # Объединяем и дедуплицируем
    seen: Set[str] = set()
    merged: List[ProxyItem] = []
    for items in results:
        for it in items:
            key = f"{it.ptype}://{it.host}:{it.port}"
            if key in seen or key in exclude_keys:
                continue
            seen.add(key)
            merged.append(it)

    # Разбиваем по типам и дописываем в socks5.txt / http.txt / socks4.txt
    by_type: Dict[str, List[ProxyItem]] = {"http": [], "socks4": [], "socks5": []}
    for p in merged:
        by_type[p.ptype].append(p)

    print(f"\n  {C.GRN}✅ Уникальных прокси: {len(merged)}{C.R}")
    print(f"  {C.CYA}📥 Дописано в файлы:{C.R}")
    for t in ("http", "socks4", "socks5"):
        added = append_to_type_file(t, by_type[t])
        total_in_file = count_lines(t)
        print(f"    {C.WHT}{t}.txt{C.R}  →  +{added}  (всего: {total_in_file})")

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


async def check_one(item, sem, pb):
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
        else:
            item.alive = False
            pb.tick(False)
        item.checked = True


async def check_batch(items, pb, stop_event):
    sem = asyncio.Semaphore(MAX_CONCURRENT)
    tasks = [asyncio.create_task(check_one(it, sem, pb)) for it in items]
    while tasks:
        if stop_event.is_set():
            for t in tasks:
                t.cancel()
            break
        _, pending = await asyncio.wait(tasks, timeout=0.25)
        tasks = list(pending)
        pb.render()
    await asyncio.gather(*tasks, return_exceptions=True)


# ======================= ЧЕК ФАЙЛА И ОСТАВИТЬ ЖИВЫЕ =======================
def check_and_keep_alive(ptype: str):
    """Проверяет socks5.txt (или http.txt / socks4.txt) и оставляет только живые."""
    path = type_file(ptype)

    if not os.path.exists(path):
        print(f"\n  {C.YEL}⚠ Файл {path} не найден.{C.R}")
        print(f"  {C.GRAY}Сначала скачайте прокси (пункт 2).{C.R}")
        input(f"\n  {C.GRAY}Нажмите Enter...{C.R}")
        return

    items = read_all_from_file(ptype)
    if not items:
        print(f"\n  {C.YEL}⚠ {ptype}.txt пустой.{C.R}")
        input(f"\n  {C.GRAY}Нажмите Enter...{C.R}")
        return

    print(f"\n  {C.GRN}{C.B}⚡ ЧЕК {ptype.upper()} И ОСТАВИТЬ ЖИВЫЕ{C.R}")
    print(f"  {C.GRAY}Файл: {path}{C.R}")
    print(f"  {C.GRAY}Всего в файле: {len(items)}{C.R}\n")

    confirm = input(f"  {C.YEL}Начать проверку всех {len(items)} прокси? (Y/n):{C.R} ").strip().lower()
    if confirm == "n":
        return

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

    # ПЕРЕЗАПИСЫВАЕМ socks5.txt — только живые
    write_all_to_file(ptype, alive)
    print(f"  {C.CYA}💾 {ptype}.txt перезаписан: осталось {len(alive)} живых{C.R}")

    # Отдельная сводка топ-500 (опционально)
    top_path = os.path.join(SCRIPT_DIR, f"{ptype}_top500.txt")
    try:
        with open(top_path, "w", encoding="utf-8") as f:
            for p in alive[:500]:
                f.write(f"{p.ptype}://{p.addr}\n")
        print(f"  {C.CYA}📄 Топ-500: {os.path.basename(top_path)}{C.R}")
    except Exception:
        pass

    if alive:
        print(f"\n  {C.B}Топ-10 по ping:{C.R}")
        for p in alive[:10]:
            print(f"    {C.GRN}✅{C.R} {p.addr:<24} {p.ping:6.0f} мс  "
                  f"{C.GRAY}{p.anonymity:<12} {p.exit_ip}{C.R}")

    input(f"\n  {C.GRAY}Нажмите Enter...{C.R}")


# ======================= ТОЧНЫЙ ЧЕК (оставляет 100% стабильные) =======================
async def precision_check_one(item, sem, pb, passes, pause_between):
    async with sem:
        ok_count = 0
        total_ping = 0.0
        for i in range(passes):
            start = time.perf_counter()
            res = await _try_request(item)
            if res is not None:
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
            item.anonymity = "elite"
            pb.tick(True)
        else:
            item.alive = False
            item.confirmed = False
            pb.tick(False)
        item.checked = True


async def precision_check_batch(items, pb, stop_event, passes, pause_between):
    sem = asyncio.Semaphore(max(MAX_CONCURRENT // 2, 50))
    tasks = [asyncio.create_task(
        precision_check_one(it, sem, pb, passes, pause_between)
    ) for it in items]
    while tasks:
        if stop_event.is_set():
            for t in tasks:
                t.cancel()
            break
        _, pending = await asyncio.wait(tasks, timeout=0.25)
        tasks = list(pending)
        pb.render()
    await asyncio.gather(*tasks, return_exceptions=True)


def precision_mode(ptype: str):
    """Точная проверка: N проходов, оставляем только 100% подтверждённые."""
    path = type_file(ptype)
    if not os.path.exists(path):
        print(f"\n  {C.YEL}⚠ Файл {path} не найден.{C.R}")
        input(f"\n  {C.GRAY}Нажмите Enter...{C.R}")
        return

    items = read_all_from_file(ptype)
    if not items:
        print(f"\n  {C.YEL}⚠ {ptype}.txt пустой.{C.R}")
        input(f"\n  {C.GRAY}Нажмите Enter...{C.R}")
        return

    print(f"\n  {C.MAG}{C.B}🎯 ТОЧНЫЙ ЧЕК {ptype.upper()}{C.R}")
    print(f"  {C.GRAY}Файл: {path}{C.R}")
    print(f"  {C.GRAY}Всего в файле: {len(items)}{C.R}\n")

    limit = ask_int("Сколько проверить (0 = все)", 500)
    if limit > 0:
        items = items[:limit]

    passes = ask_int("Сколько проходов на каждый прокси (2-5)", 3)
    passes = max(2, min(passes, 5))

    pause_ms = ask_int("Пауза между проходами, мс (0-2000)", 800)
    pause_s = max(0, min(pause_ms, 2000)) / 1000.0

    print(f"\n  {C.CYA}⚡ Точная проверка {len(items)} прокси...{C.R}")
    print(f"  {C.GRAY}Проходов: {passes} · Пауза: {pause_ms} мс{C.R}\n")

    pb = ProgressBar(len(items), label="точный чек", width=30)
    stop_event = threading.Event()
    try:
        asyncio.run(precision_check_batch(
            items, pb, stop_event, passes, pause_s
        ))
    except KeyboardInterrupt:
        stop_event.set()
    pb.finish()

    confirmed = [p for p in items if p.confirmed]
    confirmed.sort(key=lambda x: x.ping)

    print(f"\n  {C.B}{C.WHT}📊 РЕЗУЛЬТАТ{C.R}")
    print(f"  {C.GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.R}")
    print(f"  Проверено:              {C.WHT}{len(items)}{C.R}")
    print(f"  {C.GRN}✅ 100% подтверждены:    {len(confirmed)}{C.R}")
    print(f"  {C.RED}❌ Не прошли:            {len(items) - len(confirmed)}{C.R}")
    print(f"  {C.GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.R}")

    # ПЕРЕЗАПИСЫВАЕМ socks5.txt — только 100% подтверждённые
    write_all_to_file(ptype, confirmed)
    print(f"  {C.CYA}💾 {ptype}.txt перезаписан: {len(confirmed)} "
          f"100% стабильных{C.R}")

    if confirmed:
        avg = sum(p.ping for p in confirmed) / len(confirmed)
        print(f"  Средний ping:           {C.CYA}{avg:.0f} мс{C.R}")

        print(f"\n  {C.B}Топ-15:{C.R}")
        for p in confirmed[:15]:
            print(f"    {C.GRN}✅{C.R} {p.addr:<24} {p.ping:6.0f} мс  "
                  f"{C.GRAY}проходов: {p.checks_passed}/{p.checks_total}{C.R}")

    input(f"\n  {C.GRAY}Нажмите Enter...{C.R}")


# ======================= УМНЫЙ РЕЖИМ =======================
def smart_mode(selected_type: str, target_alive: int):
    print(f"\n  {C.MAG}{C.B}🧠  УМНЫЙ РЕЖИМ{C.R}")
    print(f"  {C.GRAY}Тип: {selected_type} · Цель: {target_alive} живых{C.R}\n")

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
        print(f"\n  {C.RED}⏹ Прервано.{C.R}")
        stop_event.set()

    alive_total.sort(key=lambda x: x.ping)
    final = alive_total[:target_alive]

    if final:
        avg = sum(p.ping for p in final) / len(final)
        print(f"\n  {C.GRN}🏁 Итог: {len(final)} живых · Средний ping: {avg:.0f} мс{C.R}")

        # Дописываем в общий файл типа
        by_type: Dict[str, List[ProxyItem]] = {"http": [], "socks4": [], "socks5": []}
        for p in final:
            by_type[p.ptype].append(p)
        for t in ("http", "socks4", "socks5"):
            if by_type[t]:
                added = append_to_type_file(t, by_type[t])
                print(f"  {C.CYA}💾 {t}.txt: +{added} "
                      f"(всего {count_lines(t)}){C.R}")
    else:
        print(f"\n  {C.RED}Живых прокси не найдено.{C.R}")
    return final


# ======================= МЕНЮ =======================
def ask_type(allow_all: bool = True) -> str:
    print(f"\n  {C.B}Выберите тип прокси:{C.R}")
    if allow_all:
        print(f"    {C.CYA}1{C.R}) Все типы")
        print(f"    {C.CYA}2{C.R}) HTTP")
        print(f"    {C.CYA}3{C.R}) SOCKS4")
        print(f"    {C.CYA}4{C.R}) SOCKS5")
    else:
        print(f"    {C.CYA}1{C.R}) HTTP")
        print(f"    {C.CYA}2{C.R}) SOCKS4")
        print(f"    {C.CYA}3{C.R}) SOCKS5")
    while True:
        try:
            v = input(f"  {C.CYA}>{C.R} ").strip()
        except (KeyboardInterrupt, EOFError):
            return "all" if allow_all else "socks5"
        if allow_all:
            if v == "1" or v == "":
                return "all"
            if v == "2":
                return "http"
            if v == "3":
                return "socks4"
            if v == "4":
                return "socks5"
        else:
            if v == "1" or v == "":
                return "http"
            if v == "2":
                return "socks4"
            if v == "3":
                return "socks5"
        print(f"  {C.RED}Неверный ввод{C.R}")


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
        print(f"    {C.CYA}1{C.R}) ⬇  Скачать прокси  →  в socks5.txt / http.txt / socks4.txt")
        print(f"    {C.GRN}2{C.R}) ⚡  Проверить {C.WHT}socks5.txt{C.R}  →  оставить только живые")
        print(f"    {C.YEL}3{C.R}) 🎯  Точный чек (N проходов, 100% стабильные)")
        print(f"    {C.MAG}4{C.R}) 🧠  Умный режим (качать + чекать до цели)")
        print(f"    {C.BLU}5{C.R}) 📁  Показать файлы")
        print(f"    {C.GRAY}6{C.R}) 🧹  Очистить всё")
        print(f"    {C.RED}0{C.R}) 🚪  Выход\n")

        # Показываем текущие размеры файлов
        print(f"  {C.GRAY}Текущее состояние:{C.R}")
        for t in ("http", "socks4", "socks5"):
            n = count_lines(t)
            marker = f"{C.GRN}✓{C.R}" if n > 0 else f"{C.GRAY}·{C.R}"
            print(f"    {marker} {t}.txt: {C.WHT}{n}{C.R} строк")
        print()

        try:
            choice = input(f"  {C.B}Выбор:{C.R} ").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n\n  {C.CYA}Пока! 👋{C.R}\n")
            return

        if choice == "1":
            selected = ask_type(allow_all=True)
            asyncio.run(download_all(selected, set()))
            input(f"\n  {C.GRAY}Нажмите Enter...{C.R}")

        elif choice == "2":
            ptype = ask_type(allow_all=False)
            check_and_keep_alive(ptype)

        elif choice == "3":
            ptype = ask_type(allow_all=False)
            precision_mode(ptype)

        elif choice == "4":
            selected = ask_type(allow_all=True)
            target = ask_int("Сколько живых набрать", SMART_TARGET_ALIVE)
            smart_mode(selected, target)
            input(f"\n  {C.GRAY}Нажмите Enter...{C.R}")

        elif choice == "5":
            print(f"\n  {C.GRN}📁 Папка:{C.R} {C.CYA}{SCRIPT_DIR}{C.R}\n")
            try:
                files = sorted(f for f in os.listdir(SCRIPT_DIR) if f.endswith(".txt"))
            except Exception:
                files = []
            if not files:
                print(f"  {C.GRAY}Нет .txt файлов.{C.R}")
            for f in files:
                p = os.path.join(SCRIPT_DIR, f)
                try:
                    size = os.path.getsize(p)
                    lines = 0
                    if f in ("http.txt", "socks4.txt", "socks5.txt"):
                        lines = count_lines(f[:-4])
                    if size < 1024:
                        s = f"{size} B"
                    elif size < 1024 * 1024:
                        s = f"{size/1024:.1f} KB"
                    else:
                        s = f"{size/1024/1024:.1f} MB"
                    extra = f"  {C.GRAY}({lines} строк){C.R}" if lines else ""
                    print(f"    {C.WHT}{f:<28}{C.R} {C.CYA}{s}{C.R}{extra}")
                except Exception:
                    print(f"    {f}")
            input(f"\n  {C.GRAY}Нажмите Enter...{C.R}")

        elif choice == "6":
            confirm = input(
                f"  {C.RED}Удалить все .txt и .json в {SCRIPT_DIR}? (y/N):{C.R} "
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
            print(f"  {C.GRAY}Файлы:{C.R}")
            for t in ("http", "socks4", "socks5"):
                print(f"    {C.CYA}{t}.txt{C.R}  ({count_lines(t)} строк)")
            print()
            return


# ======================= СТАРТ =======================
if __name__ == "__main__":
    print(f"{C.GRN}📁 Папка со скриптом: {SCRIPT_DIR}{C.R}")
    time.sleep(0.3)

    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n  {C.CYA}Прервано. Пока! 👋{C.R}\n")