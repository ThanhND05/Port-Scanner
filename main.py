from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
import asyncio
import socket
from ipaddress import ip_address, ip_network
import concurrent.futures
import multiprocessing
import uvicorn
import os
import json
import time
import logging

# Basic config
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("scanner")

app = FastAPI()
PORT_TIMEOUT = 3  # shorter timeout to be more responsive
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
static_path = os.path.join(BASE_DIR, "static")

if os.path.exists(static_path):
    app.mount("/static", StaticFiles(directory=static_path), name="static")
else:
    logger.warning(f"'static/' directory not found at {static_path}")

# Thread pool
max_threads = max(8, multiprocessing.cpu_count() * 4)
executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_threads)

# Result folders
os.makedirs('Success_Results', exist_ok=True)
LIVE_DATA_PATH = os.path.join('Success_Results', 'Live_Data.txt')
LIVE_IP_PATH = os.path.join('Success_Results', 'Live_IP.txt')
RIP_DATA_PATH = os.path.join('Success_Results', 'RIP_Data.txt')
SUMMARY_JSON = os.path.join('Success_Results', 'summary.jsonl')  # json lines

def DATA_SAVE(result, filename):
    with open(os.path.join('Success_Results', filename), "a", encoding="utf-8") as save:
        save.write(f'{result}\n')

def SAVE_SUMMARY(obj):
    # append one json object per line
    with open(SUMMARY_JSON, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")

# -------------------------
# Utility: parse_ports
# -------------------------
def parse_ports(ports_str):
    """
    Parse string like: "22,80,8000-8005,  443"
    Return sorted list of unique ports (ints).
    """
    if not ports_str:
        return []
    parts = [p.strip() for p in ports_str.split(",") if p.strip()]
    ports_set = set()
    for part in parts:
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                a = int(a.strip()); b = int(b.strip())
            except Exception:
                continue
            if a > b:
                a, b = b, a
            a = max(1, a); b = min(65535, b)
            for p in range(a, b+1):
                ports_set.add(p)
        else:
            try:
                p = int(part)
            except Exception:
                continue
            if 1 <= p <= 65535:
                ports_set.add(p)
    return sorted(ports_set)

# -------------------------
# Banner grab helper
# -------------------------
def grab_banner(host, port, timeout=1.0):
    """
    Try to read some bytes after connecting (simple banner grab).
    Returns stripped banner str or empty.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        try:
            # some services send banner immediately
            data = s.recv(1024)
            if data:
                return data.decode(errors='ignore').strip()
        except socket.timeout:
            return ""
        finally:
            s.close()
    except Exception:
        return ""

# -------------------------
# Scanners (with cancel support & semaphore throttle)
# -------------------------
MAX_CONCURRENT_JOBS = 200  # per-scan semaphore (tune for your machine)

async def scan_ports_threaded(host, ports=None, cancel_event: asyncio.Event = None, semaphore: asyncio.Semaphore = None):
    """
    TCP connect scan per host. Uses run_in_executor for blocking connects.
    If cancel_event is set before submitting a job, we skip.
    """
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 8080, 8443]
    if cancel_event is None:
        cancel_event = asyncio.Event()
    if semaphore is None:
        semaphore = asyncio.Semaphore(50)

    loop = asyncio.get_running_loop()
    result = {"target": host, "open_ports": [], "closed_ports": [], "banners": {}}

    def _connect_port(port):
        # runs in thread
        try:
            # can't check asyncio event here; rely on submit-time checks
            conn = socket.create_connection((host, int(port)), timeout=PORT_TIMEOUT)
            conn.close()
            return (port, True)
        except Exception:
            return (port, False)

    async def schedule(port):
        if cancel_event.is_set():
            return (port, None)
        async with semaphore:
            if cancel_event.is_set():
                return (port, None)
            return await loop.run_in_executor(executor, _connect_port, port)

    tasks = [asyncio.create_task(schedule(p)) for p in ports]
    for fut in asyncio.as_completed(tasks):
        if cancel_event.is_set():
            # cancel remaining tasks
            for t in tasks:
                if not t.done():
                    t.cancel()
            break
        try:
            res = await fut
        except asyncio.CancelledError:
            break
        if not res:
            continue
        port, status = res
        label = f"{port}/tcp"
        if status is True:
            # grab banner (fast attempt) in thread to avoid blocking loop
            banner = await loop.run_in_executor(executor, grab_banner, host, port, 0.8)
            if banner:
                result["banners"][label] = banner
            DATA_SAVE(f'{host}:{label}', 'Live_Data.txt')
            result["open_ports"].append(label)
        elif status is False:
            result["closed_ports"].append(label)
        else:
            result["closed_ports"].append(label)

    # Write summary per host
    if result["open_ports"]:
        DATA_SAVE(host, 'Live_IP.txt')
    else:
        DATA_SAVE(host, 'RIP_Data.txt')
    # Save JSON summary line
    SAVE_SUMMARY({"ts": int(time.time()), "target": host, **result})
    return result

async def scan_udp_threaded(host, ports=None, cancel_event: asyncio.Event = None, semaphore: asyncio.Semaphore = None):
    """
    Simple UDP probing. UDP is tricky; timeouts treated as inconclusive.
    """
    if ports is None:
        ports = [53, 67, 68, 69, 123, 161, 500, 33434]
    if cancel_event is None:
        cancel_event = asyncio.Event()
    if semaphore is None:
        semaphore = asyncio.Semaphore(50)

    loop = asyncio.get_running_loop()
    result = {"target": host, "open_ports": [], "closed_ports": []}

    def _udp_probe(port):
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(PORT_TIMEOUT)
            s.sendto(b'\x00', (host, int(port)))
            try:
                data, addr = s.recvfrom(1024)
                return (port, True, "recv")
            except socket.timeout:
                return (port, None, "timeout")
            except ConnectionRefusedError:
                return (port, False, "icmp_unreach")
            except OSError as e:
                return (port, None, f"oserr:{e}")
        except OSError as e:
            return (port, False, f"senderr:{e}")
        finally:
            if s:
                s.close()

    async def schedule(port):
        if cancel_event.is_set():
            return (port, None, "cancel")
        async with semaphore:
            if cancel_event.is_set():
                return (port, None, "cancel")
            return await loop.run_in_executor(executor, _udp_probe, port)

    tasks = [asyncio.create_task(schedule(p)) for p in ports]
    for fut in asyncio.as_completed(tasks):
        if cancel_event.is_set():
            for t in tasks:
                if not t.done():
                    t.cancel()
            break
        try:
            port, status, info = await fut
        except asyncio.CancelledError:
            break
        label = f"{port}/udp"
        if status is True:
            DATA_SAVE(f"{host}:{label}", 'Live_Data.txt')
            result["open_ports"].append(label)
        elif status is False:
            result["closed_ports"].append(label)
        else:
            result["closed_ports"].append(label)

    if result["open_ports"]:
        DATA_SAVE(host, 'Live_IP.txt')
    else:
        DATA_SAVE(host, 'RIP_Data.txt')
    SAVE_SUMMARY({"ts": int(time.time()), "target": host, **result})
    return result

# -------------------------
# IP range helper
# -------------------------
def IP_Ranger(start_ip, end_ip):
    try:
        start = int(ip_address(start_ip))
        end = int(ip_address(end_ip))
        if end < start:
            start, end = end, start
        return [str(ip_address(ip)) for ip in range(start, end + 1)]
    except ValueError:
        return []

# -------------------------
# Web routes + websocket
# -------------------------
@app.get("/", response_class=HTMLResponse)
async def root():
    try:
        with open("static/index.html", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return HTMLResponse(f"<h1>Error loading HTML: {e}</h1>", status_code=500)

@app.websocket("/ws/scan")
async def websocket_scan(websocket: WebSocket):
    await websocket.accept()
    scan_task = None
    scan_cancel_event = asyncio.Event()

    async def fire_scanner(data):
        """
        Orchestrates scanning based on client data.
        Expects data to contain:
          - mode: "single" or "bulk"
          - ports: string
          - protocol: "tcp"/"udp"/"both"
          - ip_range / cidr
        """
        logger.info("Scanner started")
        # parse ports
        ports_ = parse_ports(data.get("ports", ""))
        if not ports_:
            # default small set
            ports_ = [22, 80, 443]

        targets = []
        mode = data.get("mode")
        if mode == "single":
            t = data.get("target", "").strip()
            if t:
                targets = [t]
        elif mode == "bulk":
            ip_range = data.get("ip_range", "").strip()
            cidr_value = data.get("cidr", "").strip()

            if "-" in ip_range:
                try:
                    targets.extend(IP_Ranger(*map(str.strip, ip_range.split("-", 1))))
                except Exception as e:
                    await websocket.send_json({"type": "error", "message": f"Invalid IP range: {e}"})
                    return

            if cidr_value:
                for cidr_line in cidr_value.splitlines():
                    cidr_line = cidr_line.strip()
                    if not cidr_line:
                        continue
                    try:
                        net = ip_network(cidr_line, strict=False)
                        ips = list(net.hosts())
                        if not ips:
                            ips = list(net)
                        targets_cidr = [str(ip) for ip in ips]
                        # scan this CIDR block inline (report progress per-cidr)
                        total_targets = len(targets_cidr)
                        completed = 0
                        open_ports_count = 0
                        closed_ports_count = 0
                        top_ported = {}
                        sem = asyncio.Semaphore(min(MAX_CONCURRENT_JOBS, 100))
                        scan_tasks = []
                        for ip in targets_cidr:
                            if data.get("protocol", "tcp").lower() in ("tcp", "both"):
                                scan_tasks.append(scan_ports_threaded(ip, ports_, cancel_event=scan_cancel_event, semaphore=sem))
                            if data.get("protocol", "tcp").lower() in ("udp", "both"):
                                scan_tasks.append(scan_udp_threaded(ip, ports_, cancel_event=scan_cancel_event, semaphore=sem))

                        for ttask in asyncio.as_completed(scan_tasks):
                            if scan_cancel_event.is_set():
                                await websocket.send_json({"status": "stopped"})
                                return
                            res = await ttask
                            completed += 1
                            open_ports_count += len(res.get("open_ports", []))
                            closed_ports_count += len(res.get("closed_ports", []))
                            for p in res.get("open_ports", []):
                                top_ported[p] = top_ported.get(p, 0) + 1
                            line = f"Target: {res.get('target')} | Open: {res.get('open_ports')} | Closed: {res.get('closed_ports')}"
                            await websocket.send_json({
                                "progress_done": completed,
                                "progress_total": total_targets,
                                "open_ports": open_ports_count,
                                "closed_ports": closed_ports_count,
                                "top_ports": top_ported,
                                "new_result_line": line,
                                "status": "running",
                                "current_cidr": cidr_line
                            })
                    except ValueError as e:
                        await websocket.send_json({"type": "error", "message": f"Invalid CIDR format: {e}"})
                        return

        # additional file lines or dedupe
        # targets += [line.strip() for line in data.get("file_lines", []) if line.strip()]
        targets = list(dict.fromkeys(filter(None, targets)))  # preserve order, unique

        if not targets:
            await websocket.send_json({"status": "done", "message": "No valid targets"})
            return

        total_targets = len(targets)
        completed = 0
        open_ports_count = 0
        closed_ports_count = 0
        top_ported = {}
        sem = asyncio.Semaphore(min(MAX_CONCURRENT_JOBS, 100))

        protocol = data.get("protocol", "tcp").lower()
        scan_tasks = []
        for ip in targets:
            if protocol in ("tcp", "both"):
                scan_tasks.append(scan_ports_threaded(ip, ports_, cancel_event=scan_cancel_event, semaphore=sem))
            if protocol in ("udp", "both"):
                scan_tasks.append(scan_udp_threaded(ip, ports_, cancel_event=scan_cancel_event, semaphore=sem))

        logger.info(f"Starting {len(scan_tasks)} tasks for {total_targets} targets")
        try:
            for ttask in asyncio.as_completed(scan_tasks):
                if scan_cancel_event.is_set():
                    await websocket.send_json({"status": "stopped"})
                    return
                res = await ttask
                completed += 1
                open_ports_count += len(res.get("open_ports", []))
                closed_ports_count += len(res.get("closed_ports", []))
                for p in res.get("open_ports", []):
                    top_ported[p] = top_ported.get(p, 0) + 1
                line = f"Target: {res.get('target')} | Open: {res.get('open_ports')} | Closed: {res.get('closed_ports')}"
                await websocket.send_json({
                    "progress_done": completed,
                    "progress_total": total_targets,
                    "open_ports": open_ports_count,
                    "closed_ports": closed_ports_count,
                    "top_ports": top_ported,
                    "new_result_line": line,
                    "status": "running"
                })
        except asyncio.CancelledError:
            logger.info("fire_scanner cancelled")
            await websocket.send_json({"status": "cancelled"})
            return

        await websocket.send_json({"status": "done"})
        logger.info("Scanner finished")

    try:
        while True:
            data = await websocket.receive_json()
            command = data.get("command", "start")
            if command == "start":
                if scan_task and not scan_task.done():
                    await websocket.send_json({"type": "error", "message": "Scan already running"})
                    continue
                scan_cancel_event.clear()
                scan_task = asyncio.create_task(fire_scanner(data))
            elif command == "stop":
                if scan_task and not scan_task.done():
                    scan_cancel_event.set()
                    # give scanner up to 5 seconds to tidy up; then cancel forcibly
                    try:
                        await asyncio.wait_for(scan_task, timeout=5)
                    except asyncio.TimeoutError:
                        scan_task.cancel()
                        try:
                            await scan_task
                        except asyncio.CancelledError:
                            pass
                    await websocket.send_json({"status": "stopped"})
                else:
                    await websocket.send_json({"type": "error", "message": "No scan is running"})
    except WebSocketDisconnect:
        logger.info("Client disconnected")
        if scan_task and not scan_task.done():
            scan_cancel_event.set()
            try:
                await asyncio.wait_for(scan_task, timeout=3)
            except Exception:
                try:
                    scan_task.cancel()
                except Exception:
                    pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except Exception:
            logger.exception("Error sending error message")

@app.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)

if __name__ == "__main__":
    logger.info(f"[+] Starting scanner with {max_threads} threads")
    uvicorn.run("main:app", host="localhost", port=8000, reload=True, log_level="info")
