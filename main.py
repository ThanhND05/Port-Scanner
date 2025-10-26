import sys
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
from scapy.all import IP, TCP, sr1, RandShort
import asyncio.subprocess
import xml.etree.ElementTree as ET
import subprocess

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("scanner")

app = FastAPI()
PORT_TIMEOUT = 3
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
static_path = os.path.join(BASE_DIR, "static")

if os.path.exists(static_path):
    app.mount("/static", StaticFiles(directory=static_path), name="static")
else:
    logger.warning(f"'static/' directory not found at {static_path}")


max_threads = max(8, multiprocessing.cpu_count() * 4)
executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_threads)


os.makedirs('Success_Results', exist_ok=True)
SUMMARY_JSON = os.path.join('Success_Results', 'summary.jsonl')

def DATA_SAVE(result, filename):
    with open(os.path.join('Success_Results', filename), "a", encoding="utf-8") as save:
        save.write(f'{result}\n')

def SAVE_SUMMARY(obj):
    with open(SUMMARY_JSON, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def parse_ports(ports_str):
    if not ports_str: return []
    parts = [p.strip() for p in ports_str.split(",") if p.strip()]
    ports_set = set()
    for part in parts:
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                a, b = int(a.strip()), int(b.strip())
                if a > b: a, b = b, a
                a, b = max(1, a), min(65535, b)
                ports_set.update(range(a, b + 1))
            except Exception: continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535: ports_set.add(p)
            except Exception: continue
    return sorted(ports_set)

def grab_banner(host, port, timeout=1.0):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        try:
            data = s.recv(1024)
            return data.decode(errors='ignore').strip() if data else ""
        finally:
            s.close()
    except Exception:
        return ""
def IP_Ranger(start_ip, end_ip):
    try:
        start, end = int(ip_address(start_ip)), int(ip_address(end_ip))
        if end < start: start, end = end, start
        return [str(ip_address(ip)) for ip in range(start, end + 1)]
    except ValueError: return []

async def watch_cancel(proc: asyncio.subprocess.Process, cancel_event: asyncio.Event):
    await cancel_event.wait()
    logger.info(f"Yêu cầu huỷ nhận được, đang dừng Nmap process {proc.pid}")
    try:
        proc.terminate()
    except ProcessLookupError:
        pass 

MAX_CONCURRENT_JOBS = 200

async def scan_ports_threaded(host, ports, cancel_event, semaphore):
    loop = asyncio.get_running_loop()
    result = {"target": host, "open_ports": [], "closed_ports": [],"filtered_ports": [], "banners": {}}
    try:
        resolved_ip = await loop.run_in_executor(executor, socket.gethostbyname, host)
    except (socket.gaierror, socket.error) as e:
        logger.warning(f"Could not resolve host: {host}. Error: {e}")
        result["error"] = f"Could not resolve host: {host}"
        SAVE_SUMMARY({"ts": int(time.time()), "target": host, **result})
        return result
    def _connect_port(port):
        try:
            socket.create_connection((resolved_ip, port), timeout=PORT_TIMEOUT).close()
            return port, "open"
        except socket.timeout: return port, "filtered"
        except ConnectionRefusedError: return port, "closed"
        except Exception: return port, "filtered"
    async def schedule(port):
        if cancel_event.is_set(): return None
        async with semaphore:
            if cancel_event.is_set(): return None
            return await loop.run_in_executor(executor, _connect_port, port)
    tasks = [schedule(p) for p in ports]
    for fut in asyncio.as_completed(tasks):
        try:
            res = await fut
            if not res or cancel_event.is_set(): continue
            port, status = res
            label = f"{port}/tcp"
            if status == "open":
                banner = await loop.run_in_executor(executor, grab_banner, resolved_ip, port, 0.8)
                if banner: result["banners"][label] = banner
                result["open_ports"].append(label)
            elif status == "closed":
                result["closed_ports"].append(label)
            elif status == "filtered":
                result["filtered_ports"].append(label)
        except asyncio.CancelledError: break
    if result["open_ports"]: DATA_SAVE(host, 'Live_IP.txt')
    else: DATA_SAVE(host, 'RIP_Data.txt')
    for p in result["open_ports"]: DATA_SAVE(f'{host}:{p}', 'Live_Data.txt')
    SAVE_SUMMARY({"ts": int(time.time()), "target": host, **result})
    return result

def _syn_probe(host, port, timeout=PORT_TIMEOUT):
    packet = IP(dst=host) / TCP(sport=RandShort(), dport=port, flags="S")
    response = sr1(packet, timeout=timeout, verbose=0)
    if response is None:
        return port, None 
        
    elif response.haslayer(TCP):
        flags = response.getlayer(TCP).flags
        
        if flags == 0x12:
            sr1(IP(dst=host) / TCP(sport=packet[TCP].sport, dport=port, flags="R"), timeout=1, verbose=0)
            return port, True 
            
        elif flags == 0x14: 
            return port, False 
    return port, None

def _ack_probe(host, port, timeout=PORT_TIMEOUT):
    try:
        packet = IP(dst=host) / TCP(sport=RandShort(), dport=port, flags="A")
        response = sr1(packet, timeout=timeout, verbose=0)
        
        if response is None:
            return port, False 
            
        elif response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x4: 
                return port, True
        return port, False
    except Exception as e:
        logger.error(f"Lỗi _ack_probe {host}:{port}: {e}")
        return port, False

async def scan_udp_threaded(host, ports, cancel_event, semaphore):
    loop = asyncio.get_running_loop()
    result = {"target": host, "open_ports": [], "closed_ports": []}
    def _udp_probe(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(PORT_TIMEOUT)
                s.sendto(b'\x00', (host, port))
                s.recvfrom(1024)
                return port, True
        except socket.timeout: return port, None
        except ConnectionRefusedError: return port, False
        except Exception: return port, False
    
    async def schedule(port):
        if cancel_event.is_set(): return None
        async with semaphore:
            if cancel_event.is_set(): return None
            return await loop.run_in_executor(executor, _udp_probe, port)
    tasks = [schedule(p) for p in ports]
    for fut in asyncio.as_completed(tasks):
        try:
            res = await fut
            if not res or cancel_event.is_set(): continue
            port, status = res
            label = f"{port}/udp"
            if status: result["open_ports"].append(label)
            else: result["closed_ports"].append(label)
        except asyncio.CancelledError: break
    if result["open_ports"]: DATA_SAVE(host, 'Live_IP.txt')
    else: DATA_SAVE(host, 'RIP_Data.txt')
    for p in result["open_ports"]: DATA_SAVE(f'{host}:{p}', 'Live_Data.txt')
    SAVE_SUMMARY({"ts": int(time.time()), "target": host, **result})
    return result

async def scan_syn_threaded(host, ports, cancel_event, semaphore):
 
    loop = asyncio.get_running_loop()
    result = {"target": host, "open_ports": [], "closed_ports": [], "filtered_ports": [], "banners": {}}
    
    async def schedule(port):
        if cancel_event.is_set(): return None
        async with semaphore:
            if cancel_event.is_set(): return None
            return await loop.run_in_executor(executor, _syn_probe, host, port, PORT_TIMEOUT)
            
    tasks = [schedule(p) for p in ports]
    for fut in asyncio.as_completed(tasks):
        try:
            res = await fut
            if not res or cancel_event.is_set(): continue
            
            port, status = res
            
            if status is True: 
                label = f"{port}/tcp"
                result["open_ports"].append(label)
                banner = await loop.run_in_executor(executor, grab_banner, host, port, 0.8)
                if banner: result["banners"][label] = banner
            elif status is False: 
                label = f"{port}/tcp"
                result["closed_ports"].append(label)
            else: 
                label = f"{port}/tcp"
                result["filtered_ports"].append(label)
                
        except asyncio.CancelledError: break

    if result["open_ports"]: DATA_SAVE(host, 'Live_IP.txt')
    else: DATA_SAVE(host, 'RIP_Data.txt')
    for p in result["open_ports"]: DATA_SAVE(f'{host}:{p}', 'Live_Data.txt')
    SAVE_SUMMARY({"ts": int(time.time()), "target": host, **result})
    
    return result

async def scan_ack_threaded(host, ports, cancel_event, semaphore):
    loop = asyncio.get_running_loop()
    result = {"target": host, "open_ports": [], "closed_ports": [], "filtered_ports": []}
    
    async def schedule(port):
        if cancel_event.is_set(): return None
        async with semaphore:
            if cancel_event.is_set(): return None
            return await loop.run_in_executor(executor, _ack_probe, host, port, PORT_TIMEOUT)
            
    tasks = [schedule(p) for p in ports]
    for fut in asyncio.as_completed(tasks):
        try:
            res = await fut
            if not res or cancel_event.is_set(): continue
            
            port, status = res
            label = f"{port}/tcp"
            
            if status is True: 
                result["closed_ports"].append(label)
            else:
                result["filtered_ports"].append(label)
                
        except asyncio.CancelledError: break

    if result["closed_ports"]: 
        DATA_SAVE(host, 'Live_IP_Unfiltered.txt')
    SAVE_SUMMARY({"ts": int(time.time()), "target": host, **result})
    
    return result

async def scan_vuln_async(host, ports_list, cancel_event):
    ports_str = ",".join(map(str, ports_list))
    command = ["nmap", "-sV", "--script=vuln", "-T4", "--host-timeout", "20m", "-p", ports_str, host, "-oX", "-"]
    logger.info(f"Đang chạy Nmap (blocking executor): {' '.join(command)}")
    result = {"target": host, "vulnerabilities": []}

    def _run_nmap_blocking():
        try:
            proc = subprocess.run(command, 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=60, 
                                  encoding='utf-8',
                                  errors='ignore')
            return proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired as e:
            logger.warning(f"Nmap for {host} timed out after 1 minutes.")
            return e.stdout or "", e.stderr or "Scan timed out after 1 minutes.", 
        except Exception as e:
            logger.error(f"Lỗi khi chạy subprocess Nmap {host}: {e}")
            return "", f"Failed to execute Nmap process: {e}"
    try:
        loop = asyncio.get_running_loop()
        if cancel_event.is_set():
            raise asyncio.CancelledError()
        stdout_str, stderr_str, returncode = await loop.run_in_executor(
            None, _run_nmap_blocking
        )
        if cancel_event.is_set():
            logger.info(f"Nmap for {host} finished, but cancellation was requested.")
            raise asyncio.CancelledError()
        if returncode != 0:
            logger.error(f"Nmap lỗi cho {host}: {stderr_str}")
            
            if "Failed to resolve" in stderr_str or "Couldn't resolve host" in stderr_str:
                result["error"] = f"Could not resolve host: {host}"
            elif returncode == -1: 
                result["error"] = stderr_str
            elif returncode == -2: 
                result["error"] = stderr_str 
            else:
                result["error"] = f"Nmap command failed: {stderr_str.strip() or 'Unknown error'}"
        
        else:
            if not stdout_str:
                logger.warning(f"Nmap for {host} succeeded but produced no output.")
                result["error"] = "Nmap ran successfully but returned no data (host may be down)."
            else:
                try:
                    xml_root = ET.fromstring(stdout_str)
                    for port_elem in xml_root.findall(".//port"):
                        port_id = port_elem.get("portid") + "/" + port_elem.get("protocol")
                        service_elem = port_elem.find("./service")
                        service_name = service_elem.get("name") if service_elem is not None else "unknown"

                        for script_elem in port_elem.findall("./script"):
                            script_id = script_elem.get("id")
                            if script_id and "vuln" in script_id:
                                output = script_elem.get("output", "No output").strip()
                                vuln = {
                                    "port": port_id,
                                    "service": service_name,
                                    "script_id": script_id,
                                    "output": output
                                }
                                result["vulnerabilities"].append(vuln)
                    logger.info(f"Nmap cho {host} hoàn thành. Tìm thấy {len(result['vulnerabilities'])} lỗ hổng.")
                except ET.ParseError as pe:
                    logger.error(f"Lỗi phân tích XML Nmap cho {host}: {pe}. Output: {stdout_str[:200]}...")
                    result["error"] = f"Nmap returned invalid XML: {pe}"

    except asyncio.CancelledError:
        logger.info(f"Nmap cho {host} đã bị huỷ.")
        raise 
    except FileNotFoundError: 
        logger.error("LỖI NGHIÊM TRỌNG: Không tìm thấy 'nmap'.")
        result["error"] = "Nmap not found. Please install it and ensure it's in PATH."
    except Exception as e: 
        logger.exception(f"Lỗi không xác định khi quét Nmap {host}: {e}")
        result["error"] = f"An unknown error occurred during Nmap scan: {e}"
        
    SAVE_SUMMARY({"ts": int(time.time()), "target": host, **result})
    return result

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
        logger.info("Scanner started")
        ports_ = parse_ports(data.get("ports", "")) or [22, 80, 443]
        protocol = data.get("protocol", "tcp").lower()
        scan_type = data.get("scan_type", "tcp-connect").lower()
        sem = asyncio.Semaphore(min(MAX_CONCURRENT_JOBS, 100))
        all_targets_list = []
        mode = data.get("mode")
        if mode == "single":
            t = data.get("target", "").strip()
            if t: all_targets_list.append(t)
        
        elif mode == "bulk":
            ip_range = data.get("ip_range", "").strip()
            if "-" in ip_range:
                try:
                    all_targets_list.extend(IP_Ranger(*map(str.strip, ip_range.split("-", 1))))
                except Exception as e:
                    await websocket.send_json({"type": "error", "message": f"Invalid IP range: {e}"})
            
            cidr_value = data.get("cidr", "").strip()
            if cidr_value:
                for cidr_line in cidr_value.splitlines():
                    cidr_line = cidr_line.strip()
                    if not cidr_line: continue
                    try:
                        net = ip_network(cidr_line, strict=False)
                        hosts_generator = net.hosts() if net.prefixlen < 31 else net
                        all_targets_list.extend(str(ip) for ip in hosts_generator)
                    except Exception as e:
                        logger.warning(f"Skipping invalid CIDR: {cidr_line} ({e})")
        
        unique_targets = list(dict.fromkeys(filter(None, all_targets_list)))
        if not unique_targets:
            await websocket.send_json({"status": "done", "message": "No valid targets found."})
            return
        all_scan_tasks = []
        for ip in unique_targets:
            if scan_type == "vuln":
                logger.info(f"Queueing Nmap Vuln Scan for {ip}")
                all_scan_tasks.append(scan_vuln_async(ip, ports_, scan_cancel_event))
            elif protocol in ("tcp", "both"):
                if scan_type == "tcp-syn":
                    logger.info(f"Queueing SYN Scan for {ip}")
                    all_scan_tasks.append(scan_syn_threaded(ip, ports_, scan_cancel_event, sem))
                elif scan_type == "tcp-ack":
                    logger.info(f"Queueing ACK Scan for {ip}")
                    all_scan_tasks.append(scan_ack_threaded(ip, ports_, scan_cancel_event, sem))
                else: 
                    logger.info(f"Queueing TCP Connect Scan for {ip}")
                    all_scan_tasks.append(scan_ports_threaded(ip, ports_, scan_cancel_event, sem))
            if protocol in ("udp", "both"):
                logger.info(f"Queueing UDP Scan for {ip}")
                all_scan_tasks.append(scan_udp_threaded(ip, ports_, scan_cancel_event, sem))

        completed, open_ports_count, closed_ports_count, filtered_ports_count = 0, 0, 0, 0
        top_ported = {}
        total_tasks = len(all_scan_tasks)

        logger.info(f"Processing {total_tasks} tasks for {len(unique_targets)} unique targets.")
        try:
            for ttask in asyncio.as_completed(all_scan_tasks):
                if scan_cancel_event.is_set(): break
                res = await ttask
                completed += 1
                json_payload = {
                    "progress_done": completed, "progress_total": total_tasks,
                    "status": "running",
                }
                if "vulnerabilities" in res:
                    json_payload["new_vuln_result"] = res
                elif res.get("error"):
                    line = f"Target: {res.get('target')} | ERROR: {res.get('error')}"
                    json_payload["new_result_line"] = line
                elif "open_ports" in res:                  
                    open_ports_count += len(res.get("open_ports", []))
                    closed_ports_count += len(res.get("closed_ports", []))
                    filtered_ports_count += len(res.get("filtered_ports", []))
                    for p in res.get("open_ports", []):
                        top_ported[p] = top_ported.get(p, 0) + 1
                    filtered_ports_list = res.get('filtered_ports', [])
                    line = f"Target: {res.get('target')} | Open: {res.get('open_ports')} | Closed: {res.get('closed_ports')} | Filtered: {filtered_ports_list}"
                    json_payload.update({
                        "open_ports": open_ports_count,
                        "closed_ports": closed_ports_count,
                        "filtered_ports_total": filtered_ports_count,
                        "top_ports": top_ported,
                        "new_result_line": line,
                    })
                await websocket.send_json(json_payload)
        except asyncio.CancelledError:
            logger.info("Scan cancelled by client.")
        
        final_status = "stopped" if scan_cancel_event.is_set() else "done"
        try:
            await websocket.send_json({"status": final_status})
            logger.info(f"Scanner finished with status: {final_status}")
        except Exception as e:
            logger.warning(f"Could not send final status '{final_status}' to client: {e}")

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
                    logger.info("Stop command received. Setting cancel event.")
                    scan_cancel_event.set()
                    await scan_task
    except WebSocketDisconnect:
        logger.info("Client disconnected, stopping scan.")
        if scan_task and not scan_task.done():
            scan_cancel_event.set()
    except Exception as e:
        logger.exception("An error occurred in the websocket connection.")

@app.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)

if __name__ == "__main__":
    if sys.platform == "win32":
        logger.info("Setting asyncio policy for Windows")
       
    logger.info(f"[+] Starting scanner with {max_threads} threads")
    uvicorn.run("main:app", host="localhost", port=8000, reload=True, log_level="info")