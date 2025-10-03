# agent/agent.py

import json
import math
import os
import platform
import socket
import time
from urllib.parse import urljoin

import cpuinfo
import psutil
import requests
from dotenv import load_dotenv

load_dotenv()

# --- Configuration ---
SERVER_URL = os.getenv("SERVER_URL", "http://127.0.0.1:5000")
REPORT_INTERVAL = int(os.getenv("REPORT_INTERVAL", 60))
DEVICE_ID = socket.gethostname()
COMMAND_POLL_INTERVAL = 5
CACHE_FILE = "network_cache.json"
SERVICES_TO_MONITOR_STR = os.getenv("SERVICES_TO_MONITOR", "")
SERVICES_TO_MONITOR = [
    service.strip() for service in SERVICES_TO_MONITOR_STR.split(",") if service.strip()
]
VERBOSE = os.getenv("VERBOSE", "1") == "1"

EXTERNAL_IP_CACHE = {"ip": None, "timestamp": 0}
EXTERNAL_IP_CACHE_DURATION = int(
    os.getenv("EXTERNAL_IP_CACHE_DURATION", 600)
)  # seconds
FETCH_EXTERNAL_IP = os.getenv("FETCH_EXTERNAL_IP", "1") == "1"


def human_readable_bytes(b):
    if not isinstance(b, (int, float)) or b <= 0:
        return "0B"
    s = ("B", "KB", "MB", "GB", "TB")
    i = int(math.floor(math.log(b, 1024)))
    p = math.pow(1024, i)
    return f"{round(b / p, 2)} {s[i]}"


def get_network_rate():
    current_counters = psutil.net_io_counters()
    current_time = time.time()
    in_rate, out_rate = 0, 0
    try:
        with open(CACHE_FILE, "r") as f:
            last_data = json.load(f)
        time_delta = current_time - last_data.get("timestamp", current_time)
        if time_delta > 0:
            last_counters = last_data.get("counters", {})
            bytes_recv_delta = current_counters.bytes_recv - last_counters.get(
                "bytes_recv", current_counters.bytes_recv
            )
            bytes_sent_delta = current_counters.bytes_sent - last_counters.get(
                "bytes_sent", current_counters.bytes_sent
            )
            in_rate = bytes_recv_delta / time_delta
            out_rate = bytes_sent_delta / time_delta
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    with open(CACHE_FILE, "w") as f:
        json.dump(
            {
                "timestamp": current_time,
                "counters": {
                    "bytes_sent": current_counters.bytes_sent,
                    "bytes_recv": current_counters.bytes_recv,
                },
            },
            f,
        )
    return in_rate, out_rate


def get_service_statuses():
    if not SERVICES_TO_MONITOR:
        return {}
    running_processes = {p.info["name"] for p in psutil.process_iter(["name"])}
    statuses = {}
    for service in SERVICES_TO_MONITOR:
        statuses[service] = "running" if service in running_processes else "stopped"
    return statuses


def get_cpu_usage():
    return psutil.cpu_percent(interval=1)


def get_memory_usage():
    return psutil.virtual_memory().percent


def get_disk_usage():
    disks = []
    fs_types_env = os.getenv("VALID_FS_TYPES", "")
    if fs_types_env:
        valid_fs_types = [
            fs.strip().lower() for fs in fs_types_env.split(",") if fs.strip()
        ]
    else:
        valid_fs_types = [
            "ntfs",
            "ext4",
            "ext3",
            "fat32",
            "apfs",
            "xfs",
            "btrfs",
            "exfat",
            "hfsplus",
            "ufs",
            "zfs",
        ]

    for p in psutil.disk_partitions():
        if p.fstype.lower() in valid_fs_types:
            try:
                u = psutil.disk_usage(p.mountpoint)
                disks.append(
                    {
                        "mountpoint": p.mountpoint,
                        "total": u.total,
                        "used": u.used,
                        "free": u.free,
                        "percent": u.percent,
                    }
                )
            except PermissionError:
                continue
    return disks


def get_ip_addresses():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        internal_ip = s.getsockname()[0]
    finally:
        s.close()
    external_ip = "N/A"
    if FETCH_EXTERNAL_IP:
        now = time.time()
        if (
            EXTERNAL_IP_CACHE["ip"] is None
            or now - EXTERNAL_IP_CACHE["timestamp"] > EXTERNAL_IP_CACHE_DURATION
        ):
            try:
                EXTERNAL_IP_CACHE["ip"] = requests.get(
                    "https://api.ipify.org", timeout=3
                ).text
                EXTERNAL_IP_CACHE["timestamp"] = now
            except Exception:
                EXTERNAL_IP_CACHE["ip"] = "N/A"
        external_ip = EXTERNAL_IP_CACHE["ip"]
    return internal_ip, external_ip


def get_top_processes_by_cpu(n=5):
    processes = []
    ignore_list = []
    if platform.system() == "Windows":
        ignore_list = ["System Idle Process", "System", "Registry"]
    for proc in psutil.process_iter(["name", "username", "cpu_percent"]):
        try:
            pinfo = proc.info
            if pinfo["name"] in ignore_list:
                continue
            processes.append(pinfo)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return sorted(processes, key=lambda p: p["cpu_percent"], reverse=True)[:n]


def get_top_processes_by_memory(n=5):
    processes = []
    for proc in psutil.process_iter(["name", "username", "memory_info"]):
        try:
            pinfo = proc.info
            pinfo["memory_rss"] = pinfo["memory_info"].rss
            processes.append(pinfo)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    sorted_processes = sorted(processes, key=lambda p: p["memory_rss"], reverse=True)
    top_processes = []
    for p in sorted_processes[:n]:
        top_processes.append(
            {
                "name": p["name"],
                "username": p["username"],
                "memory_rss": p["memory_rss"],
                "memory_rss_readable": human_readable_bytes(p["memory_rss"]),
            }
        )
    return top_processes


def get_top_processes_by_network(n=5, interval=1):
    procs = {}
    # Using a dict to easily update process info
    for p in psutil.process_iter(['pid', 'name', 'username']):
        try:
            procs[p.pid] = {
                'name': p.info['name'],
                'username': p.info['username'],
                'last_io': psutil.Process(p.pid).io_counters()
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, KeyError):
            continue

    time.sleep(interval)

    processes = []
    for pid, p_info in procs.items():
        try:
            current_io = psutil.Process(pid).io_counters()
            last_io = p_info['last_io']

            if last_io and current_io:
                read_rate = (current_io.read_bytes - last_io.read_bytes) / interval
                write_rate = (current_io.write_bytes - last_io.write_bytes) / interval
                
                read_rate = max(0, read_rate)
                write_rate = max(0, write_rate)

                processes.append({
                    'name': p_info['name'],
                    'username': p_info['username'],
                    'network_in': read_rate,
                    'network_out': write_rate,
                    'network_in_readable': f"{human_readable_bytes(read_rate)}/s",
                    'network_out_readable': f"{human_readable_bytes(write_rate)}/s",
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    top_in = sorted(processes, key=lambda p: p['network_in'], reverse=True)[:n]
    top_out = sorted(processes, key=lambda p: p['network_out'], reverse=True)[:n]
    return top_in, top_out


def collect_metrics():
    """Collects all metrics and returns them as a single, clean dictionary."""
    internal_ip, external_ip = get_ip_addresses()
    network_in_rate, network_out_rate = get_network_rate()
    top_net_in, top_net_out = get_top_processes_by_network(5)

    try:
        current_user = psutil.users()[0].name
    except (IndexError, AttributeError):
        current_user = "user"

    data = {
        "hostname": DEVICE_ID,
        "username": current_user,
        "cpu": get_cpu_usage(),
        "cpu_model": cpuinfo.get_cpu_info().get("brand_raw", "N/A"),
        "memory": get_memory_usage(),
        "total_memory": psutil.virtual_memory().total,
        "disk": get_disk_usage(),
        "internal_ip": internal_ip,
        "external_ip": external_ip,
        "network_in_rate": network_in_rate,
        "network_out_rate": network_out_rate,
        "monitored_services": get_service_statuses(),
        "top_processes_by_cpu": get_top_processes_by_cpu(5),
        "top_processes_by_memory": get_top_processes_by_memory(5),
        "top_processes_by_network_in": top_net_in,
        "top_processes_by_network_out": top_net_out,
    }
    return data


def collect_and_send_data():
    metrics = collect_metrics()
    try:
        report_url = urljoin(SERVER_URL, "report")
        response = requests.post(report_url, json=metrics, timeout=10)
        if response.status_code == 200:
            log("Successfully sent data.")
        else:
            print(f"Failed to send data. Status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error sending data: {e}")


def check_for_commands():
    try:
        command_url = urljoin(SERVER_URL, f"api/command/check/{DEVICE_ID}")
        response = requests.get(command_url, timeout=5)
        if response.status_code == 200 and response.json().get("command") == "refresh":
            print("Received 'refresh' command.")
            collect_and_send_data()
    except requests.exceptions.RequestException:
        pass


def get_report_rate(server_url, hostname, default_rate=60):
    try:
        resp = requests.get(f"{server_url}/api/report_rate/{hostname}", timeout=5)
        if resp.ok:
            return int(resp.json().get("report_rate", default_rate))
    except Exception:
        pass
    return default_rate


def log(msg):
    if VERBOSE:
        print(msg)


if __name__ == "__main__":
    report_rate = get_report_rate(SERVER_URL, DEVICE_ID, REPORT_INTERVAL)
    print(
        f"Starting agent for '{DEVICE_ID}'. Reporting every {report_rate}s. Polling every {COMMAND_POLL_INTERVAL}s."
    )
    try:
        last_report_time = 0
        last_report_rate = report_rate
        while True:
            # Check for updated report rate
            new_report_rate = get_report_rate(SERVER_URL, DEVICE_ID, REPORT_INTERVAL)
            if new_report_rate != last_report_rate:
                print(
                    f"[CONFIG] Report rate updated: {last_report_rate} -> {new_report_rate}"
                )
                last_report_rate = new_report_rate
            report_rate = last_report_rate
    
            current_time = time.time()
            if current_time - last_report_time >= report_rate:
                log("Collecting and sending data...")
                collect_and_send_data()
                last_report_time = current_time
            check_for_commands()
            time.sleep(COMMAND_POLL_INTERVAL)
    except KeyboardInterrupt:
        print("\nAgent stopped by user. Exiting.")
