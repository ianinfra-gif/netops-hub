import http.server
import socketserver
import subprocess
import os
import re
import platform
import json
import socket
import time
from datetime import datetime
from urllib.parse import parse_qs, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from services.dhcp_loader import enrich_json_data
except ImportError:
    def enrich_json_data(data): return data

PORT = 8000
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DIAG_LOGS_DIR = os.path.join(BASE_DIR, 'NetDiagWeb', 'logs')
SCAN_LOGS_DIR = os.path.join(BASE_DIR, 'NetOpsRecon', 'logs')
SCAN_JSONS_DIR = os.path.join(BASE_DIR, 'NetOpsRecon', 'jsons')
SENTINEL_LOGS_DIR = os.path.join(BASE_DIR, 'PortSentinel', 'logs')

os.makedirs(DIAG_LOGS_DIR, exist_ok=True)
os.makedirs(SCAN_LOGS_DIR, exist_ok=True)
os.makedirs(SCAN_JSONS_DIR, exist_ok=True)
os.makedirs(SENTINEL_LOGS_DIR, exist_ok=True)

def get_unified_os_name():
    sys_os = platform.system()
    if sys_os == 'Darwin':
        try:
            ver = subprocess.check_output(['sw_vers', '-productVersion'], text=True).strip()
            return f"macOS {ver}"
        except Exception:
            return f"macOS {platform.mac_ver()[0]}"
    elif sys_os == 'Linux':
        try:
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release') as f:
                    for line in f:
                        if line.startswith('PRETTY_NAME='):
                            return line.strip().split('=')[1].strip('"')
        except Exception:
            pass
        return "Linux"
    elif sys_os == 'Windows':
        return f"Windows {platform.release()}"
    return sys_os

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

class DiagHandler(http.server.BaseHTTPRequestHandler):
    def get_diag_command(self, script_dir):
        sys_os = platform.system()
        if sys_os == 'Darwin':
            script_path = os.path.join(script_dir, 'net_diag_mac.sh')
            return ['zsh', script_path], script_path
        elif sys_os == 'Linux':
            script_path = os.path.join(script_dir, 'net_diag_linux.sh')
            return ['bash', script_path], script_path
        elif sys_os == 'Windows':
            script_path = os.path.join(script_dir, 'net_diag_win.ps1')
            return ['powershell', '-ExecutionPolicy', 'Bypass', '-File', script_path], script_path
        return None, None

    def do_POST(self):
        if self.path == '/upload_log':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8', errors='ignore')
            
            client_ip = self.client_address[0]
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            log_filepath = os.path.join(DIAG_LOGS_DIR, f"RemoteDiag_{client_ip}_{timestamp}.log")
            
            with open(log_filepath, 'w', encoding='utf-8') as f:
                f.write(post_data)
                
            self.send_response(200)
            self.send_header("Content-type", "text/plain; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(b"SUCCESS")
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        query = parse_qs(parsed_url.query)

        if path == '/':
            template_path = os.path.join(BASE_DIR, 'templates', 'index.html')
            if os.path.exists(template_path):
                self.send_response(200)
                self.send_header("Content-type", "text/html; charset=utf-8")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                with open(template_path, 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(500)
                self.end_headers()
            return

        elif path in ['/run_sentinel', '/run_portcheck']:
            res_text = ""
            try:
                target_host = query.get('host', ['127.0.0.1'])[0].strip() or '127.0.0.1'
                ports_str = query.get('ports', ['22,80,443'])[0].strip() or '22,80,443'
                port_list = [int(p) for p in re.split(r'[,; ]+', ports_str) if p.isdigit()]
                
                if not port_list:
                    res_text = "[FAIL] 請輸入有效的埠號格式"
                else:
                    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    sys_os = platform.system()
                    os_info = get_unified_os_name()
                    
                    try:
                        host_name = subprocess.check_output(['hostname', '-s'], text=True).strip() if sys_os == 'Darwin' else socket.gethostname().split('.')[0]
                    except Exception:
                        host_name = socket.gethostname()

                    start_time_sec = time.time()
                    output = [
                        "Target Port Sentinel",
                        f"Host: {host_name} | OS: {os_info}",
                        f"Start Time: {now_str}",
                        "----------------------------------------"
                    ]

                    try:
                        target_ip = socket.gethostbyname(target_host)
                        output.append(f" [INFO] 目標標靶主機 : {target_host} ({target_ip})" if target_host != target_ip else f" [INFO] 目標標靶主機 : {target_ip}")
                    except Exception as e:
                        output.append(f" [FAIL] 域名解析失敗 : {str(e)}")
                        target_ip = None

                    if target_ip:
                        def probe_port(port):
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(1.2)
                            start_t = time.time()
                            try:
                                res = s.connect_ex((target_ip, port))
                                latency = (time.time() - start_t) * 1000
                                return (port, res == 0, f" [OK]   Port {port:<5} : OPEN   (延遲: {latency:.1f} ms)" if res == 0 else f" [FAIL] Port {port:<5} : CLOSED / FILTERED")
                            except Exception as err:
                                return (port, False, f" [FAIL] Port {port:<5} : ERROR ({err})")
                            finally:
                                s.close()

                        port_results = []
                        with ThreadPoolExecutor(max_workers=min(20, len(port_list))) as executor:
                            futures = [executor.submit(probe_port, p) for p in port_list]
                            for future in as_completed(futures):
                                port_results.append(future.result())

                        port_results.sort(key=lambda x: port_list.index(x[0]))
                        open_count = sum(1 for _, is_open, _ in port_results if is_open)
                        
                        for _, _, res_line in port_results:
                            output.append(res_line)

                        output.append("----------------------------------------")
                        output.append(f"[抽查結論] 標靶抽查完畢，共檢測 {len(port_list)} 個埠口，開啟 {open_count} 個。")
                        output.append("----------------------------------------")

                    safe_host = re.sub(r'[^a-zA-Z0-9\.]', '_', target_host)
                    log_filename = f"Sentinel_{safe_host}_{timestamp}.log"
                    log_filepath = os.path.join(SENTINEL_LOGS_DIR, log_filename)
                    
                    with open(log_filepath, 'w', encoding='utf-8') as f:
                        f.write("\n".join(output))

                    duration = int(time.time() - start_time_sec)
                    output.append(f" [INFO] 日誌已存至: PortSentinel/logs/{log_filename}")
                    output.append(f" [INFO] 總執行耗時: {duration} 秒")

                    res_text = "\n".join(output)
            except Exception as e:
                res_text = f"[FATAL] 執行發生錯誤: {str(e)}"

            try:
                self.send_response(200)
                self.send_header("Content-type", "text/plain; charset=utf-8")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(res_text.encode('utf-8'))
            except Exception:
                pass
            return

        elif path == '/get_log_list':
            file_list = []
            for folder_type, target_dir in [('diag', DIAG_LOGS_DIR), ('scan_log', SCAN_LOGS_DIR), ('sentinel_log', SENTINEL_LOGS_DIR), ('scan_json', SCAN_JSONS_DIR)]:
                if os.path.exists(target_dir):
                    for fname in os.listdir(target_dir):
                        if fname.endswith('.log') or fname.endswith('.json'):
                            fpath = os.path.join(target_dir, fname)
                            mtime = datetime.fromtimestamp(os.path.getmtime(fpath)).strftime('%m-%d %H:%M')
                            file_list.append({
                                'folder': folder_type,
                                'name': fname,
                                'ext': fname.split('.')[-1],
                                'type': 'sentinel' if folder_type == 'sentinel_log' else ('diag' if folder_type == 'diag' else 'scan'),
                                'time': mtime
                            })
            file_list.sort(key=lambda x: x['time'], reverse=True)
            
            self.send_response(200)
            self.send_header("Content-type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(file_list).encode('utf-8'))
            return

        elif path == '/download_diag':
            os_name = query.get('os', [''])[0].lower()
            script_map = {
                'windows': ('net_diag_win.ps1', 'application/octet-stream'),
                'linux': ('net_diag_linux.sh', 'text/x-shellscript; charset=utf-8'),
                'macos': ('net_diag_mac.sh', 'text/x-shellscript; charset=utf-8'),
            }
            script_info = script_map.get(os_name)
            if not script_info:
                self.send_response(404)
                self.end_headers()
                return

            filename, content_type = script_info
            script_path = os.path.join(BASE_DIR, 'NetDiagWeb', filename)
            if not os.path.isfile(script_path):
                self.send_response(404)
                self.end_headers()
                return

            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
            self.send_header('Content-Length', str(os.path.getsize(script_path)))
            self.end_headers()
            with open(script_path, 'rb') as f:
                self.wfile.write(f.read())
            return

        elif path == '/read_log_file':
            folder = query.get('folder', [''])[0]
            filename = query.get('file', [''])[0]
            is_download = query.get('dl', ['0'])[0] == '1'

            dir_map = { 'diag': DIAG_LOGS_DIR, 'scan_log': SCAN_LOGS_DIR, 'sentinel_log': SENTINEL_LOGS_DIR, 'scan_json': SCAN_JSONS_DIR }
            target_dir = dir_map.get(folder)
            
            if target_dir and filename:
                fpath = os.path.abspath(os.path.join(target_dir, filename))
                if fpath.startswith(target_dir) and os.path.exists(fpath):
                    self.send_response(200)
                    if is_download:
                        self.send_header("Content-Type", "application/octet-stream")
                        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                    else:
                        self.send_header("Content-type", "text/plain; charset=utf-8")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    
                    with open(fpath, 'rb') as f:
                        content_bytes = f.read()

                    if folder == 'scan_json' or filename.endswith('.json'):
                        try:
                            json_obj = json.loads(content_bytes.decode('utf-8', errors='ignore'))
                            content_bytes = json.dumps(enrich_json_data(json_obj), ensure_ascii=False, indent=2).encode('utf-8')
                        except Exception:
                            pass

                    self.wfile.write(content_bytes)
                    return

            self.send_response(404)
            self.end_headers()
            return

        elif path in ['/run_diag', '/run_scan']:
            self.send_response(200)
            self.send_header("Content-type", "text/plain; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            
            if path == '/run_scan':
                script_dir = os.path.join(BASE_DIR, 'NetOpsRecon')
                if platform.system() == 'Windows':
                    script_path = os.path.join(script_dir, 'net_scanner_win.ps1')
                    cmd = ['powershell', '-ExecutionPolicy', 'Bypass', '-File', script_path]
                else:
                    script_path = os.path.join(script_dir, 'net_scanner.sh')
                    cmd = ['bash', script_path]
            else:
                script_dir = os.path.join(BASE_DIR, 'NetDiagWeb')
                cmd, script_path = self.get_diag_command(script_dir)
            
            if not cmd or not script_path or not os.path.exists(script_path):
                self.wfile.write(f"[FATAL] 未找到腳本檔: {script_path}".encode('utf-8'))
                return

            try:
                env = os.environ.copy()
                env["CLIENT_IP"] = self.client_address[0]
                env["TERM"] = "xterm-256color"
                
                raw_output = subprocess.check_output(cmd, cwd=script_dir, env=env, stderr=subprocess.STDOUT, text=True)
                clean_output = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-9;]*[ -/]*[@-~])', '', raw_output)
                
                lines = clean_output.splitlines()
                filtered = [line for i, line in enumerate(lines) if "頻寬品質測試: 滿載測速中" not in line]
                result = "\n".join(filtered)
            except subprocess.CalledProcessError as e:
                clean_err = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-9;]*[ -/]*[@-~])', '', e.output)
                result = f"執行錯誤:\n{clean_err}"
            except Exception as e:
                result = f"系統錯誤: {str(e)}"
                
            self.wfile.write(result.encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == "__main__":
    server = ThreadedHTTPServer(('0.0.0.0', PORT), DiagHandler)
    print(f"[*] 控制臺已啟動: http://0.0.0.0:{PORT}")
    server.serve_forever()
