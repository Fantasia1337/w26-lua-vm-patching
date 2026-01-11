#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Universal launcher for Frida JS scripts via Python.
Features:
- Spawn app (default) or attach to existing process.
- Auto USB device selection.
- Loads JS from file and keeps session alive, printing messages.

Usage examples:
  python work/run_frida_js.py --script work/hp_scan.js --package com.bleach.apj --spawn
  python work/run_frida_js.py --script work/hp_watch.js --package com.bleach.apj --spawn
  python work/run_frida_js.py --script work/damage_hook.js --package com.bleach.apj --spawn
  python work/run_frida_js.py --script work/damage_hook.js --package com.bleach.apj --attach
"""

import argparse
import sys
import time
import subprocess
import re
from pathlib import Path

import frida


def on_message(message, data):
    mtype = message.get("type")
    if mtype == "send":
        payload = message.get("payload")
        # Special handling for Lua script dumps
        if isinstance(payload, dict) and payload.get("type") == "lua_dump":
            idx = payload.get("idx")
            size = payload.get("size")
            name = payload.get("name") or "noname"
            safe_name = payload.get("safeName") or name
            # Additional safety check for filename sanitization
            safe_name = re.sub(r"[^0-9a-zA-Z_.-]", "_", safe_name)
            if not safe_name:
                safe_name = "noname"

            out_dir = Path("work") / "lua_dumps"
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / f"bleach_lua_{idx}_{safe_name}.bin"

            if data is not None:
                try:
                    with open(out_path, "wb") as f:
                        f.write(data)
                    print(f"[LUA_DUMP] #{idx} size={size} name={name} -> {out_path}")
                except Exception as e:
                    print(f"[LUA_DUMP-ERROR] #{idx} name={name} -> {e}")
            else:
                print(f"[LUA_DUMP] #{idx} name={name} (NO DATA)")
        # Handle Proto dumps for analysis
        elif isinstance(payload, dict) and payload.get("type") == "proto_dump":
            idx = payload.get("idx")
            code_size = payload.get("codeSize", 0)
            const_count = payload.get("constCount", 0)
            name = payload.get("name") or "noname"
            safe_name = payload.get("safeName") or f"proto_{code_size}_{const_count}_{idx}"
            consts_sample = payload.get("constsSample", [])
            
            out_dir = Path("work") / "proto_dumps"
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / f"{safe_name}.code.bin"
            
            if data is not None:
                try:
                    with open(out_path, "wb") as f:
                        f.write(data)
                    print(f"[PROTO_DUMP] #{idx} codeSize={code_size} constCount={const_count} name={name}")
                    print(f"  -> Saved to: {out_path}")
                    if consts_sample:
                        print(f"  -> Consts sample: {consts_sample[:5]}")
                except Exception as e:
                    print(f"[PROTO_DUMP-ERROR] #{idx} -> {e}")
            else:
                print(f"[PROTO_DUMP] #{idx} (NO DATA)")
        # Handle traffic files (JSON)
        elif isinstance(payload, dict) and payload.get("type") == "traffic_file":
            filename = payload.get("filename", "unknown.json")
            timestamp = payload.get("timestamp", 0)
            size = payload.get("size", 0)
            
            out_dir = Path("work") / "traffic_dumps"
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / filename
            
            if data is not None:
                try:
                    with open(out_path, "wb") as f:
                        f.write(data)
                    print(f"[TRAFFIC] Saved: {filename} ({size} bytes) -> {out_path}")
                except Exception as e:
                    print(f"[TRAFFIC-ERROR] Failed to save {filename}: {e}")
            else:
                print(f"[TRAFFIC] {filename} (NO DATA)")
        # Handle binary traffic files
        elif isinstance(payload, dict) and payload.get("type") == "traffic_file_binary":
            filename = payload.get("filename", "unknown.bin")
            timestamp = payload.get("timestamp", 0)
            size = payload.get("size", 0)
            
            out_dir = Path("work") / "traffic_dumps"
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / filename
            
            if data is not None:
                try:
                    with open(out_path, "wb") as f:
                        f.write(data)
                    print(f"[TRAFFIC-BIN] Saved: {filename} ({size} bytes) -> {out_path}")
                except Exception as e:
                    print(f"[TRAFFIC-BIN-ERROR] Failed to save {filename}: {e}")
            else:
                print(f"[TRAFFIC-BIN] {filename} (NO DATA)")
        else:
            print("[JS]", payload)
    elif mtype == "error":
        print("[JS-ERROR]", message.get("stack", message))
    else:
        print("[JS-MSG]", message)


def load_script(session, path: Path):
    code = path.read_text(encoding="utf-8")
    script = session.create_script(code)
    script.on("message", on_message)
    script.load()
    return script


def get_adb_device():
    """
    Determines which ADB device to use.
    Prefers physical devices over emulators.
    Returns device_id or None if no devices are found.
    """
    try:
        result = subprocess.run(
            ["adb", "devices"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode != 0:
            print(f"[!] ADB devices command failed: {result.stderr}")
            return None
        
        lines = result.stdout.strip().split('\n')[1:]  # Skip header line
        devices = []
        offline_devices = []
        unauthorized_devices = []
        
        for line in lines:
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 2:
                device_id = parts[0]
                status = parts[1]
                
                if status == "device":
                    devices.append(device_id)
                elif status == "offline":
                    offline_devices.append(device_id)
                    print(f"[!] Device {device_id} is OFFLINE")
                elif status == "unauthorized":
                    unauthorized_devices.append(device_id)
                    print(f"[!] Device {device_id} is UNAUTHORIZED (enable USB debugging on device!)")
        
        if not devices:
            if offline_devices:
                print("[!] All devices are OFFLINE. Try:")
                print("    1. Disconnect and reconnect USB cable")
                print("    2. Restart ADB: adb kill-server && adb start-server")
                print("    3. Check USB mode on device")
            elif unauthorized_devices:
                print("[!] All devices are UNAUTHORIZED. Try:")
                print("    1. Enable USB debugging on device")
                print("    2. Accept authorization request on device")
            else:
                print("[!] No ADB devices found. Check:")
                print("    1. Device is connected via USB")
                print("    2. USB debugging is enabled (USB Debugging)")
            return None
        
        if len(devices) == 1:
            print(f"[+] Found device: {devices[0]}")
            return devices[0]
        
        # If multiple devices, prefer physical device (not emulator)
        physical = [d for d in devices if not d.startswith("emulator-")]
        if physical:
            print(f"[*] Multiple devices found, using: {physical[0]}")
            return physical[0]
        else:
            print(f"[*] Multiple emulators found, using: {devices[0]}")
            return devices[0]
    except subprocess.TimeoutExpired:
        print("[!] Timeout while executing 'adb devices'")
        return None
    except FileNotFoundError:
        print("[!] ADB not found in PATH. Make sure Android SDK Platform Tools are installed.")
        return None
    except Exception as e:
        print(f"[!] Error determining ADB device: {e}")
        import traceback
        traceback.print_exc()
        return None


def restart_adb(device_id=None):
    """Restarts ADB to fix connection issues"""
    print("[*] Restarting ADB...")
    max_retries = 3
    
    for attempt in range(max_retries):
        try:
            # Stop ADB server
            print(f"[*] Attempt {attempt + 1}/{max_retries}: stopping ADB server...")
            kill_result = subprocess.run(
                ["adb", "kill-server"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if kill_result.returncode == 0:
                print("[+] ADB server stopped")
            else:
                print(f"[*] ADB kill-server returned code {kill_result.returncode}")
            time.sleep(1.5)
            
            # Start ADB server again
            print("[*] Starting ADB server...")
            start_result = subprocess.run(
                ["adb", "start-server"],
                capture_output=True,
                text=True,
                timeout=15
            )
            if start_result.returncode == 0:
                print("[+] ADB server started")
            else:
                print(f"[!] ADB start-server returned code {start_result.returncode}")
                if start_result.stderr:
                    print(f"[!] Error: {start_result.stderr}")
            time.sleep(2.5)
            
            # Determine device if not specified
            if device_id is None:
                device_id = get_adb_device()
                if device_id is None:
                    if attempt < max_retries - 1:
                        print(f"[*] Device not found, retrying in 2 seconds...")
                        time.sleep(2)
                        continue
                    print("[!] ADB: no devices found after all attempts")
                    return False
            
            # Check connection to specific device
            print(f"[*] Checking connection to device {device_id}...")
            cmd = ["adb", "-s", device_id, "devices"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            # Detailed status check
            if device_id in result.stdout:
                if "device" in result.stdout and "offline" not in result.stdout:
                    # Additional check: try executing a simple command
                    test_cmd = ["adb", "-s", device_id, "shell", "echo", "test"]
                    test_result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=5)
                    if test_result.returncode == 0:
                        print(f"[+] ADB connection successful to device: {device_id}")
                        return device_id
                    else:
                        print(f"[!] Device visible but commands don't execute: {test_result.stderr}")
                elif "offline" in result.stdout:
                    print(f"[!] Device {device_id} is OFFLINE")
                    if attempt < max_retries - 1:
                        print(f"[*] Retrying in 3 seconds...")
                        time.sleep(3)
                        continue
                elif "unauthorized" in result.stdout:
                    print(f"[!] Device {device_id} is UNAUTHORIZED")
                    print("[!] Enable USB debugging on device!")
                    return False
            else:
                print(f"[!] Device {device_id} not found in list")
                print(f"[!] adb devices output: {result.stdout}")
                if attempt < max_retries - 1:
                    print(f"[*] Retrying in 2 seconds...")
                    time.sleep(2)
                    continue
            
            # If we got here and it's not the last attempt - continue
            if attempt < max_retries - 1:
                print(f"[*] Retrying in 2 seconds...")
                time.sleep(2)
                continue
            else:
                return False
                
        except subprocess.TimeoutExpired:
            print(f"[!] Timeout while restarting ADB (attempt {attempt + 1})")
            if attempt < max_retries - 1:
                time.sleep(2)
                continue
            return False
        except Exception as e:
            print(f"[!] Error restarting ADB (attempt {attempt + 1}): {e}")
            if attempt < max_retries - 1:
                time.sleep(2)
                continue
            return False
    
    print("[!] Failed to establish ADB connection after all attempts")
    return False


def ensure_frida_server_remote(device_id):
    """
    Ensures that frida-server is running on device and accessible at 127.0.0.1:27042.
    - Checks for binary at /data/local/tmp/frida-server, pushes from work/ if needed.
    - Starts frida-server with FRIDA_DISABLE_JAVA=1 and -l 0.0.0.0:27042 if not already running.
    - Sets up adb forward tcp:27042 tcp:27042.
    """
    if device_id is None:
        print("[!] device_id not specified for ensure_frida_server_remote")
        return
    
    server_remote = "/data/local/tmp/frida-server"
    server_local = Path("work") / "frida-server-17.5.1-android-arm64"

    # Check if binary exists on device
    try:
        res = subprocess.run(
            ["adb", "-s", device_id, "shell", "su", "-c", f"ls {server_remote}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        need_push = res.returncode != 0
    except Exception:
        need_push = True

    if need_push:
        if not server_local.is_file():
            print(f"[!] Local frida-server not found: {server_local}")
            print("[!] Download frida-server for android-arm64 and place it in work/")
        else:
            print("[*] Copying frida-server to device...")
            subprocess.run(
                ["adb", "-s", device_id, "push", str(server_local), server_remote],
                timeout=30,
            )
            subprocess.run(
                ["adb", "-s", device_id, "shell", "su", "-c", f"chmod 755 {server_remote}"],
                timeout=5,
            )

    # Check if frida-server is running
    running = False
    try:
        res = subprocess.run(
            ["adb", "-s", device_id, "shell", "su", "-c", "ps | grep frida-server | grep -v grep"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        running = "frida-server" in res.stdout and res.returncode == 0
        if running:
            print("[+] frida-server already running")
    except subprocess.TimeoutExpired:
        print("[!] Timeout while checking frida-server")
    except Exception as e:
        print(f"[!] Error checking frida-server: {e}")

    if not running:
        print("[*] frida-server not running, starting it (without Java)...")
        try:
            # First kill old frida-server processes if any
            subprocess.run(
                ["adb", "-s", device_id, "shell", "su", "-c", "pkill -9 frida-server"],
                capture_output=True,
                timeout=5,
            )
            time.sleep(0.5)
            
            # Start new frida-server
            start_result = subprocess.run(
                [
                    "adb",
                    "-s",
                    device_id,
                    "shell",
                    "su",
                    "-c",
                    f"FRIDA_DISABLE_JAVA=1 {server_remote} -l 0.0.0.0:27042 &",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if start_result.returncode == 0:
                print("[+] frida-server start command executed")
            else:
                print(f"[!] Start command returned code {start_result.returncode}")
                if start_result.stderr:
                    print(f"[!] Error: {start_result.stderr}")
            time.sleep(3)  # Give more time for startup
            
            # Check if it started
            try:
                check_res = subprocess.run(
                    ["adb", "-s", device_id, "shell", "su", "-c", "ps | grep frida-server | grep -v grep"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if "frida-server" in check_res.stdout:
                    print("[+] frida-server started successfully")
                    # Additional check: try connecting and executing a command
                    time.sleep(1)
                    try:
                        test_dev = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
                        test_dev.enumerate_processes()  # Try executing a command
                        print("[+] frida-server responding to requests")
                    except Exception as test_e:
                        print(f"[!] frida-server started but not responding: {test_e}")
                        print("[!] Try restarting frida-server manually:")
                        print(f"    adb -s {device_id} shell 'su -c pkill -9 frida-server'")
                        print(f"    adb -s {device_id} shell 'su -c FRIDA_DISABLE_JAVA=1 /data/local/tmp/frida-server -l 0.0.0.0:27042 &'")
                else:
                    print("[!] frida-server didn't start, check root permissions")
            except Exception as e:
                print(f"[!] Failed to verify frida-server startup: {e}")
        except subprocess.TimeoutExpired:
            print("[!] Timeout while starting frida-server")
        except Exception as e:
            print(f"[!] Failed to start frida-server: {e}")

    # Set up port forwarding for frida-server
    print("[*] Setting up port forwarding for frida-server...")
    try:
        # First remove old forward if exists
        subprocess.run(
            ["adb", "-s", device_id, "forward", "--remove", "tcp:27042"],
            capture_output=True,
            timeout=5,
        )
        time.sleep(0.3)
        
        # Create new forward
        forward_result = subprocess.run(
            ["adb", "-s", device_id, "forward", "tcp:27042", "tcp:27042"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if forward_result.returncode == 0:
            print("[+] Port forwarding configured: tcp:27042 -> tcp:27042")
        else:
            print(f"[!] adb forward returned code {forward_result.returncode}")
            if forward_result.stderr:
                print(f"[!] Error: {forward_result.stderr}")
    except subprocess.TimeoutExpired:
        print("[!] Timeout while setting up adb forward")
    except Exception as e:
        print(f"[!] Failed to set up adb forward for frida-server: {e}")


def get_frida_device(device_id=None):
    """
    Returns frida Device, preferring frida-server (remote) over "jailed" USB.
    This bypasses the NotSupportedError: need Gadget to attach on jailed Android.
    """
    # First try frida-server via adb forward -> 127.0.0.1:27042
    try:
        # Set up port forwarding for frida-server
        print("[*] Setting up port forwarding for frida-server...")
        if device_id:
            forward_result = subprocess.run(
                ["adb", "-s", device_id, "forward", "tcp:27042", "tcp:27042"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if forward_result.returncode != 0:
                print(f"[!] adb forward returned error: {forward_result.stderr}")
        else:
            forward_result = subprocess.run(
                ["adb", "forward", "tcp:27042", "tcp:27042"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if forward_result.returncode != 0:
                print(f"[!] adb forward returned error: {forward_result.stderr}")
        
        # Small delay for port forwarding to establish
        time.sleep(0.5)
        
        # Try connecting to remote device
        print("[*] Connecting to frida-server at 127.0.0.1:27042...")
        try:
            dev = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
            # Verify device is actually working
            try:
                dev.enumerate_processes()  # Try executing a command
                print("[+] Connected to frida-server at 127.0.0.1:27042 (remote device)")
                return dev
            except Exception as test_e:
                print(f"[!] Connection established but frida-server not responding: {test_e}")
                raise
        except frida.TransportError as e:
            print(f"[!] Transport error connecting to frida-server: {e}")
            raise
    except frida.TransportError as e:
        print(f"[!] Transport error connecting to frida-server: {e}")
        print("[!] Make sure frida-server is running on device")
        print("[*] Trying standard USB connection frida.get_usb_device()...")
    except Exception as e:
        print(f"[!] Failed to connect to frida-server at 127.0.0.1:27042: {e}")
        print("[*] Trying standard USB connection frida.get_usb_device()...")

    # Fallback: standard path via USB (may require Gadget on "jailed" Android)
    try:
        print("[*] Attempting USB connection...")
        return frida.get_usb_device(timeout=15)
    except Exception as e:
        print(f"[!] Failed to connect via USB: {e}")
        raise


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--script", required=True, help="Path to Frida JS file")
    ap.add_argument("--package", default="auto", help="Package/process name or PID (default: auto-detect BLEACH)")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--spawn", action="store_true", help="Spawn package (default)")
    mode.add_argument("--attach", action="store_true", help="Attach to running process")
    args = ap.parse_args()
    
    # Check ADB availability
    print("[*] Checking ADB availability...")
    try:
        adb_check = subprocess.run(
            ["adb", "version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if adb_check.returncode == 0:
            version_line = adb_check.stdout.split('\n')[0] if adb_check.stdout else "unknown"
            print(f"[+] ADB available: {version_line}")
        else:
            print("[!] ADB returned error when checking version")
            sys.exit(1)
    except FileNotFoundError:
        print("[!] ADB not found in PATH")
        print("[!] Install Android SDK Platform Tools and add them to PATH")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("[!] Timeout while checking ADB")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error checking ADB: {e}")
        sys.exit(1)
    
    # Determine device (first attempt)
    device_id = get_adb_device()
    
    # Restart ADB before starting work (this will also re-determine device_id if needed)
    result = restart_adb(device_id)
    if not result:
        print("\n[!] =========================================")
        print("[!] Failed to establish ADB connection")
        print("[!] =========================================")
        print("[!] Check:")
        print("    1. Device is connected via USB")
        print("    2. USB debugging is enabled (USB Debugging)")
        print("    3. Debugging is allowed for this computer")
        print("    4. Authorization request was accepted on device")
        print("    5. USB mode is set to 'File Transfer' or 'MTP'")
        print("\n[*] Try manually:")
        print("    adb kill-server")
        print("    adb start-server")
        print("    adb devices")
        print("    # If device is 'unauthorized' - authorize on device")
        print("    # If device is 'offline' - reconnect USB")
        sys.exit(1)
    
    # Make sure device_id is set
    if isinstance(result, str):
        device_id = result
    elif device_id is None:
        print("[!] Critical error: device_id not determined")
        sys.exit(1)

    # Ensure frida-server is running and accessible at 127.0.0.1:27042
    ensure_frida_server_remote(device_id)
    
    # Automatic BLEACH process search if not specified
    if args.package == "auto" or args.package.lower() == "bleach":
        print("[*] Automatic BLEACH process search...")

        try:
            device = get_frida_device(device_id)
            processes = device.enumerate_processes()
            matches = [p for p in processes if "bleach" in p.name.lower()]
            if matches:
                args.package = str(matches[0].pid)
                print(f"[+] Found process: {matches[0].name} (PID: {args.package})")
            else:
                print("[!] BLEACH process not found!")
                print("[*] Available processes (first 30):")
                for p in sorted(processes, key=lambda x: x.name)[:30]:
                    print(f"    {p.name} (PID: {p.pid})")
                print()
                print("[!] Make sure the game is running!")
                sys.exit(1)
        except frida.ProcessNotFoundError as e:
            print(f"[!] Frida connection error: {e}")
            print("[!] Make sure:")
            print("    1. Device is connected via USB")
            print("    2. USB debugging is enabled (USB Debugging)")
            print("    3. Debugging is allowed for this computer")
            print("    4. Frida-server is running: adb shell 'su -c /data/local/tmp/frida-server &'")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Error searching for process: {e}")
            sys.exit(1)

    js_path = Path(args.script)
    if not js_path.is_file():
        print(f"[!] JS file not found: {js_path}")
        sys.exit(1)

    try:
        device = get_frida_device(device_id)
    except frida.ProcessNotFoundError:
        print("[!] Error: USB device not found")
        print("[!] Check:")
        print("    1. Device is connected via USB")
        print("    2. USB debugging is enabled (USB Debugging)")
        print("    3. Debugging is allowed for this computer")
        print("    4. Frida-server is running: adb shell 'su -c /data/local/tmp/frida-server &'")
        sys.exit(1)

    if args.attach:
        print(f"[*] Attaching to {args.package} ...")
        # If PID is specified as number - attach directly, without name search
        if args.package.isdigit():
            pid = int(args.package)
            print(f"[+] Using PID: {pid}")
            session = device.attach(pid)
        else:
            # Special path for BLEACH: Soul Resonance, to avoid touching
            # enumerate_processes() / getRunningAppProcesses (they break Frida for us).
            target_pkg = args.package.lower()
            if target_pkg in ("auto", "bleach", "com.bleach.apj"):
                print("[*] Resolving PID via adb shell pidof com.bleach.apj ...")
                try:
                    cmd = ["adb", "-s", device_id, "shell", "pidof", "com.bleach.apj"]
                    res = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if res.returncode != 0 or not res.stdout.strip():
                        print(f"[!] pidof com.bleach.apj didn't return PID: {res.stdout} {res.stderr}")
                        sys.exit(1)
                    pid = int(res.stdout.strip().split()[0])
                    print(f"[+] Found PID via pidof: {pid}")
                    
                    # Additional check before attach
                    print(f"[*] Checking process availability PID {pid}...")
                    try:
                        # Check that process exists and is accessible
                        test_cmd = ["adb", "-s", device_id, "shell", "su", "-c", f"ls -l /proc/{pid}/exe"]
                        test_res = subprocess.run(test_cmd, capture_output=True, text=True, timeout=5)
                        if test_res.returncode != 0:
                            print(f"[!] Process PID {pid} is not accessible: {test_res.stderr}")
                            sys.exit(1)
                        print(f"[+] Process PID {pid} is accessible")
                    except Exception as e:
                        print(f"[!] Error checking process: {e}")
                    
                    # Small delay before attach
                    time.sleep(1)
                    
                    try:
                        session = device.attach(pid)
                        print(f"[+] Connected to PID {pid} (BLEACH: Soul Resonance)")
                    except frida.ProcessNotFoundError as e:
                        print(f"[!] Process not found: {e}")
                        print(f"[!] Make sure game is running and process is active")
                        sys.exit(1)
                    except frida.ExecutableNotFoundError as e:
                        print(f"[!] Executable not found: {e}")
                        sys.exit(1)
                    except Exception as e:
                        error_msg = str(e)
                        if "ptrace" in error_msg.lower() or "i/o error" in error_msg.lower():
                            print(f"[!] ptrace error connecting to process: {e}")
                            print(f"[!] Possible causes:")
                            print(f"    1. Frida-server not running or not responding")
                            print(f"    2. Process is protected from debugging (anti-debug)")
                            print(f"    3. SELinux blocking ptrace (check: adb shell 'su -c getenforce')")
                            print(f"    4. Insufficient root permissions")
                            print(f"\n[*] Try:")
                            print(f"    1. Restart frida-server: adb shell 'su -c pkill frida-server && su -c /data/local/tmp/frida-server &'")
                            print(f"    2. Check SELinux: adb shell 'su -c getenforce'")
                            print(f"    3. Temporarily disable SELinux: adb shell 'su -c setenforce 0'")
                        else:
                            print(f"[!] Failed to connect to process: {e}")
                        sys.exit(1)
                except ValueError as e:
                    print(f"[!] Invalid PID format: {e}")
                    sys.exit(1)
                except Exception as e:
                    print(f"[!] Failed to get BLEACH PID via pidof: {e}")
                    sys.exit(1)
            else:
                # General case for other processes - can try by name
                # (here we can allow enumerate_processes, as BLEACH is not affected).
                try:
                    session = device.attach(args.package)
                except (frida.ProcessNotFoundError, ValueError):
                    print(f"[!] Process '{args.package}' not found, searching by partial match...")
                    processes = device.enumerate_processes()
                    matches = [p for p in processes if args.package.lower() in p.name.lower()]
                    if matches:
                        print(f"[+] Found processes: {[p.name for p in matches]}")
                        session = device.attach(matches[0].pid)
                        print(f"[+] Connected to PID {matches[0].pid} ({matches[0].name})")
                    else:
                        print(f"[!] Process not found. Available processes:")
                        for p in sorted(processes, key=lambda x: x.name)[:20]:
                            print(f"    {p.name} (PID: {p.pid})")
                        raise
    else:
        print(f"[*] Spawning {args.package} ...")
        pid = device.spawn([args.package])
        session = device.attach(pid)
        device.resume(pid)
        print(f"[*] Spawned PID {pid}")

    script = load_script(session, js_path)
    print(f"[+] Script loaded: {js_path}")
    
    # Check if RPC exports exist (for interactive menu)
    has_rpc = False
    try:
        ping_result = script.exports.ping()
        has_rpc = True
        print("[+] RPC exports available - interactive menu enabled")
    except:
        print("[*] No RPC exports - running in monitor mode")
        print("[*] Press Ctrl+C to quit")
    
    # Automatic traffic file synchronization (if using network_traffic_interceptor.js)
    traffic_sync_enabled = "network_traffic_interceptor" in str(js_path)
    traffic_sync_thread = None
    
    if traffic_sync_enabled:
        import threading
        
        def sync_traffic_files():
            """Periodically syncs traffic files from device to computer"""
            remote_dir = "/sdcard/Download/bleach_traffic/"
            local_dir = Path("work") / "traffic_dumps"
            local_dir.mkdir(parents=True, exist_ok=True)
            
            synced_files = set()
            
            while True:
                try:
                    time.sleep(5)  # Sync every 5 seconds
                    
                    # Get list of files on device
                    cmd = ["adb", "-s", device_id, "shell", "ls", remote_dir]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    
                    if result.returncode == 0:
                        files = [f.strip() for f in result.stdout.split('\n') if f.strip() and f.strip().endswith(('.json', '.bin'))]
                        
                        for filename in files:
                            if filename not in synced_files:
                                remote_path = remote_dir + filename
                                local_path = local_dir / filename
                                
                                # Copy file
                                pull_cmd = ["adb", "-s", device_id, "pull", remote_path, str(local_path)]
                                pull_result = subprocess.run(pull_cmd, capture_output=True, timeout=10)
                                
                                if pull_result.returncode == 0:
                                    synced_files.add(filename)
                                    print(f"[SYNC] Copied: {filename} -> {local_path}")
                                else:
                                    # File may be locked, skip
                                    pass
                except Exception as e:
                    # Ignore sync errors (not critical)
                    pass
        
        traffic_sync_thread = threading.Thread(target=sync_traffic_files, daemon=True)
        traffic_sync_thread.start()
        print("[+] Traffic file sync enabled (backup method)")
    
    # Global variables for reconnection (accessible via closure)
    reconnect_context = {
        'device': device,
        'device_id': device_id,
        'args': args,
        'js_path': js_path,
        'session': session,
        'script': script
    }
    
    def reconnect_to_game():
        """Reconnects to game"""
        print("\n[*] Reconnecting to game...")
        try:
            # Disconnect from old session
            try:
                reconnect_context['script'].unload()
                reconnect_context['session'].detach()
            except:
                pass
            
            time.sleep(1)
            
            # Get new device
            new_device = get_frida_device(reconnect_context['device_id'])
            
            # Reconnect to process
            if reconnect_context['args'].attach:
                target_pkg = reconnect_context['args'].package
                if target_pkg.lower() in ("auto", "bleach", "com.bleach.apj") or not target_pkg.isdigit():
                    # Search for PID via pidof
                    cmd = ["adb", "-s", reconnect_context['device_id'], "shell", "pidof", "com.bleach.apj"]
                    res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    if res.returncode == 0 and res.stdout.strip():
                        pid = int(res.stdout.strip().split()[0])
                        new_session = new_device.attach(pid)
                        print(f"[+] Reconnected to PID {pid}")
                    else:
                        print("[!] Game process not found")
                        return None, None
                else:
                    pid = int(target_pkg)
                    new_session = new_device.attach(pid)
                    print(f"[+] Reconnected to PID {pid}")
            else:
                # Spawn mode - restart application
                pid = new_device.spawn([reconnect_context['args'].package])
                new_session = new_device.attach(pid)
                new_device.resume(pid)
                print(f"[+] Spawned and attached to PID {pid}")
            
            # Reload script
            new_script = load_script(new_session, reconnect_context['js_path'])
            print("[+] Script reloaded")
            
            # Update context
            reconnect_context['session'] = new_session
            reconnect_context['script'] = new_script
            reconnect_context['device'] = new_device
            
            time.sleep(2)  # Give time for initialization
            return new_session, new_script
            
        except Exception as e:
            print(f"[!] Reconnection failed: {e}")
            import traceback
            traceback.print_exc()
            return None, None
    
    def show_menu(script_ref=None):
        """Shows control menu"""
        if script_ref is None:
            script_ref = reconnect_context['script']
        print("\n" + "="*60)
        print("W26 DAMAGE MULTIPLIER MENU")
        print("="*60)
        try:
            stats = script_ref.exports.get_stats()
            print(f"Stats: total={stats['totalProtos']}, matched={stats['matchedProtos']}, found={stats['foundProtos']}")
        except:
            pass
        
        try:
            protos = script_ref.exports.list_protos()
            if protos:
                print("\nFound Protos:")
                for i, p in enumerate(protos, 1):
                    print(f"  {i}. {p['tag']}: current={p['currentValue']}, original={p['originalValue']}")
            else:
                print("\nNo Protos found yet. Wait for game to load Lua chunks.")
        except Exception as e:
            print(f"Error listing protos: {e}")
        
        print("\nCommands:")
        print("  1 - Set damage multiplier")
        print("  2 - Show current multiplier")
        print("  3 - Reset to original value")
        print("  4 - Show stats")
        print("  5 - Reconnect to game (requires script restart)")
        print("  q - Quit")
        print("="*60)
    
    def handle_command(cmd, script_ref=None):
        """Handles menu command"""
        if script_ref is None:
            script_ref = reconnect_context['script']
        cmd = cmd.strip().lower()
        
        if cmd == 'q' or cmd == 'quit':
            return False
        
        elif cmd == '1':
            try:
                protos = script_ref.exports.list_protos()
                if not protos:
                    print("[!] No Protos found. Wait for game to load Lua chunks.")
                    return True
                
                print("\nAvailable Protos:")
                for i, p in enumerate(protos, 1):
                    print(f"  {i}. {p['tag']} (current: {p['currentValue']})")
                
                choice = input("\nSelect Proto number (or tag name): ").strip()
                proto_tag = None
                
                if choice.isdigit():
                    idx = int(choice) - 1
                    if 0 <= idx < len(protos):
                        proto_tag = protos[idx]['tag']
                    else:
                        print("[!] Invalid number")
                        return True
                else:
                    proto_tag = choice
                
                mult_str = input("Enter new multiplier (e.g., 0.01, 0.1, 1.0, 10.0): ").strip()
                try:
                    multiplier = float(mult_str)
                    result = script_ref.exports.set_damage_multiplier(proto_tag, multiplier)
                    if result.get('success'):
                        print(f"[+] Multiplier set to {multiplier} for {proto_tag}")
                    else:
                        print(f"[!] Error: {result.get('error', 'Unknown error')}")
                except ValueError:
                    print("[!] Invalid multiplier value")
            except Exception as e:
                print(f"[!] Error: {e}")
        
        elif cmd == '2':
            try:
                protos = script_ref.exports.list_protos()
                if protos:
                    print("\nCurrent multipliers:")
                    for p in protos:
                        print(f"  {p['tag']}: {p['currentValue']} (original: {p['originalValue']})")
                else:
                    print("[!] No Protos found yet.")
            except Exception as e:
                print(f"[!] Error: {e}")
        
        elif cmd == '3':
            try:
                protos = script_ref.exports.list_protos()
                if not protos:
                    print("[!] No Protos found.")
                    return True
                
                print("\nAvailable Protos:")
                for i, p in enumerate(protos, 1):
                    print(f"  {i}. {p['tag']}")
                
                choice = input("\nSelect Proto number (or 'all' for all): ").strip().lower()
                
                if choice == 'all':
                    for p in protos:
                        result = script_ref.exports.set_damage_multiplier(p['tag'], p['originalValue'])
                        if result.get('success'):
                            print(f"[+] Reset {p['tag']} to original: {p['originalValue']}")
                elif choice.isdigit():
                    idx = int(choice) - 1
                    if 0 <= idx < len(protos):
                        p = protos[idx]
                        result = script_ref.exports.set_damage_multiplier(p['tag'], p['originalValue'])
                        if result.get('success'):
                            print(f"[+] Reset {p['tag']} to original: {p['originalValue']}")
                    else:
                        print("[!] Invalid number")
                else:
                    result = script_ref.exports.set_damage_multiplier(choice, None)
                    if result.get('success'):
                        print(f"[+] Reset {choice}")
            except Exception as e:
                print(f"[!] Error: {e}")
        
        elif cmd == '4':
            try:
                stats = script_ref.exports.get_stats()
                print("\nStatistics:")
                print(f"  Total Protos processed: {stats['totalProtos']}")
                print(f"  Interesting Protos: {stats['interestingProtos']}")
                print(f"  Matched Protos: {stats['matchedProtos']}")
                print(f"  Found Protos (for menu): {stats['foundProtos']}")
            except Exception as e:
                print(f"[!] Error: {e}")
        
        elif cmd == '5':
            print("\n[*] Reconnecting to game...")
            new_session, new_script = reconnect_to_game()
            if new_session and new_script:
                print("[+] Reconnection successful! Menu will use new connection.")
                return True
            else:
                print("[!] Reconnection failed. You may need to restart the script.")
                return False
        
        else:
            print("[!] Unknown command. Type 'q' to quit or number to select option.")
        
        return True
    
    # Main loop with interactive menu
    # Use dictionary to store flag so it's accessible from closure
    menu_state = {'running': True}
    
    def menu_thread_func():
        """Thread for interactive menu"""
        time.sleep(2)  # Give time for initialization
        
        while menu_state['running']:
            try:
                # Always use current script from reconnect_context
                current_script = reconnect_context['script']
                show_menu(current_script)
                cmd = input("\nCommand (or 'q' to quit): ").strip()
                if not cmd:
                    continue
                if cmd.lower() in ('q', 'quit', 'exit'):
                    menu_state['running'] = False
                    break
                handle_command(cmd, current_script)
            except (EOFError, KeyboardInterrupt):
                menu_state['running'] = False
                break
            except Exception as e:
                print(f"[!] Menu error: {e}")
                time.sleep(1)
    
    try:
        if has_rpc:
            print("\n[*] Interactive menu enabled")
            print("[*] Menu will appear in separate thread")
            print("[*] Press Ctrl+C in main thread to quit\n")
            
            # Start menu in separate thread
            import threading
            menu_thread = threading.Thread(target=menu_thread_func, daemon=True)
            menu_thread.start()
        
        # Main loop - process messages from Frida
        while menu_state['running']:
            time.sleep(0.2)
    except KeyboardInterrupt:
        menu_state['running'] = False
    finally:
        print("\n[*] Detaching...")
        try:
            reconnect_context['script'].unload()
            reconnect_context['session'].detach()
        except:
            pass


if __name__ == "__main__":
    main()

