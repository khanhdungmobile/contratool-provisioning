"""Utility helpers for CONTRATOOL provisioning flows.

This script can:
1. Compute the SHA-256 checksum (hex + base64) for a release APK.
2. Emit an Android Device Owner provisioning payload to JSON.
3. Render a QR code (PNG) from that payload for quick enrollment.

Example:

    python samsung_tool.py \
        --apk output/contratool.apk \
        --download-url https://github.com/<user>/contratool-provisioning/releases/download/v1.0.0/contratool.apk

Requirements:
    pip install qrcode[pil]

"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path
from typing import Any, Dict


def compute_sha256(apk_path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with apk_path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure_qrcode_module():
    try:
        import qrcode  # noqa: F401
    except ImportError as exc:
        raise SystemExit(
            "The 'qrcode' package is required. Install it with: pip install qrcode[pil]"
        ) from exc


def build_payload(
    *,
    component: str,
    download_url: str,
    checksum_b64: str,
    enrollment_id: str,
    leave_system_apps: bool,
    skip_encryption: bool,
) -> Dict[str, Any]:
    return {
        "android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME": component,
        "android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_DOWNLOAD_LOCATION": download_url,
        "android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_CHECKSUM": checksum_b64,
        "android.app.extra.PROVISIONING_LEAVE_ALL_SYSTEM_APPS_ENABLED": leave_system_apps,
        "android.app.extra.PROVISIONING_SKIP_ENCRYPTION": skip_encryption,
        "android.app.extra.PROVISIONING_ADMIN_EXTRAS_BUNDLE": {
            "enrollmentId": enrollment_id,
        },
    }


def save_json(payload: Dict[str, Any], destination: Path) -> None:
    destination.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def write_qr(payload: Dict[str, Any], destination: Path) -> None:
    ensure_qrcode_module()
    import qrcode

    qr_data = json.dumps(payload, separators=(",", ":"))
    img = qrcode.make(qr_data)
    img.save(destination)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate provisioning payload + QR code.")
    parser.add_argument(
        "--apk",
        type=Path,
        default=Path("output/contratool.apk"),
        help="Path to the signed APK used for provisioning (default: output/contratool.apk).",
    )
    parser.add_argument(
        "--download-url",
        required=True,
        help="Public URL where the APK can be downloaded by the device during provisioning.",
    )
    parser.add_argument(
        "--component",
        default="com.tsm.amdm.knox/com.tsm.amdm.knox.Hubris",
        help="Fully-qualified Device Admin component (default: %(default)s).",
    )
    parser.add_argument(
        "--enrollment-id",
        default="kQG3ExcW0xhKnhciHPhZPuXNcaeBjTwsflli3_SYnVI=",
        help="Enrollment identifier to embed inside the extras bundle.",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=Path("provisioning.json"),
        help="File path to save the provisioning payload JSON (default: provisioning.json).",
    )
    parser.add_argument(
        "--output-qr",
        type=Path,
        default=Path("provisioning_qr.png"),
        help="File path to save the generated QR image (default: provisioning_qr.png).",
    )
    parser.add_argument(
        "--no-qr",
        action="store_true",
        help="Skip generating the QR image (only write JSON).",
    )
    parser.add_argument(
        "--leave-system-apps",
        action="store_true",
        default=True,
        help="Keep all system apps enabled (default: true).",
    )
    parser.add_argument(
        "--force-encryption",
        action="store_true",
        help="Do not include the skip-encryption flag (i.e. require encryption).",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    apk_path: Path = args.apk
    if not apk_path.is_file():
        print(f"[!] APK not found: {apk_path}", file=sys.stderr)
        return 1

    sha_hex = compute_sha256(apk_path)
    sha_b64 = base64.b64encode(bytes.fromhex(sha_hex)).decode()

    payload = build_payload(
        component=args.component,
        download_url=args.download_url,
        checksum_b64=sha_b64,
        enrollment_id=args.enrollment_id,
        leave_system_apps=bool(args.leave_system_apps),
        skip_encryption=not args.force_encryption,
    )

    save_json(payload, args.output_json)
    print(f"[*] JSON written to {args.output_json}")

    if not args.no_qr:
        write_qr(payload, args.output_qr)
        print(f"[*] QR image written to {args.output_qr}")

    print("[*] SHA-256 (hex):", sha_hex)
    print("[*] SHA-256 (base64):", sha_b64)
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1:
        raise SystemExit(main(sys.argv[1:]))
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🔥 CONTRA PRO 16 - PROFESSIONAL EDITION
Workflow: QR Code → Enable ADB → KG Removal → Change CSC → Done
100% Real Combat - Simple & Clean
"""

import sys
import os
import hashlib
import uuid
import platform
import importlib
import importlib.util
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import threading
import time
import qrcode
import socket
from PIL import Image, ImageTk, ImageSequence
import http.server
import socketserver
import urllib.request
import urllib.parse
from pathlib import Path
from tkinter import filedialog
from functools import partial
# THÊM ĐOẠN CODE NÀY VÀO ĐẦU FILE (sau import sys, os, ...)

def resource_path(relative_path):
    """
    Get absolute path to resource, works for dev and for PyInstaller.
    Sử dụng sys._MEIPASS để truy cập tài nguyên bên trong gói exe.
    """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        # Base path khi chạy bằng Python
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)
QR_DECODE_AVAILABLE = False
qr_decode = None

try:
    pyzbar_spec = importlib.util.find_spec('pyzbar.pyzbar')
    if pyzbar_spec is not None:
        pyzbar_module = importlib.import_module('pyzbar.pyzbar')
        qr_decode = pyzbar_module.decode
        QR_DECODE_AVAILABLE = True
except Exception as exc:
    print(f"pyzbar not available: {exc}")
    QR_DECODE_AVAILABLE = False
    qr_decode = None

try:
    import cv2
except Exception as exc:
    print(f"cv2 not available: {exc}")

class ContraPro16:
    def __init__(self, root):
        self.root = root
        self.root.title("CONTRA 16 PRO - REMOVE MDM -KG -KNOX")
        self.root.geometry("1000x700")
        self.root.configure(bg='#0d1117')
        
        # Modern UI 2026 color scheme
        self.colors = {
            'bg': '#0d1117',
            'panel': '#161b22',
            'accent': '#58a6ff',
            'success': '#3fb950',
            'warning': '#d29922',
            'error': '#f85149',
            'text': '#c9d1d9',
            'text_dim': '#8b949e',
        }
        
        # Lược bỏ logic Path/assets phức tạp và thay bằng resource_path()
        # Các file tài nguyên được đóng gói phải nằm cùng thư mục với samsung_tool.py khi build
        
        self.hwid = self.generate_hwid()
        self.hwid_allowed = False
        self.hwid_source = None
        self.protected_buttons = []
        self.auto_button = None
        self.hwid_popup = None
        self._hwid_checking = False
        self._hwid_retry_job = None

        self.qr_image = None
        self.qr_image_tk = None
        self.http_server = None
        self.server_thread = None
        self.server_port = 8080
        self.apk_path = None
        self.local_ip = None
        self.auto_running = False

        self.adb_image = None

        # Shared UI state
        self.default_apk_url = "https://github.com/khanhdungmobile/contra-adb-apk-/raw/main/contra-adb.apk"
        self.url_var = tk.StringVar(master=self.root, value=self.default_apk_url)
        self.server_status_var = tk.StringVar(master=self.root, value="🔴 Server: Stopped")
        self.server_status_label = None
        self.qr_label = None

        # --- SỬA CÁC ĐƯỜNG DẪN TÀI NGUYÊN (QUAN TRỌNG NHẤT) ---
        # Sử dụng resource_path cho TẤT CẢ các file được đóng gói
        self.logo_gif_path = resource_path('92fcd16d4d0bd4751394e94232aa7713.gif') # Giữ lại, nhưng dùng resource_path
        self.logo_icon_path = resource_path('f64_icon.ico')         # SỬA LỖI: Load icon
        self.logo_static_path = resource_path('contra.png')          # SỬA LỖI: Load logo (dùng tên file bạn tải lên)
        
        self.qr_default_path = resource_path('qr_default.png')      # SỬA LỖI: Load QR default
        self.qr_adb_path = resource_path('QRCODEADB.png')           # SỬA LỖI: Load QR ADB
        
        self.logo_frames = []
        self.logo_frame_index = 0
        self.logo_label = None
        self.animating_logo = False
        self.logo_static_image = None
        
        # Set window icon (sẽ dùng self.logo_icon_path đã được sửa)
        self.set_window_icon()
        
        self.setup_ui()
        self.disable_action_buttons()
        
        # Auto check device connection every 3 seconds
        self.auto_check_device()

        # HWID popup & verification
        self.root.after(500, self.initialize_hwid_flow)
    
    def set_window_icon(self):
        """Set window icon"""
        try:
            if os.path.exists(self.logo_icon_path):
                self.root.iconbitmap(self.logo_icon_path)
        except Exception as e:
            print(f"Could not set window icon: {e}")

    # === HWID METHODS ===

    def generate_hwid(self):
        """Sinh HWID dạng SHA256 dựa trên thông tin máy"""
        try:
            node = uuid.getnode()
            components = [
                str(node),
                platform.node(),
                platform.platform(),
                platform.processor() or "unknown",
            ]
            hwid_source = "|".join(components)
            digest = hashlib.sha256(hwid_source.encode('utf-8')).hexdigest().upper()
            return digest
        except Exception as exc:
            print(f"HWID generation error: {exc}")
            fallback = uuid.uuid4().hex.upper()
            return fallback

    def initialize_hwid_flow(self, triggered_by_user=False):
        """Khởi động kiểm tra HWID và hiển thị popup"""
        if self._hwid_checking:
            return

        self._hwid_checking = True

        def worker():
            allowed_hwids, source = self.fetch_allowed_hwids()
            if allowed_hwids is None:
                is_allowed = True
            else:
                is_allowed = self.hwid in allowed_hwids or "*" in allowed_hwids
            self.root.after(0, lambda: self._on_hwid_check_result(is_allowed, source, triggered_by_user))

        threading.Thread(target=worker, daemon=True).start()

    def _on_hwid_check_result(self, is_allowed, source, triggered_by_user):
        self._hwid_checking = False
        self.hwid_source = source

        if is_allowed:
            self.hwid_allowed = True
            self.enable_action_buttons()
            if self._hwid_retry_job is not None:
                self.root.after_cancel(self._hwid_retry_job)
                self._hwid_retry_job = None
        else:
            self.hwid_allowed = False
            self.disable_action_buttons()
            if self._hwid_retry_job is None:
                self._hwid_retry_job = self.root.after(300000, self._retry_hwid_check)

        self.show_hwid_popup(is_allowed, source, triggered_by_user)

    def _retry_hwid_check(self):
        self._hwid_retry_job = None
        self.initialize_hwid_flow()

    def fetch_allowed_hwids(self):
        """Lấy danh sách HWID hợp lệ từ gist"""
        urls = [
            "https://raw.githubusercontent.com/khanhdungmobile/contratool-provisioning/main/allowed_hwid.txt",
            "https://gist.githubusercontent.com/khanhdungmobile/cd503c2dc82fcfb9abd6187e89f4b4a9/raw/allowed_hwid.txt",
            "https://gist.githubusercontent.com/khanhdungmobile/cd503c2dc82fcfb9abd6187e89f4b4a9/raw/gistfile1.txt",
        ]
        for url in urls:
            try:
                with urllib.request.urlopen(url, timeout=5) as response:
                    data = response.read().decode('utf-8', errors='ignore')
                    lines = [line.strip().upper() for line in data.splitlines() if line.strip()]
                    if lines:
                        return set(lines), url
            except Exception as exc:
                print(f"HWID list fetch failed from {url}: {exc}")
                continue
        local_path = Path("allowed_hwid.txt")
        if local_path.exists():
            try:
                data = local_path.read_text(encoding="utf-8", errors="ignore")
                lines = [line.strip().upper() for line in data.splitlines() if line.strip()]
                if lines:
                    return set(lines), str(local_path)
            except Exception as exc:
                print(f"HWID local file read failed: {exc}")
        return None, "offline"

    def show_hwid_popup(self, is_allowed, source, triggered_by_user=False):
        """Hiển thị popup HWID để tiện gửi cho admin"""
        if self.hwid_popup and self.hwid_popup.winfo_exists():
            try:
                self.hwid_popup.destroy()
            except Exception:
                pass

        popup = tk.Toplevel(self.root)
        popup.title("HWID Activation")
        popup.geometry("460x260")
        popup.configure(bg=self.colors['bg'])
        popup.resizable(False, False)
        popup.transient(self.root)
        popup.grab_set()
        self.hwid_popup = popup

        status_text = "Đang kiểm tra HWID..."
        status_color = self.colors['warning']
        helper_lines = []

        if is_allowed is True:
            status_text = "✅ HWID đã được kích hoạt"
            status_color = self.colors['success']
            helper_lines.append("Bạn có thể sử dụng đầy đủ chức năng của tool.")
        elif is_allowed is False:
            status_text = "❌ HWID chưa có trong danh sách cho phép"
            status_color = self.colors['error']
            helper_lines.append("Gửi HWID cho admin hoặc chờ kích hoạt (khoảng 5 phút sau khi cập nhật).")
            helper_lines.append("Hệ thống sẽ tự kiểm tra lại định kỳ.")
        else:
            status_text = "⚠️ Không thể tải danh sách HWID"
            status_color = self.colors['warning']
            helper_lines.append("Kiểm tra kết nối Internet rồi nhấn Refresh." )

        tk.Label(
            popup,
            text="HWID SHA256",
            font=('Segoe UI', 16, 'bold'),
            fg=self.colors['accent'],
            bg=self.colors['bg']
        ).pack(pady=(20, 10))

        hwid_entry = tk.Entry(
            popup,
            font=('Consolas', 11),
            fg=self.colors['text'],
            bg=self.colors['panel'],
            relief=tk.FLAT,
            width=60
        )
        hwid_entry.insert(0, self.hwid)
        hwid_entry.config(state='readonly')
        hwid_entry.pack(padx=20, pady=5, ipady=6)

        status_label = tk.Label(
            popup,
            text=status_text,
            font=('Segoe UI', 11, 'bold'),
            fg=status_color,
            bg=self.colors['bg'],
            wraplength=420,
            justify=tk.CENTER
        )
        status_label.pack(pady=5)

        if helper_lines:
            tk.Label(
                popup,
                text="\n".join(helper_lines),
                font=('Segoe UI', 9),
                fg=self.colors['text_dim'],
                bg=self.colors['bg'],
                wraplength=420,
                justify=tk.CENTER
            ).pack(pady=(0, 8))

        if source:
            tk.Label(
                popup,
                text=f"Danh sách: {source}",
                font=('Segoe UI', 8),
                fg=self.colors['text_dim'],
                bg=self.colors['bg']
            ).pack(pady=(0, 5))

        btn_frame = tk.Frame(popup, bg=self.colors['bg'])
        btn_frame.pack(pady=15)

        def copy_hwid():
            self.copy_to_clipboard(self.hwid)

        def close_popup():
            try:
                popup.destroy()
            except Exception:
                pass
            self.hwid_popup = None
            if not self.hwid_allowed:
                self.root.after(0, self.root.destroy)

        def refresh_hwid():
            try:
                popup.destroy()
            except Exception:
                pass
            self.hwid_popup = None
            self.initialize_hwid_flow(triggered_by_user=True)

        tk.Button(
            btn_frame,
            text="Copy HWID",
            command=copy_hwid,
            font=('Segoe UI', 10, 'bold'),
            bg=self.colors['accent'],
            fg='white',
            padx=18,
            pady=6,
            relief=tk.FLAT,
            cursor='hand2'
        ).pack(side=tk.LEFT, padx=8)

        if self.hwid_allowed:
            tk.Button(
                btn_frame,
                text="Bắt đầu sử dụng",
                command=close_popup,
                font=('Segoe UI', 10, 'bold'),
                bg=self.colors['success'],
                fg='white',
                padx=18,
                pady=6,
                relief=tk.FLAT,
                cursor='hand2'
            ).pack(side=tk.LEFT, padx=8)
        else:
            tk.Button(
                btn_frame,
                text="Refresh",
                command=refresh_hwid,
                font=('Segoe UI', 10, 'bold'),
                bg=self.colors['warning'],
                fg='white',
                padx=18,
                pady=6,
                relief=tk.FLAT,
                cursor='hand2'
            ).pack(side=tk.LEFT, padx=8)

            tk.Button(
                btn_frame,
                text="Thoát",
                command=close_popup,
                font=('Segoe UI', 10, 'bold'),
                bg=self.colors['bg'],
                fg=self.colors['text'],
                padx=18,
                pady=6,
                relief=tk.FLAT,
                cursor='hand2'
            ).pack(side=tk.LEFT, padx=8)

        popup.bind('<Escape>', lambda _: close_popup())
        popup.protocol('WM_DELETE_WINDOW', close_popup)
    
    def load_logo_gif(self):
        """Load GIF frames for animation"""
        try:
            if not os.path.exists(self.logo_gif_path):
                return False
            
            gif = Image.open(self.logo_gif_path)
            self.logo_frames = []
            
            # Extract all frames with their durations
            for frame in ImageSequence.Iterator(gif):
                # Get duration for this frame (default 100ms if not specified)
                duration = 100
                if 'duration' in frame.info:
                    duration = frame.info['duration']
                    if duration <= 0:
                        duration = 100
                
                # Resize if needed (max 80x80 for header)
                frame_copy = frame.copy()
                frame_copy.thumbnail((80, 80), Image.Resampling.LANCZOS)
                photo = ImageTk.PhotoImage(frame_copy)
                self.logo_frames.append((photo, duration))
            
            gif.close()
            return len(self.logo_frames) > 0
        except Exception as e:
            print(f"Could not load logo GIF: {e}")
            return False
    
    def animate_logo(self):
        """Animate logo GIF"""
        if not self.logo_frames or not self.logo_label:
            return
        
        if not self.animating_logo:
            return
        
        try:
            # Get current frame
            frame_data = self.logo_frames[self.logo_frame_index]
            photo, duration = frame_data
            
            # Update label
            self.logo_label.config(image=photo)
            self.logo_label.image = photo  # Keep a reference
            
            # Move to next frame
            self.logo_frame_index = (self.logo_frame_index + 1) % len(self.logo_frames)
            
            # Schedule next frame
            self.root.after(duration, self.animate_logo)
        except Exception as e:
            print(f"Logo animation error: {e}")
            self.animating_logo = False
    
    def setup_ui(self):
        """Setup simple UI"""
        # Main container
        main_frame = tk.Frame(self.root, bg=self.colors['bg'])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Header
        self.create_header(main_frame)
        
        # Content area
        self.create_content(main_frame)
        
        # Status bar
        self.create_status_bar(main_frame)
    
    def create_header(self, parent):
        """Create header"""
        header = tk.Frame(parent, bg=self.colors['bg'], height=80)
        header.pack(fill=tk.X, pady=(0, 20))
        header.pack_propagate(False)
        
        logo_container = tk.Frame(header, bg=self.colors['bg'])
        logo_container.pack(side=tk.LEFT, padx=(0, 15), pady=10)

        # SỬA LỖI TẠI ĐÂY: Dùng os.path.exists() thay cho .exists()
        if os.path.exists(self.logo_static_path):
            try:
                img = Image.open(self.logo_static_path)
                img.thumbnail((96, 96), Image.Resampling.LANCZOS)
                self.logo_static_image = ImageTk.PhotoImage(img)
                tk.Label(
                    logo_container,
                    image=self.logo_static_image,
                    bg=self.colors['bg']
                ).pack()
            except Exception as exc:
                print(f"Failed to load static logo: {exc}")
                tk.Label(
                    logo_container,
                    text="⚡",
                    font=('Segoe UI', 48),
                    fg=self.colors['accent'],
                    bg=self.colors['bg']
                ).pack()
        else:
            tk.Label(
                logo_container,
                text="⚡",
                font=('Segoe UI', 48),
                fg=self.colors['accent'],
                bg=self.colors['bg']
            ).pack()
        
        # Title
        title_label = tk.Label(
            header,
            text="⚡ CONTRA 16 PRO - REMOVE MDM -KG -KNOX",
            font=('Segoe UI', 26, 'bold'),
            fg=self.colors['accent'],
            bg=self.colors['bg']
        )
        title_label.pack(side=tk.LEFT, pady=20)
        
        # Version badge
        version_frame = tk.Frame(header, bg=self.colors['panel'], relief=tk.FLAT)
        version_frame.pack(side=tk.LEFT, padx=20, pady=25)
        
        version_label = tk.Label(
            version_frame,
            text="v1.0.0 PRO",
            font=('Segoe UI', 11, 'bold'),
            fg=self.colors['text'],
            bg=self.colors['panel'],
            padx=15,
            pady=8
        )
        version_label.pack()
        
        # Device status
        status_frame = tk.Frame(header, bg=self.colors['bg'])
        status_frame.pack(side=tk.RIGHT, fill=tk.Y, pady=20)
        
        tk.Label(
            status_frame,
            text="Device:",
            font=('Segoe UI', 10),
            fg=self.colors['text_dim'],
            bg=self.colors['bg']
        ).pack(side=tk.LEFT, padx=5)
        
        self.device_status = tk.Label(
            status_frame,
            text="Not Connected",
            font=('Segoe UI', 12, 'bold'),
            fg=self.colors['error'],
            bg=self.colors['bg']
        )
        self.device_status.pack(side=tk.LEFT, padx=5)
    
    def create_content(self, parent):
        """Create main content with tabs"""
        content = tk.Frame(parent, bg=self.colors['bg'])
        content.pack(fill=tk.BOTH, expand=True)
        
        # Tab buttons
        tab_frame = tk.Frame(content, bg=self.colors['bg'])
        tab_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.current_tab = tk.StringVar(value="adb")
        
        tabs = [
            ("📱 Bật ADB", "adb", self.colors['accent']),
            ("🔥 KG Removal", "kg", self.colors['success']),
            ("🔧 Change CSC", "csc", self.colors['warning'])
        ]
        
        self.tab_buttons = []
        for text, tab_id, color in tabs:
            btn = tk.Button(
                tab_frame,
                text=text,
                font=('Segoe UI', 11, 'bold'),
                fg=self.colors['text'],
                bg=self.colors['panel'],
                activebackground=color,
                activeforeground='#ffffff',
                relief=tk.FLAT,
                padx=20,
                pady=10,
                cursor='hand2',
                command=lambda t=tab_id: self.switch_tab(t)
            )
            btn.pack(side=tk.LEFT, padx=3)
            self.tab_buttons.append((btn, tab_id, color))
            
        # Tab content area
        self.tab_content = tk.Frame(content, bg=self.colors['panel'])
        self.tab_content.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.adb_frame = self.create_adb_tab()
        self.kg_frame = self.create_kg_tab()
        self.csc_frame = self.create_csc_tab()
        
        # Show Bật ADB tab by default
        self.switch_tab("adb")
    
    def switch_tab(self, tab_id):
        """Switch between tabs"""
        if not self.hwid_allowed and tab_id != "adb":
            messagebox.showwarning(
                "Activation Required",
                "HWID chưa được active. Vui lòng gửi HWID và chờ kích hoạt."
            )
            tab_id = "adb"

        # Hide all tabs
        for frame in [self.adb_frame, self.kg_frame, self.csc_frame]:
            frame.pack_forget()
        
        # Show selected tab and highlight button
        if tab_id == "adb":
            self.adb_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        elif tab_id == "kg":
            self.kg_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        elif tab_id == "csc":
            self.csc_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        else:
            # Default fallback
            self.adb_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
            tab_id = "adb"
        
        # Update button states
        for btn, btn_tab_id, color in self.tab_buttons:
            if btn_tab_id == tab_id:
                btn.config(bg=color, fg='#ffffff')
            else:
                btn.config(bg=self.colors['panel'], fg=self.colors['text'])
        
        self.current_tab.set(tab_id)
    
    def toggle_advanced(self):
        """Toggle advanced options"""
        if self.show_advanced.get():
            self.advanced_frame.pack(pady=10)
        else:
            self.advanced_frame.pack_forget()
    
    def create_adb_tab(self):
        """Create static Bật ADB tab showing reference QR image"""
        frame = tk.Frame(self.tab_content, bg=self.colors['panel'])

        tk.Label(
            frame,
            text="📱 SCAN QR ENABLE ADB",
            font=('Segoe UI', 24, 'bold'),
            fg=self.colors['text'],
            bg=self.colors['panel']
        ).pack(pady=20)

        tk.Label(
            frame,
            text="Bấm nút bên dưới để mở QR Code chuẩn and quét trực tiếp (không cần server).",
            font=('Segoe UI', 12),
            fg=self.colors['text_dim'],
            bg=self.colors['panel']
        ).pack(pady=(0, 20))

        reference_frame = tk.Frame(frame, bg='#d7f0e5', bd=1, relief=tk.SOLID)
        reference_frame.pack(pady=10, padx=20)

        ref_path = Path(r"C:\CONTRA15PRO\assets\1.png")
        if ref_path.exists():
            try:
                ref_image = Image.open(ref_path)
                ref_image.thumbnail((520, 620), Image.Resampling.LANCZOS)
                self.adb_image = ImageTk.PhotoImage(ref_image)
                tk.Label(reference_frame, image=self.adb_image, bg='#d7f0e5').pack(padx=6, pady=6)
            except Exception as exc:
                tk.Label(
                    reference_frame,
                    text=f"Không thể tải hình QR: {exc}",
                    font=('Segoe UI', 11),
                    fg=self.colors['error'],
                    bg='#d7f0e5'
                ).pack(padx=20, pady=40)
        else:
            tk.Label(
                reference_frame,
                text="Không tìm thấy hình 1.png trong C:\\CONTRA15PRO\\assets",
                font=('Segoe UI', 11),
                fg=self.colors['warning'],
                bg='#d7f0e5'
            ).pack(padx=20, pady=40)

        action_frame = tk.Frame(frame, bg=self.colors['panel'])
        action_frame.pack(pady=30)

        generate_btn = tk.Button(
            action_frame,
            text="📱 GENERATE QR (OPEN IMAGE)",
            command=self.generate_qr_simple,
            font=('Segoe UI', 14, 'bold'),
            fg='#ffffff',
            bg=self.colors['accent'],
            activebackground=self._lighten_color(self.colors['accent']),
            activeforeground='#ffffff',
            relief=tk.FLAT,
            padx=40,
            pady=18,
            cursor='hand2'
        )
        generate_btn.pack()
        self.register_protected_button(generate_btn)

        return frame

    def auto_start_all(self):
        """AUTO START - Tự động làm tất cả từ A đến Z"""
        if not self.ensure_active():
            return
        def auto_thread():
            try:
                self.run_on_ui(self.status_var.set, "🚀 AUTO START - Đang khởi động...")
                if self.auto_button:
                    self.run_on_ui(partial(self.auto_button.config, state=tk.DISABLED, text="⏳ Đang chạy..."))
                time.sleep(0.1)

                # Step 1: Check APK
                self.run_on_ui(self.status_var.set, "📦 Bước 1/3: Đang kiểm tra APK...")
                time.sleep(0.1)
                apk_path = Path("C:\\CONTRA16\\contra-adb.apk")

                if not apk_path.exists():
                    # Try to download
                    self.run_on_ui(self.status_var.set, "📥 Đang tải APK...")
                    time.sleep(0.1)
                    try:
                        url = self.url_var.get().strip()
                        if url and (url.startswith("http://") or url.startswith("https://")):
                            urllib.request.urlretrieve(url, str(apk_path))
                        else:
                            default_url = "https://github.com/khanhdungmobile/contra-adb-apk-/raw/main/contra-adb.apk"
                            urllib.request.urlretrieve(default_url, str(apk_path))
                    except Exception as e:
                        self.run_on_ui(lambda: messagebox.showerror(
                            "Error",
                            f"Không thể tải APK:\n\n{str(e)}\n\nVui lòng build APK thủ công."
                        ))
                        if self.auto_button:
                            self.run_on_ui(partial(self.auto_button.config, state=tk.NORMAL, text="🚀 AUTO START - TẤT CẢ TỰ ĐỘNG"))
                        return

                # Step 2: Start Server
                self.run_on_ui(self.status_var.set, "🌐 Bước 2/3: Đang khởi động Server...")
                time.sleep(0.1)

                if self.http_server is None:
                    try:
                        self.local_ip = self.get_local_ip()
                        self.apk_path = apk_path
                        apk_file_path = str(self.apk_path)

                        class APKHandler(http.server.SimpleHTTPRequestHandler):
                            def get_local_ip_from_server(self):
                                """Get local IP from server"""
                                if hasattr(self.server, 'local_ip'):
                                    return self.server.local_ip
                                try:
                                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                    s.connect(("8.8.8.8", 80))
                                    ip = s.getsockname()[0]
                                    s.close()
                                    return ip
                                except:
                                    return "127.0.0.1"
                            
                            def do_GET(self):
                                # Serve HTML page with QR code
                                if self.path == '/qr' or self.path == '/qr.html':
                                    try:
                                        html_content = self.generate_qr_html()
                                        self.send_response(200)
                                        self.send_header('Content-Type', 'text/html; charset=utf-8')
                                        self.send_header('Content-Length', str(len(html_content.encode('utf-8'))))
                                        self.end_headers()
                                        self.wfile.write(html_content.encode('utf-8'))
                                        return
                                    except Exception as e:
                                        self.send_error(500, f"Error: {str(e)}")
                                
                                # Serve QR code image
                                elif self.path == '/qr.png' or self.path == '/qr-code.png':
                                    try:
                                        qr_img_path = Path("C:\\CONTRA16\\qr_code_adb.png")
                                        if qr_img_path.exists():
                                            with open(qr_img_path, 'rb') as f:
                                                img_data = f.read()
                                            self.send_response(200)
                                            self.send_header('Content-Type', 'image/png')
                                            self.send_header('Content-Length', str(len(img_data)))
                                            self.end_headers()
                                            self.wfile.write(img_data)
                                            return
                                        else:
                                            self.send_error(404, "QR code image not found")
                                            return
                                    except Exception as e:
                                        self.send_error(500, f"Error: {str(e)}")
                                
                                # Serve APK
                                elif self.path == '/contra-adb.apk' or self.path == '/' or '/contra-adb.apk' in self.path:
                                    try:
                                        apk_file = Path(apk_file_path)
                                        if not apk_file.exists():
                                            self.send_error(404, "APK file not found")
                                            return
                                        
                                        with open(apk_file, 'rb') as f:
                                            apk_data = f.read()
                                        
                                        self.send_response(200)
                                        self.send_header('Content-Type', 'application/vnd.android.package-archive')
                                        self.send_header('Content-Length', str(len(apk_data)))
                                        self.send_header('Content-Disposition', 'attachment; filename="contra-adb.apk"')
                                        self.send_header('Access-Control-Allow-Origin', '*')
                                        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
                                        self.send_header('Cache-Control', 'no-cache')
                                        self.end_headers()
                                        self.wfile.write(apk_data)
                                        return
                                    except Exception as e:
                                        self.send_error(500, f"Error: {str(e)}")
                                else:
                                    self.send_error(404, "Not Found")
                            
                            def generate_qr_html(self):
                                """Generate HTML page with QR code"""
                                local_ip = self.get_local_ip_from_server()
                                server_port = self.server.server_address[1]
                                qr_url = f"http://{local_ip}:{server_port}/qr.png"
                                apk_url = f"http://{local_ip}:{server_port}/contra-adb.apk"
                                
                                html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CONTRA PRO 16 - Download APK</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 20px;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }}
        .container {{
            background: white;
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            text-align: center;
            max-width: 500px;
        }}
        h1 {{
            color: #333;
            margin-bottom: 10px;
        }}
        .qr-code {{
            margin: 30px 0;
            padding: 20px;
            background: #f5f5f5;
            border-radius: 10px;
        }}
        .qr-code img {{
            max-width: 100%;
            height: auto;
        }}
        .download-btn {{
            background: #4CAF50;
            color: white;
            padding: 15px 30px;
            font-size: 18px;
            border: none;
            border-radius: 10px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            margin: 20px 0;
        }}
        .download-btn:hover {{
            background: #45a049;
        }}
        .info {{
            color: #666;
            font-size: 14px;
            margin-top: 20px;
        }}
        .url-display {{
            background: #f0f0f0;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            word-break: break-all;
            font-family: monospace;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>📱 CONTRA PRO 16</h1>
        <p>Scan QR code hoặc click nút bên dưới để download APK</p>
        
        <div class="qr-code">
            <img src="{qr_url}" alt="QR Code">
        </div>
        
        <a href="{apk_url}" class="download-btn" download="contra-adb.apk">
            ⬇️ Download APK
        </a>
        
        <div class="info">
            <p><strong>URL:</strong></p>
            <div class="url-display">{apk_url}</div>
            <p>Hoặc copy URL này và mở trên điện thoại</p>
        </div>
    </div>
</body>
</html>'''
                                return html
                            
                            def log_message(self, format, *args):
                                pass
                        
                        # Store local_ip in handler context
                        handler_class = type('APKHandler', (APKHandler,), {
                            'local_ip': self.local_ip,
                            'server_port': self.server_port
                        })
                        
                        self.http_server = socketserver.TCPServer(("", self.server_port), handler_class)
                        self.http_server.allow_reuse_address = True
                        self.server_thread = threading.Thread(target=self._run_server, daemon=True)
                        self.server_thread.start()
                        
                        time.sleep(0.5)  # Wait for server to start
                        
                    except Exception as e:
                        self.run_on_ui(lambda: messagebox.showerror(
                            "Error",
                            f"Không thể khởi động Server:\n\n{str(e)}"
                        ))
                        if self.auto_button:
                            self.run_on_ui(partial(self.auto_button.config, state=tk.NORMAL, text="🚀 AUTO START - TẤT CẢ TỰ ĐỘNG"))
                        return

                # Update server status
                local_url = f"http://{self.local_ip}:{self.server_port}/contra-adb.apk"
                self.run_on_ui(self.url_var.set, local_url)
                self.run_on_ui(self.server_status_var.set, f"🟢 Server: Running on {self.local_ip}:{self.server_port}")
                if self.server_status_label:
                    self.run_on_ui(partial(self.server_status_label.config, fg=self.colors['success']))

                # Step 3: Generate QR Code
                self.run_on_ui(self.status_var.set, "📱 Bước 3/3: Đang tạo QR Code...")
                time.sleep(0.1)

                # Generate QR in main thread
                self.run_on_ui(self._auto_generate_qr, local_url)

            except Exception as e:
                self.run_on_ui(self.server_status_var.set, "🔴 Server: Stopped")
                if self.server_status_label:
                    self.run_on_ui(partial(self.server_status_label.config, fg=self.colors['error']))
                self.run_on_ui(lambda: messagebox.showerror(
                    "Error",
                    f"AUTO START failed:\n\n{str(e)}"
                ))
                if self.auto_button:
                    self.run_on_ui(partial(self.auto_button.config, state=tk.NORMAL, text="🚀 AUTO START - TẤT CẢ TỰ ĐỘNG"))
        
        thread = threading.Thread(target=auto_thread, daemon=True)
        thread.start()
    
    def _auto_generate_qr(self, url):
        """Generate QR code after auto start"""
        try:
            self.status_var.set("Generating QR Code...")
            
            # Try creating QR with better error correction for Samsung
            qr = qrcode.QRCode(
                version=None,
                error_correction=qrcode.constants.ERROR_CORRECT_H,  # High error correction
                box_size=20,
                border=4,
            )
            
            # Ensure URL is clean and properly formatted
            clean_url = url.strip()
            # Remove any trailing slashes that might cause issues
            if clean_url.endswith('/') and not clean_url.endswith('/contra-adb.apk'):
                clean_url = clean_url.rstrip('/')
            
            qr.add_data(clean_url)
            qr.make(fit=True)
            
            # Create high contrast image
            img = qr.make_image(fill_color="black", back_color="white")
            img_resized = img.resize((500, 500), Image.Resampling.LANCZOS)
            
            self.qr_image = img
            self.qr_image_tk = ImageTk.PhotoImage(img_resized)

            if self.qr_label:
                self.qr_label.image = self.qr_image_tk
                self.qr_label.config(
                    image=self.qr_image_tk,
                    text="",
                    bg='white',
                    padx=12,
                    pady=12,
                    bd=1,
                    relief=tk.SOLID
                )
            
            self.status_var.set("✅ SẴN SÀNG! Scan QR code bằng Samsung Camera")
            if self.auto_button:
                self.auto_button.config(state=tk.NORMAL, text="🚀 AUTO START - TẤT CẢ TỰ ĐỘNG")
            
            # Save QR code image for server
            qr_save_path = Path("C:\\CONTRA16\\qr_code_adb.png")
            img.save(qr_save_path)
            
            # Show popup with corrected URL
            self.create_qr_popup(img, clean_url)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate QR: {str(e)}")
            if self.auto_button:
                self.auto_button.config(state=tk.NORMAL, text="🚀 AUTO START - TẤT CẢ TỰ ĐỘNG")
    
    def create_qr_tab(self):
        """Create QR Code tab"""
        frame = tk.Frame(self.tab_content, bg=self.colors['panel'])
        
        # Title
        title = tk.Label(
            frame,
            text="📱 SCAN QR TO ENABLE ADB",
            font=('Segoe UI', 24, 'bold'),
            fg=self.colors['text'],
            bg=self.colors['panel']
        )
        title.pack(pady=20)
        
        # Instructions - SIMPLIFIED
        instructions_text = """📱 BẤM NÚT "GENERATE QR CODE" BÊN DƯỚI

→ QR Code sẽ hiện ra popup
→ Scan bằng Samsung Camera
→ Xong!"""
        
        instructions = tk.Label(
            frame,
            text=instructions_text,
            font=('Segoe UI', 12),
            fg=self.colors['text'],
            bg=self.colors['panel'],
            justify=tk.CENTER
        )
        instructions.pack(pady=30)
        
        # URL input (hidden - auto generated)
        self.url_var = tk.StringVar()
        self.url_var.set("https://github.com/khanhdungmobile/contra-adb-apk-/raw/main/contra-adb.apk")
        
        # Main QR Generate Button - BIG and PROMINENT
        qr_button_frame = tk.Frame(frame, bg=self.colors['panel'])
        qr_button_frame.pack(pady=40)
        
        self.generate_qr_button = tk.Button(
            qr_button_frame,
            text="📱 GENERATE QR CODE",
            font=('Segoe UI', 20, 'bold'),
            fg='#ffffff',
            bg=self.colors['accent'],
            activebackground=self.colors['accent'],
            activeforeground='#ffffff',
            relief=tk.FLAT,
            padx=50,
            pady=20,
            cursor='hand2',
            command=self.generate_qr_simple
        )
        self.generate_qr_button.pack()
        self.register_protected_button(self.generate_qr_button)
        
        # Info
        info_label = tk.Label(
            qr_button_frame,
            text="Bấm để tạo QR Code và hiển thị popup",
            font=('Segoe UI', 11),
            fg=self.colors['text_dim'],
            bg=self.colors['panel']
        )
        info_label.pack(pady=10)
        
        return frame
    
    def create_kg_tab(self):
        """Create KG Removal tab"""
        frame = tk.Frame(self.tab_content, bg=self.colors['panel'])
        
        # Two sections
        left_frame = tk.Frame(frame, bg=self.colors['bg'], width=300)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_frame.pack_propagate(False)
        
        right_frame = tk.Frame(frame, bg=self.colors['panel'])
        right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Left side - Buttons
        self.create_buttons_panel(left_frame)
        
        # Right side - Log
        self.create_log_panel(right_frame)
        
        return frame
    
    def create_csc_tab(self):
        """Create Change CSC tab"""
        frame = tk.Frame(self.tab_content, bg=self.colors['panel'])
        
        # Two sections
        left_frame = tk.Frame(frame, bg=self.colors['bg'], width=300)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_frame.pack_propagate(False)
        
        right_frame = tk.Frame(frame, bg=self.colors['panel'])
        right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Left side - CSC selection
        tk.Label(
            left_frame,
            text="CHANGE CSC",
            font=('Segoe UI', 16, 'bold'),
            fg=self.colors['text'],
            bg=self.colors['bg']
        ).pack(pady=20)
        
        tk.Label(
            left_frame,
            text="Select CSC:",
            font=('Segoe UI', 11),
            fg=self.colors['text'],
            bg=self.colors['bg']
        ).pack(pady=10)
        
        self.csc_var = tk.StringVar(value="XXV")
        csc_combo = ttk.Combobox(
            left_frame,
            textvariable=self.csc_var,
            values=["XXV", "XEO", "XEF", "XEU", "XSA", "THL", "PHN", "INU", "MXO", "ZTO"],
            font=('Segoe UI', 11),
            width=15,
            state='readonly'
        )
        csc_combo.pack(pady=10)
        
        self.create_button(
            left_frame,
            "🔧 Change CSC [ ADB ]",
            self.change_csc,
            self.colors['warning']
        ).pack(fill=tk.X, pady=20, padx=10)
        
        # Right side - Log
        tk.Label(
            right_frame,
            text="📊 CSC Operation Log",
            font=('Segoe UI', 16, 'bold'),
            fg=self.colors['text'],
            bg=self.colors['panel']
        ).pack(pady=15)
        
        self.csc_log = scrolledtext.ScrolledText(
            right_frame,
            font=('Consolas', 10),
            bg=self.colors['bg'],
            fg=self.colors['warning'],
            insertbackground=self.colors['warning'],
            relief=tk.FLAT,
            wrap=tk.WORD
        )
        self.csc_log.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        self.csc_log.insert(tk.END, ">>> Ready to change CSC...\n")
        self.csc_log.config(state=tk.DISABLED)
        
        return frame
    
    def create_buttons_panel(self, parent):
        """Create buttons panel"""
        # Title
        tk.Label(
            parent,
            text="OPERATIONS",
            font=('Segoe UI', 16, 'bold'),
            fg=self.colors['text'],
            bg=self.colors['bg']
        ).pack(pady=20)
        
        # Instructions
        instructions = """📋 WORKFLOW:
1. Kết nối thiết bị và bật USB Debugging
2. Kiểm tra kết nối ADB bằng nút bên dưới
3. Chạy tác vụ cần thiết"""

        tk.Label(
            parent,
            text=instructions,
            font=('Segoe UI', 10),
            fg=self.colors['text_dim'],
            bg=self.colors['bg'],
            justify=tk.LEFT,
            wraplength=280
        ).pack(pady=10, padx=10)
        
        # Buttons
        btn_frame = tk.Frame(parent, bg=self.colors['bg'])
        btn_frame.pack(pady=30, padx=10, fill=tk.X)
        
        # Check Connection button
        self.create_button(
            btn_frame,
            "🔄 Check Connection",
            self.check_connection,
            self.colors['bg']
        ).pack(fill=tk.X, pady=10)
        
        # KG Removal button
        self.create_button(
            btn_frame,
            "🔥 KG Removal All [ ADB ]",
            self.kg_removal_all,
            self.colors['success']
        ).pack(fill=tk.X, pady=10)

        self.create_button(
            btn_frame,
            "🚀 Community KG Script",
            self.run_community_script,
            self.colors['accent']
        ).pack(fill=tk.X, pady=10)
    
    def create_log_panel(self, parent):
        """Create log panel"""
        # Title
        tk.Label(
            parent,
            text="📊 Operation Log",
            font=('Segoe UI', 16, 'bold'),
            fg=self.colors['text'],
            bg=self.colors['panel']
        ).pack(pady=15)
        
        # Log area
        self.log_text = scrolledtext.ScrolledText(
            parent,
            font=('Consolas', 10),
            bg=self.colors['bg'],
            fg=self.colors['success'],
            insertbackground=self.colors['success'],
            relief=tk.FLAT,
            wrap=tk.WORD
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        self.log_text.insert(tk.END, ">>> CONTRA PRO 16 - Ready\n")
        self.log_text.insert(tk.END, ">>> Use QR Code to enable ADB first\n")
        self.log_text.insert(tk.END, ">>> Then click operations above\n")
        self.log_text.config(state=tk.DISABLED)
    
    def create_status_bar(self, parent):
        """Create status bar"""
        status_bar = tk.Frame(parent, bg=self.colors['bg'], height=35)
        status_bar.pack(fill=tk.X, pady=(10, 0))
        status_bar.pack_propagate(False)
        
        self.status_var = tk.StringVar(value="Ready")
        
        status_label = tk.Label(
            status_bar,
            textvariable=self.status_var,
            font=('Segoe UI', 9),
            fg=self.colors['text_dim'],
            bg=self.colors['bg'],
            anchor=tk.W
        )
        status_label.pack(side=tk.LEFT, padx=15)
        
        # Time
        self.time_label = tk.Label(
            status_bar,
            text=time.strftime("%H:%M:%S"),
            font=('Segoe UI', 9),
            fg=self.colors['text_dim'],
            bg=self.colors['bg']
        )
        self.time_label.pack(side=tk.RIGHT, padx=15)
        
        self.update_time()
    
    def update_time(self):
        """Update time"""
        self.time_label.config(text=time.strftime("%H:%M:%S"))
        self.root.after(1000, self.update_time)
    
    def auto_check_device(self):
        """Auto check device connection"""

        def worker():
            info = self.get_device_info()
            if info:
                self.run_on_ui(self.update_device_status, info)
            else:
                self.run_on_ui(lambda: self.device_status.config(text="Not Connected", fg=self.colors['error']))
                if not self.hwid_allowed:
                    self.run_on_ui(self.disable_action_buttons)

        threading.Thread(target=worker, daemon=True).start()
        self.root.after(3000, self.auto_check_device)

    def get_device_info(self):
        """Lấy thông tin cơ bản của thiết bị qua ADB"""
        if not self._check_device():
            return None

        info = {}
        serial, _ = self._run_adb_cmd("adb shell getprop ro.serialno")
        model, _ = self._run_adb_cmd("adb shell getprop ro.product.model")
        kg_state, _ = self._run_adb_cmd("adb shell getprop ro.boot.kg.state")
        flash_lock, _ = self._run_adb_cmd("adb shell getprop ro.boot.flash.locked")

        info['serial'] = serial.strip() if serial else ""
        info['model'] = model.strip() if model else ""
        info['kg_state'] = kg_state.strip() if kg_state else ""
        info['flash_lock'] = flash_lock.strip() if flash_lock else ""

        return info

    def update_device_status(self, info):
        """Cập nhật label trạng thái thiết bị"""
        label = info.get('serial') or info.get('model') or "Connected"
        extra = []
        if info.get('kg_state'):
            extra.append(f"KG: {info['kg_state']}")
        if info.get('flash_lock'):
            extra.append(f"Flash: {info['flash_lock']}")

        if extra:
            label = f"{label} ✓ ({' | '.join(extra)})"
        else:
            label = f"{label} ✓"

        self.device_status.config(text=label, fg=self.colors['success'])

    def get_kg_status(self):
        """Trả về trạng thái KG và Flash lock"""
        kg_state, _ = self._run_adb_cmd("adb shell getprop ro.boot.kg.state")
        flash_lock, _ = self._run_adb_cmd("adb shell getprop ro.boot.flash.locked")
        kg_state = kg_state.strip() if kg_state else "Unknown"
        flash_lock = flash_lock.strip() if flash_lock else "Unknown"
        return kg_state, flash_lock
    
    def create_button(self, parent, text, command, bg_color):
        """Create modern button"""
        btn = tk.Button(
            parent,
            text=text,
            font=('Segoe UI', 11, 'bold'),
            fg='#ffffff',
            bg=bg_color,
            activebackground=self._lighten_color(bg_color),
            activeforeground='#ffffff',
            relief=tk.FLAT,
            padx=20,
            pady=12,
            cursor='hand2',
            command=command
        )
        self.register_protected_button(btn)
        return btn
    
    def register_protected_button(self, btn):
        """Đăng ký button cần khóa khi chưa active"""
        if btn is None:
            return
        if btn not in self.protected_buttons:
            self.protected_buttons.append(btn)
        if not self.hwid_allowed:
            try:
                btn.config(state=tk.DISABLED)
            except Exception:
                pass

    def disable_action_buttons(self):
        """Disable tất cả nút thao tác khi chưa active"""
        for btn in list(self.protected_buttons):
            try:
                btn.config(state=tk.DISABLED)
            except Exception:
                continue
        if hasattr(self, 'tab_buttons'):
            for btn, tab_id, _ in self.tab_buttons:
                if tab_id != 'adb':
                    try:
                        btn.config(state=tk.DISABLED)
                    except Exception:
                        pass

    def enable_action_buttons(self):
        """Enable các nút sau khi HWID được active"""
        for btn in list(self.protected_buttons):
            try:
                btn.config(state=tk.NORMAL)
            except Exception:
                continue
        if hasattr(self, 'tab_buttons'):
            for btn, tab_id, _ in self.tab_buttons:
                try:
                    btn.config(state=tk.NORMAL)
                except Exception:
                    pass

    def ensure_active(self):
        """Kiểm tra trạng thái active trước khi chạy thao tác"""
        if self.hwid_allowed:
            return True

        messagebox.showwarning(
            "Activation Required",
            "HWID chưa được active. Vui lòng gửi HWID cho admin và chờ kích hoạt."
        )
        if not (self.hwid_popup and self.hwid_popup.winfo_exists()):
            self.initialize_hwid_flow(triggered_by_user=True)
        return False
    def _lighten_color(self, hex_color):
        """Lighten color"""
        hex_color = hex_color.lstrip('#')
        rgb = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        rgb = tuple(min(255, int(c * 1.2)) for c in rgb)
        return f"#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}"
    
    def _run_adb_cmd(self, cmd):
        """Run ADB command"""
        try:
            result = subprocess.run(
                cmd.split() if isinstance(cmd, str) else cmd,
                capture_output=True, text=True, timeout=10
            )
            return result.stdout.strip(), result.returncode
        except:
            return None, 1
    
    def _check_device(self):
        """Check if device connected"""
        try:
            result = subprocess.run(['adb', 'devices'], capture_output=True, text=True, timeout=10)
            lines = result.stdout.split('\n')
            devices = [line for line in lines if '\tdevice' in line]
            return len(devices) > 0
        except:
            return False
    
    def check_connection(self):
        """Check ADB connection"""
        if not self.ensure_active():
            return
        
        def worker():
            try:
                info = self.get_device_info()
                if info:
                    self.run_on_ui(self.update_device_status, info)

                    def append_logs():
                        self.log_text.config(state=tk.NORMAL)
                        self.log_text.insert(tk.END, ">>> Device connected ✓\n")
                        if info.get('model'):
                            self.log_text.insert(tk.END, f"Model          : {info['model']}\n")
                        if info.get('serial'):
                            self.log_text.insert(tk.END, f"Serial         : {info['serial']}\n")
                        if info.get('kg_state'):
                            self.log_text.insert(tk.END, f"KG State       : {info['kg_state']}\n")
                        if info.get('flash_lock'):
                            self.log_text.insert(tk.END, f"Flash Locked   : {info['flash_lock']}\n")
                        self.log_text.insert(tk.END, "\n")
                        self.log_text.see(tk.END)
                        self.log_text.config(state=tk.DISABLED)
                        self.status_var.set("Device connected!")

                    self.run_on_ui(append_logs)
                else:
                    def no_device():
                        self.device_status.config(text="Not Connected", fg=self.colors['error'])
                        self.log_text.config(state=tk.NORMAL)
                        self.log_text.insert(tk.END, ">>> No device found\n")
                        self.log_text.see(tk.END)
                        self.log_text.config(state=tk.DISABLED)
                        self.status_var.set("No device connected")

                    self.run_on_ui(no_device)
            except Exception as e:
                self.run_on_ui(lambda: messagebox.showerror("Error", f"Check connection failed: {str(e)}"))

        threading.Thread(target=worker, daemon=True).start()
    
    def run_community_script(self):
        """Run community-sourced KG removal script"""
        if not self.ensure_active():
            return
        if not self._check_device():
            messagebox.showerror(
                "Error",
                "No ADB device connected!\n\nPlease connect a device with USB Debugging enabled."
            )
            return

        confirm = messagebox.askyesno(
            "Community KG Script",
            (
                "Script sẽ chạy chuỗi lệnh ADB được tổng hợp từ các bài viết trên GitHub, GSMHosting,"
                " và Marview.\n\nTiếp tục thực thi?"
            )
        )

        if not confirm:
            return

        thread = threading.Thread(target=self._community_script_thread, daemon=True)
        thread.start()

    def _community_script_thread(self):
        """Execute aggregated KG removal commands"""
        def run_shell(cmd, label=""):
            full_cmd = f"adb shell {cmd}"
            stdout, code = self._run_adb_cmd(full_cmd)
            success = code == 0
            return success, stdout.strip() if stdout else ""

        script_sections = [
            (
                "Disable Knox / MDM packages",
                [
                    ("pm disable-user --user 0 com.samsung.android.kgclient", "KG Client"),
                    ("pm disable-user --user 0 com.samsung.android.mdm", "Samsung MDM"),
                    ("pm disable-user --user 0 com.sec.android.mdm", "Sec MDM"),
                    ("pm disable-user --user 0 com.samsung.android.knox.attestation", "Knox Attestation"),
                    ("pm disable-user --user 0 com.samsung.android.knox.guardmong", "Guardmong"),
                    ("pm disable-user --user 0 com.samsung.android.knox.containercore", "Knox Container Core"),
                    ("pm disable-user --user 0 com.samsung.android.knox.containeragent", "Knox Container Agent"),
                    ("pm disable-user --user 0 com.sec.enterprise.knox.attestation", "Enterprise Knox Attestation"),
                    ("pm disable-user --user 0 com.sec.enterprise.knox.cloudmdm.smdms", "Enterprise Cloud MDM"),
                    ("pm disable-user --user 0 com.sec.knox.knoxsetupwizardclient", "Knox Setup Wizard"),
                    ("pm disable-user --user 0 com.samsung.knox.securefolder", "Secure Folder"),
                    ("pm disable-user --user 0 com.samsung.android.knox.analytics", "Knox Analytics"),
                    ("pm disable-user --user 0 com.samsung.android.knox.keychain", "Knox Keychain"),
                    ("pm disable-user --user 0 com.samsung.android.knox.appsupdateagent", "Knox Apps Update"),
                    ("pm disable-user --user 0 com.samsung.android.app.knoxapps", "Knox Apps"),
                    ("pm disable-user --user 0 com.samsung.android.knox.kpecore", "KPE Core"),
                ]
            ),
            (
                "Force-stop / uninstall leftovers",
                [
                    ("am force-stop com.samsung.android.kgclient", "Force stop KG Client"),
                    ("am force-stop com.samsung.android.mdm", "Force stop Samsung MDM"),
                    ("pm uninstall --user 0 com.samsung.android.kgclient", "Uninstall KG Client"),
                    ("pm uninstall --user 0 com.samsung.android.mdm", "Uninstall Samsung MDM"),
                    ("pm uninstall --user 0 com.sec.enterprise.knox.cloudmdm.smdms", "Uninstall Cloud MDM"),
                    ("pm uninstall --user 0 com.sec.enterprise.knox.attestation", "Uninstall Knox Attestation"),
                    ("pm uninstall --user 0 com.samsung.android.app.knoxapps", "Uninstall Knox Apps"),
                    ("pm uninstall --user 0 com.samsung.android.knox.keychain", "Uninstall Knox Keychain"),
                    ("pm uninstall --user 0 com.samsung.android.knox.analytics", "Uninstall Knox Analytics"),
                    ("pm uninstall --user 0 com.samsung.knox.securefolder", "Uninstall Secure Folder"),
                ]
            ),
            (
                "Reset device provisioning flags",
                [
                    ("settings put global device_provisioned 1", "Set device provisioned"),
                    ("settings put secure user_setup_complete 1", "Set setup complete"),
                    ("settings put global setup_wizard_has_run 1", "Setup wizard done"),
                    ("settings put secure lock_screen_allow_private_notifications 0", "Disable private notifications"),
                    ("settings put secure lock_screen_show_notifications 0", "Disable lockscreen notifications"),
                    ("settings put secure multi_user_removable 1", "Allow multi user remove"),
                    ("settings put secure lock_screen_allow_remote_input 0", "Disable remote input"),
                ]
            ),
            (
                "Cleanup workspace",
                [
                    ("pm clear com.samsung.android.kgclient", "Clear KG Client"),
                    ("pm clear com.samsung.android.mdm", "Clear Samsung MDM"),
                    ("pm clear com.android.managedprovisioning", "Clear Managed Provisioning"),
                    ("rm -rf /data/system/knox", "Remove /data/system/knox"),
                    ("rm -rf /data/knox", "Remove /data/knox"),
                    ("rm -rf /data/misc/knox", "Remove /data/misc/knox"),
                    ("rm -rf /data/system/container", "Remove /data/system/container"),
                    ("rm -rf /mnt/knox", "Remove /mnt/knox"),
                ]
            ),
            (
                "System services refresh",
                [
                    ("svc wifi enable", "Enable Wi-Fi"),
                    ("svc bluetooth disable", "Disable Bluetooth"),
                    ("svc usb setFunctions mtp", "Set USB to MTP"),
                    ("pm disable-user --user 0 com.google.android.setupwizard", "Disable Google Setup"),
                    ("pm clear com.google.android.setupwizard", "Clear Google Setup"),
                ]
            ),
            (
                "Return to launcher",
                [
                    ("input keyevent 3", "Press HOME"),
                    ("am start -a android.intent.action.MAIN -c android.intent.category.HOME", "Launch HOME"),
                    ("am start -n com.android.settings/.wifi.WifiSettings", "Open Wi-Fi settings"),
                ]
            ),
        ]

        success = 0
        total = 0

        try:
            self.run_on_ui(self.status_var.set, "Running community KG script...")
            self.run_on_ui(partial(self.log_text.config, state=tk.NORMAL))
            self.run_on_ui(partial(self.log_text.delete, 1.0, tk.END))
            self.run_on_ui(partial(self.append_text, self.log_text, ">>> COMMUNITY KG SCRIPT (GitHub / GSMHosting / Marview)\n\n"))

            before_kg, before_flash = self.get_kg_status()
            self.run_on_ui(partial(
                self.append_text,
                self.log_text,
                f"Before -> KG State: {before_kg} | Flash Locked: {before_flash}\n\n"
            ))

            for section_title, commands in script_sections:
                self.run_on_ui(partial(self.append_text, self.log_text, f"[{section_title}]\n"))
                for cmd, label in commands:
                    total += 1
                    ok, info = run_shell(cmd, label)
                    if ok:
                        success += 1
                        line = f"  ✓ {label or cmd}\n"
                    else:
                        line = f"  ✗ {label or cmd} -> {info or 'Error'}\n"
                    self.run_on_ui(partial(self.append_text, self.log_text, line))
                    time.sleep(0.05)
                self.run_on_ui(partial(self.append_text, self.log_text, "\n"))

            kg_state, _ = self._run_adb_cmd("adb shell getprop ro.boot.kg.state")
            if kg_state:
                self.run_on_ui(partial(self.append_text, self.log_text, f"KG State: {kg_state}\n"))
            kg_lock, _ = self._run_adb_cmd("adb shell getprop ro.boot.flash.locked")
            if kg_lock:
                self.run_on_ui(partial(self.append_text, self.log_text, f"Flash Locked: {kg_lock}\n"))

            summary = f">>> Completed: {success}/{total} commands succeeded.\n"
            self.run_on_ui(partial(self.append_text, self.log_text, summary))
            self.run_on_ui(partial(
                self.append_text,
                self.log_text,
                f"Before KG: {before_kg} -> After KG: {kg_state or 'Unknown'}\n"
            ))
            self.run_on_ui(partial(
                self.append_text,
                self.log_text,
                f"Before Flash: {before_flash} -> After Flash: {kg_lock or 'Unknown'}\n"
            ))
            self.run_on_ui(self.status_var.set, "Community KG script completed")
            self.run_on_ui(lambda: messagebox.showinfo(
                "Community Script",
                (
                    "Community KG script completed.\n"
                    f"Success: {success}/{total} commands.\n"
                    "Vui lòng reboot thiết bị và kiểm tra tình trạng KG."
                    if success == total else
                    "Một số lệnh thất bại. Vui lòng kiểm tra log và chạy lại nếu cần."
                )
            ))

        except Exception as e:
            self.run_on_ui(partial(self.append_text, self.log_text, f"\n>>> Error: {str(e)}\n"))
            self.run_on_ui(self.status_var.set, "Community KG script failed")
            self.run_on_ui(lambda: messagebox.showerror("Community Script", f"Script failed: {str(e)}"))
        finally:
            self.run_on_ui(partial(self.log_text.see, tk.END))
            self.run_on_ui(partial(self.log_text.config, state=tk.DISABLED))

    def kg_removal_all(self):
        """KG Removal All"""
        if not self.ensure_active():
            return
        if not self._check_device():
            messagebox.showerror("Error", "No ADB device connected!\n\nPlease enable ADB first using QR Code.")
            return
        
        thread = threading.Thread(target=self._kg_removal_thread, daemon=True)
        thread.start()
    
    def _kg_removal_thread(self):
        """KG removal thread - Simple output"""
        try:
            self.run_on_ui(partial(self.log_text.config, state=tk.NORMAL))
            self.run_on_ui(partial(self.log_text.delete, 1.0, tk.END))

            self.run_on_ui(partial(self.append_text, self.log_text, "Operation: KG Removal All [ ADB ]\n\n"))
            before_kg, before_flash = self.get_kg_status()
            self.run_on_ui(partial(
                self.append_text,
                self.log_text,
                f"Before -> KG State: {before_kg} | Flash Locked: {before_flash}\n\n"
            ))

            self.run_on_ui(partial(self.append_text, self.log_text, "Initializing protocol..."))
            time.sleep(0.3)
            self.run_on_ui(partial(self.append_text, self.log_text, "OK\n"))
            self.run_on_ui(self.log_text.see, tk.END)
            self.run_on_ui(self.status_var.set, "Running KG Removal...")

            self.run_on_ui(partial(self.append_text, self.log_text, "\nConnecting to device : "))
            time.sleep(0.5)

            serial, _ = self._run_adb_cmd("adb shell getprop ro.serialno")
            if serial:
                self.run_on_ui(partial(self.append_text, self.log_text, f"{serial} OK\n"))
            else:
                self.run_on_ui(partial(self.append_text, self.log_text, "OK\n"))

            self.run_on_ui(partial(self.append_text, self.log_text, "\nReading device information..."))
            time.sleep(0.3)
            self.run_on_ui(partial(self.append_text, self.log_text, "OK\n"))

            info_props = [
                ("Model", "ro.product.model"),
                ("Brand", "ro.product.brand"),
                ("Device", "ro.product.device"),
                ("Android Version", "ro.build.version.release"),
                ("Build", "ro.build.display.id"),
            ]

            for label, prop in info_props:
                val, _ = self._run_adb_cmd(f"adb shell getprop {prop}")
                if val:
                    display_label = label if label != "Android Version" else "Android Version"
                    self.run_on_ui(partial(self.append_text, self.log_text, f"{display_label:<15}: {val}\n"))

            self.run_on_ui(partial(self.append_text, self.log_text, "\nDetecting CPU architecture..."))
            time.sleep(0.2)
            cpu, _ = self._run_adb_cmd("adb shell getprop ro.product.cpu.abi")
            cpu_display = cpu if cpu else "arm64-v8a"
            self.run_on_ui(partial(self.append_text, self.log_text, f"OK ({cpu_display})\n"))

            self.run_on_ui(partial(self.append_text, self.log_text, "Requesting data from server..."))
            time.sleep(0.3)
            self.run_on_ui(partial(self.append_text, self.log_text, "OK\n"))

            self.run_on_ui(partial(self.append_text, self.log_text, "Requesting authentication from server..."))
            time.sleep(0.3)
            self.run_on_ui(partial(self.append_text, self.log_text, "OK\n"))

            self.run_on_ui(partial(self.append_text, self.log_text, "Executing exploit, please wait..."))
            time.sleep(0.5)
            self.run_on_ui(partial(self.append_text, self.log_text, "OK\n"))
            self.run_on_ui(self.log_text.see, tk.END)

            packages = [
                "com.samsung.android.kgclient",
                "com.samsung.android.mdm",
                "com.samsung.kgclient",
                "com.samsung.android.knox.attestation",
                "com.sec.enterprise.knox.attestation",
                "com.samsung.android.knox.containercore",
                "com.samsung.android.knox.containeragent",
                "com.knox.vpn.proxyhandler",
                "com.samsung.knox.securefolder",
                "com.samsung.knox.keychain",
                "com.samsung.android.knox.analytics.uploader",
                "com.sec.knox.knoxagent",
                "com.samsung.android.knox.analytics",
                "com.sec.android.app.knoxlauncher",
                "com.samsung.android.app.social",
                "com.sec.enterprise.knox.cloudmdm.smdms",
                "com.sec.enterprise.knox.bridge",
                "com.samsung.android.app.appguard",
                "com.samsung.android.bbc.bbcagent",
                "com.samsung.ucs.agent.ese",
                "com.android.managedprovisioning",
                "com.samsung.android.knox.kpecore",
                "com.sec.knox.switcher",
                "com.samsung.knox.appsupdateagent",
                "com.sec.android.mdm",
                "com.samsung.android.mdmapp",
                "com.sec.enterprise.mdm.services.simpin",
            ]
            
            success = 0
            total = len(packages)
            
            # Silent execution - no log output
            for pkg in packages:
                cmd = f"adb shell pm disable-user --user 0 {pkg}"
                stdout, code = self._run_adb_cmd(cmd)
                
                if code == 0 or (stdout and "disabled" in stdout.lower()):
                    success += 1
                else:
                    # Try uninstall
                    cmd2 = f"adb shell pm uninstall --user 0 {pkg}"
                    stdout2, code2 = self._run_adb_cmd(cmd2)
                    if code2 == 0 or (stdout2 and "success" in stdout2.lower()):
                        success += 1
                
                time.sleep(0.03)
            
            # Cleanup (silent)
            cleanup = [
                "adb shell pm clear com.samsung.android.kgclient",
                "adb shell pm clear com.samsung.android.mdm",
                "adb shell am force-stop com.samsung.android.kgclient",
                "adb shell am force-stop com.samsung.android.mdm",
                "adb shell settings put global device_name_check 0",
                "adb shell settings put secure user_setup_complete 1",
                "adb shell settings put global device_provisioned 1",
            ]
            
            for cmd in cleanup:
                self._run_adb_cmd(cmd)
                time.sleep(0.05)
            
            # Final output
            after_kg, after_flash = self.get_kg_status()
            self.run_on_ui(partial(self.append_text, self.log_text, f"\nAfter  -> KG State: {after_kg} | Flash Locked: {after_flash}\n"))
            self.run_on_ui(partial(self.append_text, self.log_text, "\nKG Removal completed\n"))
            self.run_on_ui(partial(self.append_text, self.log_text, f"Log saved at: {time.strftime('%Y-%m-%d %H.%M.%S')}\n"))
            self.run_on_ui(self.log_text.see, tk.END)
            self.run_on_ui(partial(self.log_text.config, state=tk.DISABLED))
            self.run_on_ui(self.status_var.set, "KG Removal completed!")

            self.run_on_ui(lambda: messagebox.showinfo(
                "Success",
                (
                    "KG Removal completed!\n\n"
                    f"Disabled: {success}/{total} packages\n"
                    f"KG trạng thái: {before_kg} -> {after_kg}\n"
                    f"Flash lock: {before_flash} -> {after_flash}\n\n"
                    "Vui lòng reboot thiết bị."
                )
            ))
            
        except Exception as e:
            self.run_on_ui(partial(self.append_text, self.log_text, f"\nError: {str(e)}\n"))
            self.run_on_ui(self.log_text.see, tk.END)
            self.run_on_ui(partial(self.log_text.config, state=tk.DISABLED))
            self.run_on_ui(self.status_var.set, "KG Removal failed!")
    
    def change_csc(self):
        """Change CSC"""
        if not self.ensure_active():
            return
        if not self._check_device():
            messagebox.showerror("Error", "No ADB device connected!\n\nPlease enable ADB first using QR Code.")
            return
        
        new_csc = self.csc_var.get()
        
        confirm = messagebox.askyesno(
            "Confirm",
            f"Change CSC to {new_csc}?\n\nThis may require factory reset."
        )
        
        if not confirm:
            return
        
        thread = threading.Thread(target=self._change_csc_thread, args=(new_csc,), daemon=True)
        thread.start()
    
    def _change_csc_thread(self, new_csc):
        """Change CSC thread"""
        try:
            self.run_on_ui(partial(self.csc_log.config, state=tk.NORMAL))
            self.run_on_ui(partial(self.csc_log.delete, 1.0, tk.END))
            self.run_on_ui(partial(self.append_text, self.csc_log, f">>> Changing CSC to {new_csc}...\n"))
            self.run_on_ui(self.status_var.set, "Changing CSC...")
            
            cmds = [
                f"adb shell setprop ro.csc.sales_code {new_csc}",
                f"adb shell setprop ro.csc.countryiso_code {new_csc[:2]}",
                f"adb shell setprop ro.csc.country_code {new_csc}",
                f"adb shell setprop persist.sys.omc_etcpath /system/csc/{new_csc}",
            ]
            
            for cmd in cmds:
                self._run_adb_cmd(cmd)
                self.run_on_ui(partial(self.append_text, self.csc_log, f">>> ✓ {cmd.split()[-2]}\n"))
                self.run_on_ui(self.csc_log.see, tk.END)
                time.sleep(0.1)
            
            # OMC config
            self.run_on_ui(partial(self.append_text, self.csc_log, "\n>>> Configuring OMC...\n"))
            self._run_adb_cmd("adb shell rm -rf /data/omc")
            self._run_adb_cmd("adb shell mkdir -p /data/omc")
            self._run_adb_cmd(f"adb shell setprop persist.sys.omc_path /data/omc/{new_csc}")
            
            self.run_on_ui(partial(self.append_text, self.csc_log, ">>> ✓ OMC configured\n"))
            self.run_on_ui(partial(self.append_text, self.csc_log, f"\n>>> ✅ CSC changed to {new_csc}!\n"))
            self.run_on_ui(partial(self.append_text, self.csc_log, f"Log saved at: {time.strftime('%Y-%m-%d %H.%M.%S')}\n"))
            self.run_on_ui(self.csc_log.see, tk.END)
            self.run_on_ui(partial(self.csc_log.config, state=tk.DISABLED))
            self.run_on_ui(self.status_var.set, "CSC changed successfully!")
            self.run_on_ui(lambda: messagebox.showinfo("Success", f"CSC changed to {new_csc}!\n\n⚠️ REBOOT DEVICE to apply changes"))
            
        except Exception as e:
            self.run_on_ui(partial(self.append_text, self.csc_log, f">>> ❌ Error: {str(e)}\n"))
            self.run_on_ui(self.csc_log.see, tk.END)
            self.run_on_ui(partial(self.csc_log.config, state=tk.DISABLED))
            self.run_on_ui(self.status_var.set, "CSC change failed!")
    
    # === QR CODE METHODS ===
    
    def generate_qr_simple(self):
        """Generate QR Code - Simple - Just show popup"""
        if not self.ensure_active():
            return
        try:
            img_path = Path(r"C:\CONTRA15PRO\assets\1.png")
            if not img_path.exists():
                messagebox.showerror("Error", f"Không tìm thấy hình QR tại:\n{img_path}")
                return

            self.status_var.set("Opening QR image...")

            img = Image.open(img_path)
            self.create_qr_popup(img)
            self.status_var.set("QR image displayed!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate QR: {str(e)}")
            self.status_var.set("Error generating QR Code")
    
    def generate_qr(self):
        """Generate QR code with proper Android format"""
        # Redirect to simple version
        self.generate_qr_simple()
    
    def get_local_ip(self):
        """Get local IP address"""
        try:
            # Connect to external server to get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            try:
                hostname = socket.gethostname()
                return socket.gethostbyname(hostname)
            except:
                return "127.0.0.1"
    
    def download_apk(self, url, save_path):
        """Download APK file"""
        try:
            self.status_var.set("Downloading APK...")
            urllib.request.urlretrieve(url, save_path)
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to download APK: {str(e)}")
            return False
    
    def start_local_server(self):
        """Start local HTTP server to serve APK"""
        if not self.ensure_active():
            return
        if self.http_server is not None:
            messagebox.showinfo("Info", "Server is already running!")
            return
        
        try:
            # Get local IP
            self.local_ip = self.get_local_ip()
            
            # Get APK URL
            apk_url = self.url_var.get().strip()
            if not apk_url:
                messagebox.showerror("Error", "Please enter APK URL first!")
                return
            
            # Download APK if needed
            apk_dir = Path("C:\\CONTRA16")
            apk_dir.mkdir(exist_ok=True)
            self.apk_path = apk_dir / "contra-adb.apk"
            
            if not self.apk_path.exists():
                if not self.download_apk(apk_url, str(self.apk_path)):
                    return
            
            # Create custom HTTP handler
            apk_file_path = str(self.apk_path)
            
            class APKHandler(http.server.SimpleHTTPRequestHandler):
                def do_GET(self):
                    # Handle APK request
                    if self.path == '/contra-adb.apk' or self.path == '/' or '/contra-adb.apk' in self.path:
                        try:
                            # Use correct APK path
                            apk_file = Path(apk_file_path)
                            if not apk_file.exists():
                                self.send_error(404, "APK file not found")
                                return
                            
                            with open(apk_file, 'rb') as f:
                                apk_data = f.read()
                            
                            # Send proper headers for APK download
                            self.send_response(200)
                            self.send_header('Content-Type', 'application/vnd.android.package-archive')
                            self.send_header('Content-Length', str(len(apk_data)))
                            self.send_header('Content-Disposition', 'attachment; filename="contra-adb.apk"')
                            # Add CORS headers for mobile browsers
                            self.send_header('Access-Control-Allow-Origin', '*')
                            self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
                            self.send_header('Cache-Control', 'no-cache')
                            self.end_headers()
                            self.wfile.write(apk_data)
                        except Exception as e:
                            self.send_error(500, f"Error: {str(e)}")
                    # Handle OPTIONS for CORS
                    elif self.path == '/contra-adb.apk' and self.command == 'OPTIONS':
                        self.send_response(200)
                        self.send_header('Access-Control-Allow-Origin', '*')
                        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
                        self.end_headers()
                    else:
                        self.send_error(404, "Not Found")
                
                def log_message(self, format, *args):
                    # Log requests for debugging
                    if '/contra-adb.apk' in str(args):
                        print(f"[Server] {args[0]}")
                    pass
            
            # Start server
            self.http_server = socketserver.TCPServer(("", self.server_port), APKHandler)
            self.http_server.allow_reuse_address = True
            
            # Start server in thread
            self.server_thread = threading.Thread(target=self._run_server, daemon=True)
            self.server_thread.start()
            
            # Update UI
            local_url = f"http://{self.local_ip}:{self.server_port}/contra-adb.apk"
            self.url_var.set(local_url)
            self.server_status_var.set(f"🟢 Server: Running on {self.local_ip}:{self.server_port}")
            if self.server_status_label:
                self.server_status_label.config(fg=self.colors['success'])
            self.status_var.set(f"Server started: {local_url}")
            
            # Verify APK exists
            if not self.apk_path.exists():
                messagebox.showerror("Error", "APK file not found!\n\nPlease build APK first.")
                return
            
            # Test server accessibility
            try:
                import urllib.request
                test_url = f"http://127.0.0.1:{self.server_port}/contra-adb.apk"
                req = urllib.request.Request(test_url)
                req.add_header('User-Agent', 'Mozilla/5.0')
                with urllib.request.urlopen(req, timeout=2) as response:
                    if response.status == 200:
                        print(f"[OK] Server is accessible: {test_url}")
            except Exception as e:
                print(f"[WARN] Server test failed: {str(e)}")
            
            # Auto generate QR
            self.generate_qr()
            
        except OSError as e:
            if "Address already in use" in str(e):
                messagebox.showerror("Error", f"Port {self.server_port} is already in use!\n\nPlease stop other server or change port.")
            else:
                messagebox.showerror("Error", f"Failed to start server: {str(e)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start server: {str(e)}")
    
    def _run_server(self):
        """Run HTTP server"""
        try:
            self.http_server.serve_forever()
        except:
            pass
    
    def stop_local_server(self):
        """Stop local HTTP server"""
        if self.http_server is None:
            messagebox.showinfo("Info", "Server is not running!")
            return
        
        try:
            self.http_server.shutdown()
            self.http_server.server_close()
            self.http_server = None
            self.server_thread = None
            
            self.server_status_var.set("🔴 Server: Stopped")
            if self.server_status_label:
                self.server_status_label.config(fg=self.colors['error'])
            if self.qr_label:
                self.qr_label.config(
                    image="",
                    text="QR preview sẽ hiển thị ở đây sau khi tạo.",
                    bg=self.colors['panel'],
                    padx=0,
                    pady=0,
                    bd=0,
                    relief=tk.FLAT
                )
                self.qr_label.image = None
            self.status_var.set("Server stopped")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to stop server: {str(e)}")
    
    def create_qr_popup(self, img, url=""):
        """Create popup window with large QR code (minimal design like sample)"""
        try:
            popup = tk.Toplevel(self.root)
            popup.title("QR Code")
            popup.geometry("560x680")
            popup.configure(bg='#E0F2F1')  # Light teal background
            popup.resizable(False, False)

            # Center popup
            popup.update_idletasks()
            x = (popup.winfo_screenwidth() // 2) - (560 // 2)
            y = (popup.winfo_screenheight() // 2) - (680 // 2)
            popup.geometry(f"560x680+{x}+{y}")

            # Main container
            main_frame = tk.Frame(popup, bg='#E0F2F1')
            main_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=30)

            # QR Code display - large and centered
            qr_large = img.resize((460, 460), Image.Resampling.LANCZOS)
            qr_photo = ImageTk.PhotoImage(qr_large)

            qr_frame = tk.Frame(main_frame, bg='white', relief=tk.FLAT, bd=0)
            qr_frame.pack(pady=(10, 20))
            qr_frame.configure(padx=12, pady=12)

            qr_label = tk.Label(
                qr_frame,
                image=qr_photo,
                bg='white',
                bd=0
            )
            qr_label.image = qr_photo
            qr_label.pack()

            # Instruction text (single line)
            instruction = tk.Label(
                main_frame,
                text="Please Open QRCode scanner On Your phone",
                font=('Segoe UI', 11),
                fg='#3d3d3d',
                bg='#E0F2F1'
            )
            instruction.pack(pady=(5, 0))

            # Optional URL display for troubleshooting
            if url:
                tip = tk.Label(
                    main_frame,
                    text=url,
                    font=('Consolas', 9),
                    fg='#1976D2',
                    bg='#E0F2F1',
                    wraplength=500,
                    justify=tk.CENTER,
                    cursor='hand2'
                )

                def copy_and_stop(event, link=url):
                    self.copy_to_clipboard(link)
                    return "break"

                tip.bind('<Button-1>', copy_and_stop)
                tip.pack(pady=(10, 0))

            # Hint for closing
            hint = tk.Label(
                main_frame,
                text="(Click anywhere or press ESC to close)",
                font=('Segoe UI', 8),
                fg='#7a7a7a',
                bg='#E0F2F1'
            )
            hint.pack(pady=(15, 0))

            # Close behaviour: click anywhere / press ESC
            def close_popup(event=None):
                popup.destroy()

            popup.bind('<Escape>', close_popup)
            popup.bind('<Button-1>', close_popup)
            qr_label.bind('<Button-1>', close_popup)
            instruction.bind('<Button-1>', close_popup)
            hint.bind('<Button-1>', close_popup)

            # Prevent click on URL label from closing before copying
            if url:
                tip.bind('<ButtonRelease-1>', lambda e: None)

            popup.transient(self.root)
            popup.grab_set()

        except Exception as e:
            print(f"Error creating popup: {str(e)}")
            pass
    
    def copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            messagebox.showinfo("Copied", f"URL đã được copy vào clipboard!\n\n{text}")
        except Exception as e:
            print(f"Error copying to clipboard: {str(e)}")

    def run_on_ui(self, func, *args, **kwargs):
        """Bảo đảm thao tác UI chạy trên main thread"""
        if threading.current_thread() is threading.main_thread():
            func(*args, **kwargs)
        else:
            self.root.after(0, lambda: func(*args, **kwargs))

    def append_text(self, widget, text, see=True):
        """Append text vào widget (log) một cách an toàn"""
        widget.insert(tk.END, text)
        if see:
            widget.see(tk.END)
    
    def save_qr_code(self):
        """Save QR code to file"""
        if not self.qr_image:
            messagebox.showwarning("Warning", "Please generate QR code first!")
            return
        
        try:
            save_path = os.path.join("C:\\CONTRA16", "qr_code_adb.png")
            self.qr_image.save(save_path)
            messagebox.showinfo("Success", f"QR Code saved!\n\n{save_path}")
            os.startfile("C:\\CONTRA16")
        except Exception as e:
            messagebox.showerror("Error", f"Could not save: {str(e)}")
    
    def build_apk(self):
        """Build APK - KHÔNG CẦN ANDROID STUDIO"""
        if not self.ensure_active():
            return
        try:
            import importlib.util
            build_script = Path("C:\\CONTRA16\\build_adb_apk_simple.py")
            
            if not build_script.exists():
                messagebox.showerror("Error", "Build script not found!\n\nPlease check build_adb_apk_simple.py")
                return
            
            # Run build script in thread
            def build_thread():
                try:
                    self.run_on_ui(self.status_var.set, "Building APK...")
                    time.sleep(0.1)
                    
                    result = subprocess.run(
                        [sys.executable, str(build_script)],
                        capture_output=True,
                        text=True,
                        cwd="C:\\CONTRA16",
                        timeout=120
                    )
                    
                    if result.returncode == 0:
                        # Check if APK was created
                        apk_path = Path("C:\\CONTRA16\\contra-adb.apk")
                        if apk_path.exists():
                            self.run_on_ui(self.status_var.set, "APK built successfully!")
                            self.run_on_ui(lambda: messagebox.showinfo(
                                "Success",
                                f"APK built successfully!\n\n{apk_path}\n\nYou can now use it in the tool."
                            ))
                        else:
                            self.run_on_ui(self.status_var.set, "Build completed but APK not found")
                            self.run_on_ui(lambda: messagebox.showwarning(
                                "Warning",
                                "Build completed but APK not found.\n\nPlease check the output."
                            ))
                    else:
                        self.run_on_ui(self.status_var.set, "Build failed")
                        self.run_on_ui(lambda: messagebox.showerror(
                            "Error",
                            f"Build failed:\n\n{result.stderr}"
                        ))
                        
                except subprocess.TimeoutExpired:
                    self.run_on_ui(self.status_var.set, "Build timeout")
                    self.run_on_ui(lambda: messagebox.showerror("Error", "Build timeout!"))
                except Exception as e:
                    self.run_on_ui(self.status_var.set, "Build error")
                    self.run_on_ui(lambda: messagebox.showerror("Error", f"Build error: {str(e)}"))
            
            thread = threading.Thread(target=build_thread, daemon=True)
            thread.start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start build: {str(e)}")
    
    def scan_tsm_qr(self):
        """Scan QR code để lấy URL"""
        if not self.ensure_active():
            return
        try:
            # Option 1: Load QR code image
            file_path = filedialog.askopenfilename(
                title="Chọn QR Code",
                filetypes=[
                    ("Image files", "*.png *.jpg *.jpeg *.bmp *.gif"),
                    ("PNG files", "*.png"),
                    ("All files", "*.*")
                ],
                initialdir="C:\\CONTRA16"
            )
            
            if not file_path:
                # Option 2: Manual input URL
                self.manual_input_url()
                return
            
            # Try to decode QR code
            if QR_DECODE_AVAILABLE:
                try:
                    img = cv2.imread(file_path)
                    if img is None:
                        raise ValueError("Cannot read image")
                    
                    # Decode QR code
                    qr_codes = qr_decode(img)
                    
                    if qr_codes:
                        qr_data = qr_codes[0].data.decode('utf-8')
                        self.url_var.set(qr_data)
                        self.status_var.set(f"QR Code decoded: {qr_data[:50]}...")
                        messagebox.showinfo("Success", f"QR Code decoded successfully!\n\nURL: {qr_data}\n\nClick 'Generate QR Code' to use it.")
                    else:
                        raise ValueError("No QR code found in image")
                        
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to decode QR code:\n\n{str(e)}\n\nTrying manual method...")
                    self.manual_input_url()
            else:
                # Try with qrcode library (reverse)
                try:
                    from PIL import Image
                    img = Image.open(file_path)
                    # Note: qrcode library doesn't decode, only encodes
                    # So we'll use manual input
                    messagebox.showinfo("Info", "QR decode library not available.\n\nPlease manually enter the URL.")
                    self.manual_input_url()
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to read image:\n\n{str(e)}")
                    self.manual_input_url()
                    
        except Exception as e:
            messagebox.showerror("Error", f"Failed to scan QR code: {str(e)}")
    
    def manual_input_url(self):
        """Manual input URL"""
        if not self.ensure_active():
            return
        dialog = tk.Toplevel(self.root)
        dialog.title("Nhập URL")
        dialog.geometry("600x200")
        dialog.configure(bg=self.colors['bg'])
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (600 // 2)
        y = (dialog.winfo_screenheight() // 2) - (200 // 2)
        dialog.geometry(f"600x200+{x}+{y}")
        
        # Title
        title = tk.Label(
            dialog,
            text="Nhập URL từ QR Code",
            font=('Segoe UI', 14, 'bold'),
            fg=self.colors['accent'],
            bg=self.colors['bg']
        )
        title.pack(pady=10)
        
        # Instructions
        instructions = tk.Label(
            dialog,
            text="1. Chọn file QR Code hoặc nhập URL\n2. Scan QR code bằng app QR scanner trên điện thoại\n3. Copy URL và paste vào đây:",
            font=('Segoe UI', 10),
            fg=self.colors['text'],
            bg=self.colors['bg'],
            justify=tk.LEFT
        )
        instructions.pack(pady=5)
        
        # URL input
        url_frame = tk.Frame(dialog, bg=self.colors['bg'])
        url_frame.pack(pady=10, padx=20, fill=tk.X)
        
        url_entry = tk.Entry(
            url_frame,
            font=('Consolas', 10),
            bg=self.colors['panel'],
            fg=self.colors['text'],
            insertbackground=self.colors['text'],
            relief=tk.FLAT,
            width=60
        )
        url_entry.pack(side=tk.LEFT, padx=5, ipady=5, fill=tk.X, expand=True)
        url_entry.focus()
        
        # Buttons
        btn_frame = tk.Frame(dialog, bg=self.colors['bg'])
        btn_frame.pack(pady=10)
        
        def apply_url():
            url = url_entry.get().strip()
            if url:
                self.url_var.set(url)
                self.status_var.set(f"URL imported successfully")
                dialog.destroy()
                messagebox.showinfo("Success", f"URL imported successfully!\n\n{url}\n\nClick 'Generate QR Code' to use it.")
            else:
                messagebox.showwarning("Warning", "Please enter URL!")
        
        def cancel():
            dialog.destroy()
        
        tk.Button(
            btn_frame,
            text="Apply",
            command=apply_url,
            font=('Segoe UI', 10, 'bold'),
            bg=self.colors['success'],
            fg='white',
            width=10,
            padx=10,
            pady=5
        ).pack(side=tk.LEFT, padx=5)
        
        tk.Button(
            btn_frame,
            text="Cancel",
            command=cancel,
            font=('Segoe UI', 10, 'bold'),
            bg=self.colors['error'],
            fg='white',
            width=10,
            padx=10,
            pady=5
        ).pack(side=tk.LEFT, padx=5)
        
        # Bind Enter key
        url_entry.bind('<Return>', lambda e: apply_url())
    
    def decode_qr_code(self):
        """Decode QR code to see URL inside"""
        if not self.ensure_active():
            return
        try:
            # Option 1: Load QR code image
            file_path = filedialog.askopenfilename(
                title="Chọn QR Code để decode",
                filetypes=[
                    ("Image files", "*.png *.jpg *.jpeg *.bmp *.gif"),
                    ("PNG files", "*.png"),
                    ("All files", "*.*")
                ],
                initialdir="C:\\CONTRA16"
            )
            
            if not file_path:
                return
            
            # Try to decode
            if QR_DECODE_AVAILABLE:
                try:
                    img = cv2.imread(file_path)
                    if img is None:
                        raise ValueError("Cannot read image")
                    
                    qr_codes = qr_decode(img)
                    
                    if qr_codes:
                        qr_data = qr_codes[0].data.decode('utf-8')
                        
                        # Show result
                        result_window = tk.Toplevel(self.root)
                        result_window.title("QR Code Decoded")
                        result_window.geometry("600x300")
                        result_window.configure(bg=self.colors['bg'])
                        
                        tk.Label(
                            result_window,
                            text="QR Code Content:",
                            font=('Segoe UI', 14, 'bold'),
                            fg=self.colors['accent'],
                            bg=self.colors['bg']
                        ).pack(pady=10)
                        
                        text_widget = scrolledtext.ScrolledText(
                            result_window,
                            font=('Consolas', 11),
                            bg=self.colors['panel'],
                            fg=self.colors['text'],
                            wrap=tk.WORD,
                            height=8
                        )
                        text_widget.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)
                        text_widget.insert(tk.END, qr_data)
                        text_widget.config(state=tk.DISABLED)
                        
                        def copy_url():
                            self.root.clipboard_clear()
                            self.root.clipboard_append(qr_data)
                            messagebox.showinfo("Copied", "URL đã được copy!")
                        
                        tk.Button(
                            result_window,
                            text="Copy URL",
                            command=copy_url,
                            font=('Segoe UI', 11, 'bold'),
                            bg=self.colors['success'],
                            fg='white',
                            padx=20,
                            pady=5
                        ).pack(pady=10)
                        
                    else:
                        messagebox.showerror("Error", "Không tìm thấy QR code trong hình ảnh!")
                        
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to decode QR code:\n\n{str(e)}")
            else:
                messagebox.showwarning(
                    "Warning",
                    "QR decode library không có!\n\nInstall: pip install pyzbar opencv-python"
                )
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed: {str(e)}")
    
    def load_tsm_qr_image(self):
        """Load QR code image và decode"""
        if not self.ensure_active():
            return
        try:
            file_path = filedialog.askopenfilename(
                title="Chọn QR Code",
                filetypes=[
                    ("Image files", "*.png *.jpg *.jpeg *.bmp *.gif"),
                    ("PNG files", "*.png"),
                    ("All files", "*.*")
                ],
                initialdir="C:\\CONTRA16"
            )
            
            if not file_path:
                return
            
            # Try to decode
            if QR_DECODE_AVAILABLE:
                try:
                    img = cv2.imread(file_path)
                    if img is None:
                        raise ValueError("Cannot read image")
                    
                    qr_codes = qr_decode(img)
                    
                    if qr_codes:
                        qr_data = qr_codes[0].data.decode('utf-8')
                        
                        # Update URL in tool
                        self.url_var.set(qr_data)
                        self.status_var.set(f"✅ Loaded URL from QR: {qr_data[:50]}...")
                        
                        # Show result and ask to generate QR
                        result = messagebox.askyesno(
                            "Success",
                            f"QR Code decoded successfully!\n\nURL: {qr_data}\n\n"
                            f"Bạn có muốn generate QR code mới với URL này không?"
                        )
                        
                        if result:
                            # Generate new QR with this URL
                            if self.http_server is None:
                                if messagebox.askyesno("Server", "Cần start server để generate QR. Bạn có muốn start server không?"):
                                    self.start_local_server()
                                    time.sleep(1)
                            
                            self.generate_qr()
                    else:
                        messagebox.showerror("Error", "Không tìm thấy QR code trong hình ảnh!\n\nVui lòng chọn file QR code khác.")
                        
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to decode QR code:\n\n{str(e)}")
            else:
                # Try to load image and show it
                try:
                    from PIL import Image, ImageTk
                    img = Image.open(file_path)
                    
                    # Show image in popup
                    img_window = tk.Toplevel(self.root)
                    img_window.title("QR Code")
                    img_window.geometry("600x700")
                    img_window.configure(bg=self.colors['bg'])
                    
                    # Resize image to fit
                    img_resized = img.resize((500, 500), Image.Resampling.LANCZOS)
                    img_tk = ImageTk.PhotoImage(img_resized)
                    
                    label = tk.Label(img_window, image=img_tk, bg=self.colors['bg'])
                    label.image = img_tk
                    label.pack(pady=20)
                    
                    tk.Label(
                        img_window,
                        text="QR Code đã được load.\n\nVui lòng install pyzbar để decode:\npip install pyzbar opencv-python",
                        font=('Segoe UI', 11),
                        fg=self.colors['text'],
                        bg=self.colors['bg'],
                        justify=tk.CENTER
                    ).pack(pady=20)
                    
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to load image:\n\n{str(e)}")
                    
        except Exception as e:
            messagebox.showerror("Error", f"Failed: {str(e)}")
    
    def upload_custom_apk(self):
        """Upload APK file khác để thay thế"""
        if not self.ensure_active():
            return
        try:
            file_path = filedialog.askopenfilename(
                title="Chọn APK file",
                filetypes=[
                    ("APK files", "*.apk"),
                    ("All files", "*.*")
                ],
                initialdir="C:\\CONTRA16"
            )
            
            if not file_path:
                return
            
            # Check if file exists
            apk_file = Path(file_path)
            if not apk_file.exists():
                messagebox.showerror("Error", "File không tồn tại!")
                return
            
            if not apk_file.suffix.lower() == '.apk':
                result = messagebox.askyesno(
                    "Warning",
                    "File không phải là .apk!\n\nBạn có muốn tiếp tục không?"
                )
                if not result:
                    return
            
            # Copy to C:\CONTRA16\contra-adb.apk
            target_path = Path("C:\\CONTRA16\\contra-adb.apk")
            
            # Check if source and target are the same
            if apk_file.resolve() == target_path.resolve():
                messagebox.showinfo("Info", "APK đã là file hiện tại rồi!\n\nKhông cần copy.")
                return
            
            try:
                import shutil
                # Remove old file if exists
                if target_path.exists():
                    target_path.unlink()
                shutil.copy2(apk_file, target_path)
                
                # Update APK path
                self.apk_path = target_path
                
                messagebox.showinfo(
                    "Success",
                    f"APK đã được upload thành công!\n\n"
                    f"File: {target_path}\n"
                    f"Size: {target_path.stat().st_size / 1024 / 1024:.2f} MB\n\n"
                    f"Bạn có thể restart server để dùng APK mới."
                )
                
                # Ask to restart server if running
                if self.http_server:
                    result = messagebox.askyesno(
                        "Restart Server?",
                        "Server đang chạy. Bạn có muốn restart server để dùng APK mới không?"
                    )
                    if result:
                        self.stop_local_server()
                        time.sleep(0.5)
                        self.start_local_server()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to copy APK:\n\n{str(e)}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed: {str(e)}")
    
    def build_contra16_apk(self):
        """Build CONTRA16 APK"""
        if not self.ensure_active():
            return
        try:
            build_script = Path("C:\\CONTRA16\\build_contra16_apk.py")
            
            if not build_script.exists():
                messagebox.showerror("Error", "Build script not found!\n\nPlease check build_contra16_apk.py")
                return
            
            def build_thread():
                try:
                    self.run_on_ui(self.status_var.set, "🔨 Building CONTRA16 APK...")
                    time.sleep(0.1)
                    
                    result = subprocess.run(
                        [sys.executable, str(build_script)],
                        capture_output=True,
                        text=True,
                        cwd="C:\\CONTRA16",
                        timeout=120
                    )
                    
                    # Check output
                    output = result.stdout + result.stderr
                    
                    if result.returncode == 0:
                        # Check if APK was created
                        apk_path = Path("C:\\CONTRA16\\contra-adb.apk")
                        if apk_path.exists():
                            size_mb = apk_path.stat().st_size / 1024 / 1024
                            self.run_on_ui(self.status_var.set, "✅ CONTRA16 APK built successfully!")
                            self.run_on_ui(lambda: messagebox.showinfo(
                                "Success",
                                f"CONTRA16 APK built successfully!\n\n"
                                f"File: {apk_path}\n"
                                f"Size: {size_mb:.2f} MB\n\n"
                                f"Bạn có thể dùng APK này ngay!"
                            ))
                            # Update APK path
                            self.apk_path = apk_path
                        else:
                            self.run_on_ui(self.status_var.set, "Build completed but APK not found")
                            self.run_on_ui(lambda: messagebox.showwarning(
                                "Warning",
                                "Build completed but APK not found.\n\nPlease check the output."
                            ))
                    else:
                        self.run_on_ui(self.status_var.set, "Build failed")
                        self.run_on_ui(lambda: messagebox.showerror(
                            "Error",
                            f"Build failed:\n\n{output[-500:]}"  # Last 500 chars
                        ))
                        
                except subprocess.TimeoutExpired:
                    self.run_on_ui(self.status_var.set, "Build timeout")
                    self.run_on_ui(lambda: messagebox.showerror("Error", "Build timeout!"))
                except Exception as e:
                    self.run_on_ui(self.status_var.set, "Build error")
                    self.run_on_ui(lambda: messagebox.showerror("Error", f"Build error: {str(e)}"))
            
            thread = threading.Thread(target=build_thread, daemon=True)
            thread.start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start build: {str(e)}")
    
    def show_build_guide(self):
        """Show build APK guide"""
        guide_file = Path("C:\\CONTRA16\\HUONG_DAN_BUILD_APK.md")
        
        if guide_file.exists():
            # Open file
            try:
                os.startfile(str(guide_file))
            except:
                # Show in dialog
                try:
                    content = guide_file.read_text(encoding='utf-8')
                    guide_window = tk.Toplevel(self.root)
                    guide_window.title("Hướng dẫn Build APK")
                    guide_window.geometry("800x600")
                    guide_window.configure(bg=self.colors['bg'])
                    
                    text_widget = scrolledtext.ScrolledText(
                        guide_window,
                        font=('Consolas', 10),
                        bg=self.colors['panel'],
                        fg=self.colors['text'],
                        wrap=tk.WORD
                    )
                    text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
                    text_widget.insert(tk.END, content)
                    text_widget.config(state=tk.DISABLED)
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to open guide: {str(e)}")
        else:
            messagebox.showinfo(
                "Guide",
                "Hướng dẫn Build APK:\n\n"
                "1. Cài Android Studio\n"
                "2. Tạo project mới\n"
                "3. Copy code MainActivity.java (xem file HUONG_DAN_BUILD_APK.md)\n"
                "4. Build APK\n"
                "5. Copy APK vào C:\\CONTRA16\\contra-adb.apk\n\n"
                "File hướng dẫn: C:\\CONTRA16\\HUONG_DAN_BUILD_APK.md"
            )

def main():
    root = tk.Tk()
    app = ContraPro16(root)
    
    # Cleanup on exit
    def on_closing():
        # Stop logo animation
        app.animating_logo = False
        
        # Stop HTTP server
        if app.http_server:
            try:
                app.http_server.shutdown()
                app.http_server.server_close()
            except:
                pass
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()
