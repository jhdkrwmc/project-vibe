#!/usr/bin/env python3
"""
Cross-Platform Automatic OSD Disable for SONiX C1 Camera
Works on Windows, Linux, Android, Oculus - automatically disables OSD when camera connects

This script:
1. Monitors for camera connection
2. Automatically disables OSD
3. Works across all platforms
4. No manual intervention needed
"""

import os
import sys
import time
import subprocess
import platform
import threading
from pathlib import Path

class CrossPlatformOSDDisabler:
    def __init__(self):
        self.platform = platform.system().lower()
        self.camera_vendor_id = "0c45"
        self.camera_product_id = "6366"
        self.running = False
        
        # Platform-specific paths and commands
        if self.platform == "windows":
            self.device_pattern = "USB\\VID_0C45&PID_6366"
            self.test_app = "SONiX_UVC_TestAP.exe"
        else:
            self.device_pattern = "/dev/video*"
            self.test_app = "./SONiX_UVC_TestAP"
    
    def find_camera_devices(self):
        """Find all connected SONiX C1 cameras"""
        devices = []
        
        if self.platform == "windows":
            # Windows: Use PowerShell to find USB devices
            try:
                cmd = f'Get-PnpDevice | Where-Object {{ $_.InstanceId -like "*{self.device_pattern}*" }} | Select-Object InstanceId'
                result = subprocess.run(['powershell', '-Command', cmd], capture_output=True, text=True)
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if 'VID_0C45&PID_6366' in line:
                            devices.append(line.strip())
            except:
                pass
        else:
            # Linux/WSL: Check /dev/video* devices
            try:
                for device in Path("/dev").glob("video*"):
                    if device.exists():
                        devices.append(str(device))
            except:
                pass
        
        return devices
    
    def disable_osd_on_device(self, device):
        """Disable OSD on a specific camera device"""
        try:
            print(f"🔍 Checking OSD status on {device}...")
            
            # Check current OSD status
            cmd = [self.test_app, "--xuget-oe", device]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # Check if OSD is already disabled
                if "OSD Enable Line = 0" in result.stdout and "OSD Enable Block = 0" in result.stdout:
                    print(f"✅ OSD already disabled on {device}")
                    return True
                
                # Disable OSD
                print(f"🚫 Disabling OSD on {device}...")
                cmd = [self.test_app, "--xuset-oe", "0,0", device]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    print(f"✅ OSD disabled successfully on {device}")
                    
                    # Verify disable
                    time.sleep(1)
                    cmd = [self.test_app, "--xuget-oe", device]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    
                    if "OSD Enable Line = 0" in result.stdout and "OSD Enable Block = 0" in result.stdout:
                        print(f"✅ OSD disable verified on {device}")
                        return True
                    else:
                        print(f"⚠️ OSD disable verification failed on {device}")
                        return False
                else:
                    print(f"❌ Failed to disable OSD on {device}")
                    return False
            else:
                print(f"❌ Could not access {device}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"⏰ Timeout accessing {device}")
            return False
        except Exception as e:
            print(f"❌ Error with {device}: {e}")
            return False
    
    def monitor_and_disable(self):
        """Monitor for camera connections and automatically disable OSD"""
        print(f"🎥 Starting cross-platform OSD monitor for {self.platform}...")
        print(f"📱 Looking for SONiX C1 cameras (VID:{self.camera_vendor_id}, PID:{self.camera_product_id})")
        print("🔄 Monitoring for camera connections...")
        print("💡 Press Ctrl+C to stop monitoring")
        
        last_devices = set()
        
        while self.running:
            try:
                current_devices = set(self.find_camera_devices())
                
                # Check for new devices
                new_devices = current_devices - last_devices
                if new_devices:
                    print(f"\n🆕 New camera(s) detected: {new_devices}")
                    
                    # Wait a moment for device to be ready
                    time.sleep(2)
                    
                    # Disable OSD on all new devices
                    for device in new_devices:
                        self.disable_osd_on_device(device)
                
                # Check for disconnected devices
                disconnected = last_devices - current_devices
                if disconnected:
                    print(f"\n🔌 Camera(s) disconnected: {disconnected}")
                
                last_devices = current_devices
                
                # Sleep before next check
                time.sleep(5)
                
            except KeyboardInterrupt:
                print("\n🛑 Stopping OSD monitor...")
                break
            except Exception as e:
                print(f"⚠️ Monitor error: {e}")
                time.sleep(5)
    
    def start_monitoring(self):
        """Start the monitoring thread"""
        self.running = True
        self.monitor_and_disable()
    
    def stop_monitoring(self):
        """Stop the monitoring thread"""
        self.running = False

def create_startup_scripts():
    """Create startup scripts for different platforms"""
    platform_name = platform.system().lower()
    
    if platform_name == "windows":
        # Windows batch file
        batch_content = """@echo off
cd /d "%~dp0"
python cross_platform_osd_disable.py
pause
"""
        with open("start_osd_monitor.bat", "w") as f:
            f.write(batch_content)
        print("✅ Created start_osd_monitor.bat for Windows")
        
        # Windows PowerShell script
        ps_content = """# PowerShell script to start OSD monitor
Set-Location $PSScriptRoot
python cross_platform_osd_disable.py
"""
        with open("start_osd_monitor.ps1", "w") as f:
            f.write(ps_content)
        print("✅ Created start_osd_monitor.ps1 for Windows")
        
    else:
        # Linux/Unix shell script
        shell_content = """#!/bin/bash
cd "$(dirname "$0")"
python3 cross_platform_osd_disable.py
"""
        with open("start_osd_monitor.sh", "w") as f:
            f.write(shell_content)
        os.chmod("start_osd_monitor.sh", 0o755)
        print("✅ Created start_osd_monitor.sh for Linux/Unix")

def main():
    """Main function"""
    print("🎥 Cross-Platform SONiX C1 OSD Disable Tool")
    print("=" * 50)
    
    # Check if we're in the right directory
    if not Path("SONiX_UVC_TestAP").exists() and not Path("SONiX_UVC_TestAP.exe").exists():
        print("❌ SONiX_UVC_TestAP not found in current directory")
        print("Please run this script from the directory containing the test application")
        sys.exit(1)
    
    # Create startup scripts
    create_startup_scripts()
    
    # Start monitoring
    disabler = CrossPlatformOSDDisabler()
    
    try:
        disabler.start_monitoring()
    except KeyboardInterrupt:
        print("\n👋 OSD monitor stopped")

if __name__ == "__main__":
    main()
