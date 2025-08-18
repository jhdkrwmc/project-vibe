#!/usr/bin/env python3
"""
Runtime OSD Disable Script for SONiX C1 Camera
Uses UVC control interface to disable OSD without firmware patching.

This script:
1. Disables OSD line and block overlays via UVC control
2. Checks if settings persist across power cycles
3. Attempts ASIC register writes for persistence
"""

import subprocess
import time
import sys
import os
from pathlib import Path

class SONiXOSDController:
    def __init__(self, device="/dev/video0"):
        self.device = device
        self.test_app = "./SONiX_UVC_TestAP"
        
        # Check if test app exists
        if not Path(self.test_app).exists():
            print(f"Error: {self.test_app} not found in current directory")
            print("Please run this script from the directory containing SONiX_UVC_TestAP")
            sys.exit(1)
    
    def run_command(self, cmd_args):
        """Run a command and return the result"""
        try:
            result = subprocess.run(
                [self.test_app] + cmd_args + [self.device],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except Exception as e:
            return False, "", str(e)
    
    def check_osd_status(self):
        """Check current OSD enable status"""
        print("🔍 Checking current OSD status...")
        success, stdout, stderr = self.run_command(["--xuget-oe"])
        
        if success:
            print("✅ OSD status retrieved successfully")
            # Parse output for OSD values
            if "OSD Enable Line" in stdout and "OSD Enable Block" in stdout:
                print(stdout)
                return True
            else:
                print("⚠️  Could not parse OSD values from output")
                return False
        else:
            print(f"❌ Failed to get OSD status: {stderr}")
            return False
    
    def disable_osd(self, line_disable=True, block_disable=True):
        """Disable OSD line and/or block overlays"""
        line_val = 0 if line_disable else 1
        block_val = 0 if block_disable else 1
        
        print(f"🚫 Disabling OSD: Line={line_val}, Block={block_val}")
        
        success, stdout, stderr = self.run_command([
            "--xuset-oe", str(line_val), str(block_val)
        ])
        
        if success:
            print("✅ OSD disable command sent successfully")
            return True
        else:
            print(f"❌ Failed to disable OSD: {stderr}")
            return False
    
    def verify_osd_disabled(self):
        """Verify that OSD was actually disabled"""
        print("🔍 Verifying OSD disable...")
        time.sleep(1)  # Give camera time to process
        
        success, stdout, stderr = self.run_command(["--xuget-oe"])
        
        if success:
            if "OSD Enable Line = 0" in stdout and "OSD Enable Block = 0" in stdout:
                print("✅ OSD successfully disabled!")
                return True
            else:
                print("⚠️  OSD may not be fully disabled")
                print(stdout)
                return False
        else:
            print(f"❌ Could not verify OSD status: {stderr}")
            return False
    
    def try_asic_write(self, addr, value):
        """Try to write to ASIC register for persistence"""
        print(f"🔧 Attempting ASIC write: 0x{addr:04X} = 0x{value:02X}")
        
        success, stdout, stderr = self.run_command([
            "--asic-w", f"0x{addr:04X}", f"0x{value:02X}"
        ])
        
        if success:
            print("✅ ASIC write successful")
            return True
        else:
            print(f"❌ ASIC write failed: {stderr}")
            return False
    
    def try_asic_read(self, addr):
        """Try to read from ASIC register"""
        print(f"🔍 Reading ASIC register: 0x{addr:04X}")
        
        success, stdout, stderr = self.run_command([
            "--asic-r", f"0x{addr:04X}"
        ])
        
        if success:
            print(f"✅ ASIC read successful: {stdout}")
            return True
        else:
            print(f"❌ ASIC read failed: {stderr}")
            return False
    
    def test_persistence(self):
        """Test if OSD disable persists across power cycles"""
        print("\n" + "="*60)
        print("🔄 TESTING OSD DISABLE PERSISTENCE")
        print("="*60)
        print()
        print("1. OSD has been disabled via UVC control")
        print("2. Now power cycle your camera (unplug USB)")
        print("3. Reconnect the camera")
        print("4. Run this script again to check if OSD is still disabled")
        print()
        print("If OSD re-enables after power cycle, we'll need to:")
        print("- Use ASIC register writes for persistence")
        print("- Or find the persistent storage mechanism")
        print()
        print("Press Enter when ready to test persistence...")
        input()
        
        # Check OSD status after power cycle
        if self.check_osd_status():
            print("\n🎯 OSD status after power cycle:")
            success, stdout, stderr = self.run_command(["--xuget-oe"])
            if success:
                print(stdout)
                
                # Check if still disabled
                if "OSD Enable Line = 0" in stdout and "OSD Enable Block = 0" in stdout:
                    print("🎉 SUCCESS! OSD disable persists across power cycles!")
                    return True
                else:
                    print("⚠️  OSD re-enabled after power cycle - not persistent")
                    return False
        return False
    
    def attempt_persistent_disable(self):
        """Try to make OSD disable persistent using ASIC registers"""
        print("\n" + "="*60)
        print("🔧 ATTEMPTING PERSISTENT OSD DISABLE")
        print("="*60)
        
        # Try to write to the OSD enable registers we found in firmware
        osd_registers = [
            (0xE24, 0x00, "OSD Line Enable Register"),
            (0xE25, 0x00, "OSD Block Enable Register"),
            (0xE26, 0x00, "OSD Control Register")
        ]
        
        for addr, value, desc in osd_registers:
            print(f"\n📝 Writing to {desc} (0x{addr:04X})")
            if self.try_asic_write(addr, value):
                print(f"✅ Successfully wrote 0x{value:02X} to 0x{addr:04X}")
            else:
                print(f"❌ Failed to write to 0x{addr:04X}")
        
        # Verify the writes
        print("\n🔍 Verifying ASIC register writes...")
        for addr, expected_value, desc in osd_registers:
            print(f"\nReading {desc} (0x{addr:04X})")
            if self.try_asic_read(addr):
                # Parse the output to get the actual value
                success, stdout, stderr = self.run_command(["--asic-r", f"0x{addr:04X}"])
                if success and f"0x{expected_value:02X}" in stdout:
                    print(f"✅ Register 0x{addr:04X} contains expected value 0x{expected_value:02X}")
                else:
                    print(f"⚠️  Register 0x{addr:04X} may not contain expected value")
        
        return True

def main():
    """Main function"""
    print("🎥 SONiX C1 Camera Runtime OSD Disable Tool")
    print("=" * 50)
    
    # Check if device exists
    device = "/dev/video0"
    if not Path(device).exists():
        print(f"❌ Device {device} not found")
        print("Please ensure your camera is connected and recognized")
        sys.exit(1)
    
    controller = SONiXOSDController(device)
    
    # Step 1: Check current OSD status
    if not controller.check_osd_status():
        print("❌ Could not determine current OSD status")
        sys.exit(1)
    
    # Step 2: Disable OSD
    if not controller.disable_osd(line_disable=True, block_disable=True):
        print("❌ Failed to disable OSD")
        sys.exit(1)
    
    # Step 3: Verify OSD is disabled
    if not controller.verify_osd_disabled():
        print("❌ OSD disable verification failed")
        sys.exit(1)
    
    print("\n🎯 OSD has been disabled successfully!")
    print("Now testing if this setting persists across power cycles...")
    
    # Step 4: Test persistence
    if controller.test_persistence():
        print("\n🎉 OSD disable is persistent! No further action needed.")
    else:
        print("\n⚠️  OSD disable is NOT persistent. Attempting ASIC register writes...")
        controller.attempt_persistent_disable()
        
        print("\n" + "="*60)
        print("📋 NEXT STEPS")
        print("="*60)
        print("1. Power cycle your camera again")
        print("2. Run this script again to check if ASIC writes made it persistent")
        print("3. If still not persistent, we may need to investigate further")
        print("   - Look for EEPROM/Flash write commands")
        print("   - Check for configuration save commands")
        print("   - Examine the camera's boot sequence")

if __name__ == "__main__":
    main()
