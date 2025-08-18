#!/usr/bin/env python3
"""
Test script to check if firmware5262 supports OSD control commands
"""

import subprocess
import sys
import time


def run_command(cmd: str) -> tuple[int, str, str]:
	"""Run a command and return (return_code, stdout, stderr)"""
	try:
		result = subprocess.run(
			cmd.split(), 
			capture_output=True, 
			text=True, 
			timeout=10
		)
		return result.returncode, result.stdout, result.stderr
	except subprocess.TimeoutExpired:
		return -1, "", "Command timed out"
	except Exception as e:
		return -1, "", str(e)


def test_osd_control():
	"""Test OSD control commands on firmware5262"""
	print("Testing OSD control on firmware5262...")
	
	# Test 1: Check if OSD control is supported
	print("\n1. Testing OSD control support...")
	cmd = "./SONiX_UVC_TestAP --xuget-oe /dev/video0"
	ret, out, err = run_command(cmd)
	
	if ret == 0:
		print(f"✓ OSD control supported: {out.strip()}")
	else:
		print(f"✗ OSD control not supported: {err.strip()}")
		return False
	
	# Test 2: Try to disable OSD
	print("\n2. Attempting to disable OSD...")
	cmd = "./SONiX_UVC_TestAP --xuset-oe 0,0 /dev/video0"
	ret, out, err = run_command(cmd)
	
	if ret == 0:
		print("✓ OSD disable command sent successfully")
	else:
		print(f"✗ OSD disable failed: {err.strip()}")
		return False
	
	# Test 3: Verify OSD is disabled
	print("\n3. Verifying OSD status...")
	time.sleep(1)  # Give it time to take effect
	
	cmd = "./SONiX_UVC_TestAP --xuget-oe /dev/video0"
	ret, out, err = run_command(cmd)
	
	if ret == 0:
		print(f"✓ Current OSD status: {out.strip()}")
		if "0,0" in out or "00 00" in out:
			print("✓ OSD appears to be disabled!")
			return True
		else:
			print("⚠ OSD status unclear")
			return False
	else:
		print(f"✗ Could not verify OSD status: {err.strip()}")
		return False


def main():
	print("=== Firmware5262 OSD Control Test ===")
	print("This test checks if firmware5262 supports OSD control commands")
	print("If it does, you can use runtime control instead of firmware modification")
	
	success = test_osd_control()
	
	if success:
		print("\n🎉 SUCCESS: Firmware5262 supports OSD control!")
		print("You can:")
		print("1. Flash firmware5262 (no OSD code)")
		print("2. Use runtime commands to disable OSD if needed")
		print("3. OSD should stay off since there's no OSD code to re-enable it")
	else:
		print("\n❌ FAILED: Firmware5262 doesn't support OSD control")
		print("You'll need to stick with your original firmware and use runtime control")


if __name__ == "__main__":
	main()
