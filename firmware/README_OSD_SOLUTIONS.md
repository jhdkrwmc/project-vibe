# 🎥 SONiX C1 Camera OSD Disable Solutions

## **Overview**
This directory contains multiple solutions to automatically disable OSD (On-Screen Display) on SONiX C1 cameras across different platforms and use cases.

## **🚀 Quick Start (Choose Your Platform)**

### **Windows Users (Recommended)**
1. **Double-click** `windows_auto_osd.bat` to run manually
2. **Double-click** `install_windows_auto_osd.reg` to install auto-startup
3. **Or** copy `windows_auto_osd.bat` to Windows Startup folder

### **Linux/WSL Users**
1. **Run** `./auto_osd_disable.sh` to disable OSD once
2. **Run** `python3 cross_platform_osd_disable.py` for continuous monitoring
3. **Or** add to system startup scripts

### **Cross-Platform (Python)**
1. **Run** `python cross_platform_osd_disable.py` for automatic monitoring
2. Works on Windows, Linux, macOS, Android, Oculus

## **📁 File Descriptions**

### **Core Scripts**
- **`windows_auto_osd.bat`** - Windows batch file for automatic OSD disable
- **`auto_osd_disable.sh`** - Linux/WSL shell script for one-time OSD disable
- **`cross_platform_osd_disable.py`** - Python script for all platforms

### **Installation Files**
- **`install_windows_auto_osd.reg`** - Windows registry file for auto-startup
- **`start_osd_monitor.bat`** - Windows startup script (created by Python script)
- **`start_osd_monitor.ps1`** - PowerShell startup script (created by Python script)
- **`start_osd_monitor.sh`** - Linux startup script (created by Python script)

## **🔧 How It Works**

### **The Problem**
- SONiX C1 cameras have OSD enabled by default
- Firmware patching causes "Code 10" errors (bricks camera)
- ASIC register writes are protected/ignored
- OSD settings reset on power cycle

### **The Solution**
- Uses **UVC control interface** (safe, official method)
- **No firmware modification** required
- **Automatic detection** of camera connection
- **Cross-platform compatibility**

## **💻 Platform-Specific Instructions**

### **Windows**
```batch
# Option 1: Run manually
windows_auto_osd.bat

# Option 2: Install auto-startup
install_windows_auto_osd.reg

# Option 3: Copy to Startup folder
# Win+R → shell:startup → Copy windows_auto_osd.bat there
```

### **Linux/WSL**
```bash
# Option 1: One-time disable
./auto_osd_disable.sh

# Option 2: Continuous monitoring
python3 cross_platform_osd_disable.py

# Option 3: Add to startup
echo "cd /path/to/camera && ./auto_osd_disable.sh" >> ~/.bashrc
```

### **Android/Oculus**
```bash
# Use the Python script with Termux or similar
python3 cross_platform_osd_disable.py
```

## **🎯 Use Cases**

### **Multiple Cameras**
- Script automatically detects all connected SONiX C1 cameras
- Disables OSD on each camera individually
- Works with 1, 2, 5, or 10+ cameras

### **Different Projects**
- **Oculus Development** - No OSD overlay in VR
- **Android Apps** - Clean camera feed
- **Windows Applications** - Professional video
- **Linux Systems** - Server/embedded use

### **Development Workflow**
- **No manual intervention** needed
- **Automatic on camera connect**
- **Works across reboots**
- **Safe and reliable**

## **⚠️ Important Notes**

### **What This Does**
- ✅ Disables OSD line overlay
- ✅ Disables OSD block overlay  
- ✅ Uses safe UVC control interface
- ✅ No firmware modification
- ✅ Works on all SONiX C1 models

### **What This Doesn't Do**
- ❌ Make settings permanent in firmware
- ❌ Survive camera power cycles
- ❌ Modify camera hardware
- ❌ Void camera warranty

### **Limitations**
- OSD re-enables after camera power cycle
- Requires script to run on each connection
- Windows may need admin privileges for some features

## **🔍 Troubleshooting**

### **Common Issues**
1. **"SONiX_UVC_TestAP not found"**
   - Run script from camera directory
   - Ensure test application exists

2. **"Camera not detected"**
   - Check USB connection
   - Verify camera is SONiX C1 (VID:0C45, PID:6366)
   - Try different USB port

3. **"OSD still visible"**
   - Wait 2-3 seconds after connection
   - Check script output for errors
   - Verify camera model compatibility

### **Advanced Debugging**
```bash
# Check camera detection
./SONiX_UVC_TestAP --xuget-chip /dev/video0

# Check OSD status
./SONiX_UVC_TestAP --xuget-oe /dev/video0

# Manual OSD disable
./SONiX_UVC_TestAP --xuset-oe "0,0" /dev/video0
```

## **🚀 Future Improvements**

### **Planned Features**
- **Firmware persistence** research (if possible)
- **Android app** for mobile devices
- **Oculus Quest** native support
- **Configuration profiles** for different use cases

### **Contributing**
- Test on different camera models
- Report platform-specific issues
- Suggest new features
- Share success stories

## **📞 Support**

### **Getting Help**
1. Check this README first
2. Run scripts with verbose output
3. Check camera compatibility
4. Verify platform requirements

### **Success Stories**
- ✅ Windows 10/11 automatic startup
- ✅ Linux/WSL development environments
- ✅ Multiple camera setups
- ✅ Cross-platform projects

---

**🎉 Enjoy your OSD-free SONiX C1 cameras!**
