# 💉 RbxMMap – Advanced Manual Mapping Injector for Roblox

**RbxMMap** is a powerful, low-level DLL injector built specifically for Roblox using advanced manual mapping techniques.  
Though it's currently in a WIP (work-in-progress) state due to access violations, it lays a rock-solid foundation for building next-gen, stealthy injectors.

> ⚠️ For educational and research purposes only. Unauthorized use on third-party platforms may violate terms of service.

---

## ⚙️ Features

### 💉 Advanced Process Injection Methods
- Manual Mapping with relocation handling
- Reflective DLL injection support
- LoadLibraryW fallback injection
- Thread hijacking for stealth memory operations
- Optimized chunked memory writes (16–64 bytes)
- 10x retry logic for reliable memory writes

### 🔒 Anti-Debug & Security Bypass
- PEB manipulation to hide from user-mode debuggers
- Heap flag manipulation for anti-debug hardening
- API hooking to bypass standard debug checks
- Hardware breakpoint detection and removal
- Thread hiding from common debugging tools
- Patches for:
  - `TaskSpawn` (0x10DD3C0) – prevents thread-based detection
  - `RequestCode` (0xA120E0) – bypasses memory validation
  - `LockViolationInstanceCrash` (0x5A91678) – avoids memory write crashes

### 🛡️ Memory Protection & Manipulation
- VirtualProtect memory permission control
- Custom retry logic for stable memory writing
- Polymorphic shellcode generation for evasion
- Simplified `WriteProcessMemory` for better performance
- Access violation handling with delayed retries (15ms)

### 🔍 Process Analysis & Control
- Target process enumeration + PID detection
- Full thread enumeration and remote thread control
- Privilege checks for injection readiness
- Updated Roblox Hyperion base address reference: `0x7ffdf0a00000`

### 📝 Logging & Error Handling
- File-based error logs for crash diagnostics
- Real-time console output with status updates
- Exception catching for key failure points
- Operation timing and intelligent retry delays
- Cleaner error message formatting

### 🧩 Code Structure
- Clean and modular C++ codebase
- Integrated low-level Windows APIs
- Custom NT definitions (no extra libs required)
- Easy to extend and customize
- Code randomization support for anti-detection
- Improved reliability via intelligent retry logic

---

## 🚧 Current Status

The injector is **not yet stable** due to **access violation issues**, but it's already packed with robust architecture and defense bypass techniques.  
A perfect base for:
- Fixing internal crashes
- Experimenting with different injection methods
- Learning about memory manipulation and manual mapping

---

## 🛠️ Disclaimer

This is a near-complete implementation of an advanced manual mapping injector for Roblox.  
While it currently encounters access violation issues, it serves as an excellent starting point for any developer looking to understand or build upon modern manual mapping techniques.
