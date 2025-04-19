#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <iostream>
#include <random>

#pragma comment(lib, "shlwapi.lib")

// Custom PEB definitions (simplified for anti-debug)
typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN BitField;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    // Simplified: Add more fields if needed
    ULONG NtGlobalFlag;
} PEB, * PPEB;

// Log error to file
void LogError(const std::wstring& error) {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    PathRemoveFileSpecW(exePath);
    std::wofstream logFile(std::wstring(exePath) + L"\\injection_log.txt", std::ios::app);
    if (logFile.is_open()) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        logFile << L"[" << st.wYear << L"-" << st.wMonth << L"-" << st.wDay << L" "
            << st.wHour << L":" << st.wMinute << L":" << st.wSecond << L"] ERROR: "
            << error << L"\n";
        logFile.close();
    }
}

// Anti-debug check (targeted to avoid false positives)
bool IsDebuggerPresentAdvanced() {
    // Check standard debugger
    if (IsDebuggerPresent()) {
        LogError(L"Debugger detected: IsDebuggerPresent returned TRUE");
        return true;
    }

    // Check PEB BeingDebugged flag
    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
    if (peb->BeingDebugged) {
        LogError(L"Debugger detected: PEB BeingDebugged flag set");
        // Clear BeingDebugged to evade anti-cheat
        peb->BeingDebugged = FALSE;
        if (IsDebuggerPresent()) {
            LogError(L"Debugger detected after clearing BeingDebugged");
            return true;
        }
    }

    // Skip NtGlobalFlag and hardware breakpoints to avoid Hyperion false positives
    std::wcout << L"Anti-debug check passed\n";
    return false;
}

// Find RobloxPlayerBeta PID
DWORD FindRobloxPID() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        LogError(L"Failed to create process snapshot: Error " + std::to_wstring(error));
        std::wcout << L"Error: Failed to create process snapshot (Error: " << error << L")\n";
        return 0;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    std::wstring targetProcess = L"RobloxPlayerBeta";
    std::wstring targetProcessExe = L"RobloxPlayerBeta.exe";

    std::wcout << L"Enumerating processes...\n";
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            std::wcout << L"Found process: " << pe32.szExeFile << L" (PID: " << pe32.th32ProcessID << L")\n";
            if (_wcsicmp(pe32.szExeFile, targetProcess.c_str()) == 0 ||
                _wcsicmp(pe32.szExeFile, targetProcessExe.c_str()) == 0 ||
                wcsstr(pe32.szExeFile, L"Roblox") != nullptr) {
                std::wcout << L"Matched Roblox process: " << pe32.szExeFile << L" (PID: " << pe32.th32ProcessID << L")\n";
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    else {
        DWORD error = GetLastError();
        LogError(L"Failed to enumerate processes: Error " + std::to_wstring(error));
        std::wcout << L"Error: Failed to enumerate processes (Error: " << error << L")\n";
    }

    CloseHandle(hSnapshot);
    return 0;
}

// Obfuscated memory write
bool ObfuscatedWriteProcessMemory(HANDLE hProcess, LPVOID dest, const void* src, SIZE_T size, SIZE_T* bytesWritten) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> chunkDist(64, 256); // Random chunk sizes

    SIZE_T totalWritten = 0;
    const uint8_t* srcPtr = static_cast<const uint8_t*>(src);
    uint8_t* destPtr = static_cast<uint8_t*>(dest);

    while (totalWritten < size) {
        SIZE_T chunkSize = min(chunkDist(gen), size - totalWritten);
        if (!WriteProcessMemory(hProcess, destPtr + totalWritten, srcPtr + totalWritten, chunkSize, nullptr)) {
            LogError(L"Obfuscated write failed at offset " + std::to_wstring(totalWritten) +
                L": Error " + std::to_wstring(GetLastError()));
            std::wcout << L"Error: Obfuscated write failed\n";
            return false;
        }
        totalWritten += chunkSize;
        Sleep(1); // Small delay to evade timing-based detection
    }

    if (bytesWritten) *bytesWritten = totalWritten;
    return true;
}

// Manual mapping injector class
class ManualMapper {
private:
    HANDLE hProcess;

    // Map sections with obfuscation
    bool MapSections(const IMAGE_NT_HEADERS* ntHeaders, LPVOID imageBase, const std::vector<uint8_t>& dllData) {
        std::wcout << L"Mapping sections...\n";
        auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (sectionHeader[i].SizeOfRawData == 0) continue;

            LPVOID sectionDest = static_cast<uint8_t*>(imageBase) + sectionHeader[i].VirtualAddress;
            LPVOID sectionSrc = const_cast<uint8_t*>(dllData.data()) + sectionHeader[i].PointerToRawData;

            std::wcout << L"Writing section " << i << L" (Size: " << sectionHeader[i].SizeOfRawData << L")\n";
            if (!ObfuscatedWriteProcessMemory(hProcess, sectionDest, sectionSrc, sectionHeader[i].SizeOfRawData, nullptr)) {
                LogError(L"Failed to write section " + std::to_wstring(i) + L" to process memory");
                std::wcout << L"Error: Failed to write section " << i << L" to process memory\n";
                return false;
            }
        }
        std::wcout << L"Sections mapped\n";
        return true;
    }

    // Fix relocations with advanced validation
    bool FixRelocations(const IMAGE_NT_HEADERS* ntHeaders, LPVOID imageBase, DWORD64 delta) {
        std::wcout << L"Fixing relocations...\n";
        auto relocationDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        std::wcout << L"Relocation directory: VA=" << relocationDir.VirtualAddress
            << L", Size=" << relocationDir.Size
            << L", SizeOfImage=" << ntHeaders->OptionalHeader.SizeOfImage << L"\n";

        if (relocationDir.Size == 0 || relocationDir.VirtualAddress == 0) {
            std::wcout << L"No relocations needed\n";
            return true;
        }

        // Validate relocation directory
        if (relocationDir.VirtualAddress >= ntHeaders->OptionalHeader.SizeOfImage ||
            relocationDir.Size > ntHeaders->OptionalHeader.SizeOfImage ||
            relocationDir.VirtualAddress + relocationDir.Size > ntHeaders->OptionalHeader.SizeOfImage) {
            LogError(L"Invalid relocation directory: VA=" + std::to_wstring(relocationDir.VirtualAddress) +
                L", Size=" + std::to_wstring(relocationDir.Size) +
                L", SizeOfImage=" + std::to_wstring(ntHeaders->OptionalHeader.SizeOfImage));
            std::wcout << L"Error: Invalid relocation directory\n";
            return false;
        }

        try {
            // Ensure memory is accessible
            LPVOID relocationAddr = static_cast<uint8_t*>(imageBase) + relocationDir.VirtualAddress;
            MEMORY_BASIC_INFORMATION mbi;
            if (!VirtualQueryEx(hProcess, relocationAddr, &mbi, sizeof(mbi)) ||
                mbi.State != MEM_COMMIT ||
                (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) == 0) {
                // Attempt to fix protection
                DWORD oldProtect;
                if (!VirtualProtectEx(hProcess, relocationAddr, relocationDir.Size,
                    PAGE_EXECUTE_READWRITE, &oldProtect)) {
                    LogError(L"Failed to adjust relocation memory protection: Error=" +
                        std::to_wstring(GetLastError()));
                    std::wcout << L"Error: Failed to adjust relocation memory protection\n";
                    return false;
                }
            }

            auto relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(relocationAddr);
            DWORD blockCount = 0;
            SIZE_T totalSize = 0;

            while (totalSize < relocationDir.Size && relocation->VirtualAddress && relocation->SizeOfBlock) {
                blockCount++;
                std::wcout << L"Processing relocation block " << blockCount << L" (VA: " << relocation->VirtualAddress
                    << L", Size: " << relocation->SizeOfBlock << L")\n";

                if (relocation->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
                    totalSize + relocation->SizeOfBlock > relocationDir.Size) {
                    LogError(L"Invalid relocation block " + std::to_wstring(blockCount) +
                        L": Size=" + std::to_wstring(relocation->SizeOfBlock));
                    std::wcout << L"Error: Invalid relocation block size\n";
                    return false;
                }

                DWORD numRelocs = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                auto relocInfo = reinterpret_cast<PWORD>(relocation + 1);

                for (DWORD i = 0; i < numRelocs; i++) {
                    WORD type = relocInfo[i] >> 12;
                    WORD offset = relocInfo[i] & 0xFFF;

                    if (type == IMAGE_REL_BASED_DIR64) {
                        auto* patchAddr = reinterpret_cast<DWORD64*>(
                            static_cast<uint8_t*>(imageBase) + relocation->VirtualAddress + offset);
                        if (reinterpret_cast<SIZE_T>(patchAddr) < reinterpret_cast<SIZE_T>(imageBase) ||
                            reinterpret_cast<SIZE_T>(patchAddr) >=
                            reinterpret_cast<SIZE_T>(imageBase) + ntHeaders->OptionalHeader.SizeOfImage) {
                            LogError(L"Invalid relocation patch address in block " + std::to_wstring(blockCount) +
                                L": Address=" + std::to_wstring(reinterpret_cast<SIZE_T>(patchAddr)));
                            std::wcout << L"Error: Invalid relocation patch address\n";
                            return false;
                        }
                        *patchAddr += delta;
                    }
                }
                totalSize += relocation->SizeOfBlock;
                relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                    reinterpret_cast<uint8_t*>(relocation) + relocation->SizeOfBlock);
            }
            std::wcout << L"Processed " << blockCount << L" relocation blocks (Total Size: " << totalSize << L")\n";
            return true;
        }
        catch (const std::exception& e) {
            LogError(L"Exception in FixRelocations: " + std::wstring(e.what(), e.what() + strlen(e.what())));
            std::wcout << L"Error: Exception in FixRelocations: " << e.what() << L"\n";
            return false;
        }
        catch (...) {
            LogError(L"Unknown exception in FixRelocations");
            std::wcout << L"Error: Unknown exception in FixRelocations\n";
            return false;
        }
    }

public:
    ManualMapper(HANDLE process) : hProcess(process) {}

    // Read DLL file
    bool ReadDllFile(const std::wstring& dllPath, std::vector<uint8_t>& dllData) {
        std::wcout << L"Reading DLL file: " << dllPath << L"\n";
        std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
        if (!file) {
            LogError(L"Failed to open DLL file: " + dllPath);
            std::wcout << L"Error: Failed to open DLL file: " << dllPath << L"\n";
            return false;
        }

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);
        dllData.resize(size);
        if (!file.read(reinterpret_cast<char*>(dllData.data()), size)) {
            LogError(L"Failed to read DLL file: " + dllPath);
            std::wcout << L"Error: Failed to read DLL file: " << dllPath << L"\n";
            return false;
        }
        std::wcout << L"DLL file read successfully (" << size << L" bytes)\n";
        return true;
    }

    // Verify DLL is 64-bit
    bool IsDll64Bit(const std::vector<uint8_t>& dllData) {
        std::wcout << L"Verifying DLL architecture...\n";
        if (dllData.size() < sizeof(IMAGE_DOS_HEADER)) {
            LogError(L"Invalid DLL: File too small for DOS header");
            std::wcout << L"Error: Invalid DLL (File too small for DOS header)\n";
            return false;
        }

        auto* rawData = dllData.data();
        auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(rawData);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            LogError(L"Invalid DLL: DOS signature mismatch during architecture check");
            std::wcout << L"Error: Invalid DLL (DOS signature mismatch during architecture check)\n";
            return false;
        }

        if (dllData.size() < dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
            LogError(L"Invalid DLL: File too small for NT headers");
            std::wcout << L"Error: Invalid DLL (File too small for NT headers)\n";
            return false;
        }

        auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(rawData + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            LogError(L"Invalid DLL: NT signature mismatch during architecture check");
            std::wcout << L"Error: Invalid DLL (NT signature mismatch during architecture check)\n";
            return false;
        }

        if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
            LogError(L"DLL is not 64-bit (Machine: " + std::to_wstring(ntHeaders->FileHeader.Machine) + L")");
            std::wcout << L"Error: DLL is not 64-bit (Machine: " << ntHeaders->FileHeader.Machine << L")\n";
            return false;
        }
        std::wcout << L"DLL is 64-bit\n";
        return true;
    }

    // Get image size
    SIZE_T GetImageSize(const IMAGE_NT_HEADERS* ntHeaders) {
        return ntHeaders->OptionalHeader.SizeOfImage;
    }

    bool Inject(const std::wstring& dllPath) {
        LPVOID imageBase = nullptr;
        try {
            std::vector<uint8_t> dllData;
            if (!ReadDllFile(dllPath, dllData)) {
                return false;
            }

            // Verify DLL is 64-bit
            if (!IsDll64Bit(dllData)) {
                return false;
            }

            // Parse headers
            std::wcout << L"Parsing PE headers...\n";
            auto* rawData = dllData.data();
            if (dllData.size() < sizeof(IMAGE_DOS_HEADER)) {
                LogError(L"Invalid DLL: File too small for DOS header");
                std::wcout << L"Error: Invalid DLL (File too small for DOS header)\n";
                return false;
            }

            auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(rawData);
            if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
                LogError(L"Invalid DLL: DOS signature mismatch");
                std::wcout << L"Error: Invalid DLL (DOS signature mismatch)\n";
                return false;
            }

            if (dllData.size() < dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
                LogError(L"Invalid DLL: File too small for NT headers");
                std::wcout << L"Error: Invalid DLL (File too small for NT headers)\n";
                return false;
            }

            auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(rawData + dosHeader->e_lfanew);
            if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
                LogError(L"Invalid DLL: NT signature mismatch");
                std::wcout << L"Error: Invalid DLL (NT signature mismatch)\n";
                return false;
            }
            std::wcout << L"PE headers valid\n";

            // Allocate memory
            std::wcout << L"Allocating memory in target process...\n";
            imageBase = VirtualAllocEx(hProcess, nullptr, GetImageSize(ntHeaders),
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!imageBase) {
                LogError(L"Failed to allocate memory in target process: Error " + std::to_wstring(GetLastError()));
                std::wcout << L"Error: Failed to allocate memory in target process\n";
                return false;
            }
            std::wcout << L"Memory allocated at " << imageBase << L"\n";

            // Write headers
            std::wcout << L"Writing PE headers...\n";
            if (!ObfuscatedWriteProcessMemory(hProcess, imageBase, rawData,
                ntHeaders->OptionalHeader.SizeOfHeaders, nullptr)) {
                LogError(L"Failed to write PE headers to process memory");
                std::wcout << L"Error: Failed to write PE headers to process memory\n";
                return false;
            }
            std::wcout << L"PE headers written\n";

            // Map sections
            if (!MapSections(ntHeaders, imageBase, dllData)) {
                return false;
            }

            // Fix relocations
            DWORD64 delta = reinterpret_cast<DWORD64>(imageBase) - ntHeaders->OptionalHeader.ImageBase;
            if (!FixRelocations(ntHeaders, imageBase, delta)) {
                return false;
            }

            // Execute DLL entry point
            std::wcout << L"Creating remote thread for DLL entry point...\n";
            LPVOID loadLibraryAddr = reinterpret_cast<LPVOID>(
                GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA"));
            if (!loadLibraryAddr) {
                LogError(L"Failed to get LoadLibraryA address: Error " + std::to_wstring(GetLastError()));
                std::wcout << L"Error: Failed to get LoadLibraryA address\n";
                return false;
            }

            HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryAddr),
                imageBase, 0, nullptr);
            if (!hThread) {
                LogError(L"Failed to create remote thread: Error " + std::to_wstring(GetLastError()));
                std::wcout << L"Error: Failed to create remote thread\n";
                return false;
            }

            std::wcout << L"Waiting for remote thread to complete...\n";
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
            std::wcout << L"Remote thread completed\n";
            return true;
        }
        catch (const std::exception& e) {
            LogError(L"Exception during injection: " + std::wstring(e.what(), e.what() + strlen(e.what())));
            std::wcout << L"Error: Exception during injection: " << e.what() << L"\n";
            if (imageBase) VirtualFreeEx(hProcess, imageBase, NULL, MEM_RELEASE);
            return false;
        }
        catch (...) {
            LogError(L"Unknown exception during injection");
            std::wcout << L"Error: Unknown exception during injection\n";
            if (imageBase) VirtualFreeEx(hProcess, imageBase, NULL, MEM_RELEASE);
            return false;
        }
    }
};

// Reflective DLL injection
bool ReflectiveInject(HANDLE hProcess, const std::wstring& dllPath) {
    std::wcout << L"Attempting reflective DLL injection...\n";
    std::vector<uint8_t> dllData;
    ManualMapper mapper(hProcess);
    if (!mapper.ReadDllFile(dllPath, dllData)) {
        return false;
    }

    // Allocate memory for DLL
    auto* rawData = dllData.data();
    auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(rawData);
    auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(rawData + dosHeader->e_lfanew);
    LPVOID imageBase = VirtualAllocEx(hProcess, nullptr, ntHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!imageBase) {
        LogError(L"Reflective: Failed to allocate memory: Error " + std::to_wstring(GetLastError()));
        std::wcout << L"Error: Reflective failed to allocate memory\n";
        return false;
    }

    // Write DLL image with obfuscation
    if (!ObfuscatedWriteProcessMemory(hProcess, imageBase, dllData.data(), dllData.size(), nullptr)) {
        LogError(L"Reflective: Failed to write DLL image");
        std::wcout << L"Error: Reflective failed to write DLL image\n";
        VirtualFreeEx(hProcess, imageBase, NULL, MEM_RELEASE);
        return false;
    }

    // Find reflective loader (assume DLL has a reflective entry point)
    DWORD64 delta = reinterpret_cast<DWORD64>(imageBase) - ntHeaders->OptionalHeader.ImageBase;
    LPVOID reflectiveEntry = static_cast<uint8_t*>(imageBase) + ntHeaders->OptionalHeader.AddressOfEntryPoint;

    // Create remote thread to execute reflective loader
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(reflectiveEntry),
        imageBase, 0, nullptr);
    if (!hThread) {
        LogError(L"Reflective: Failed to create remote thread: Error " + std::to_wstring(GetLastError()));
        std::wcout << L"Error: Reflective failed to create remote thread\n";
        VirtualFreeEx(hProcess, imageBase, NULL, MEM_RELEASE);
        return false;
    }

    std::wcout << L"Waiting for reflective thread to complete...\n";
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    std::wcout << L"Reflective injection completed\n";
    return true;
}

// Fallback LoadLibraryW injection
bool FallbackInject(HANDLE hProcess, const std::wstring& dllPath) {
    std::wcout << L"Attempting fallback LoadLibraryW injection...\n";
    LPVOID remotePath = VirtualAllocEx(hProcess, nullptr, (dllPath.size() + 1) * sizeof(wchar_t),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remotePath) {
        LogError(L"Fallback: Failed to allocate memory for DLL path: Error " + std::to_wstring(GetLastError()));
        std::wcout << L"Error: Fallback failed to allocate memory for DLL path\n";
        return false;
    }

    if (!ObfuscatedWriteProcessMemory(hProcess, remotePath, dllPath.c_str(),
        (dllPath.size() + 1) * sizeof(wchar_t), nullptr)) {
        LogError(L"Fallback: Failed to write DLL path to process memory");
        std::wcout << L"Error: Fallback failed to write DLL path to process memory\n";
        VirtualFreeEx(hProcess, remotePath, NULL, MEM_RELEASE);
        return false;
    }

    LPVOID loadLibraryAddr = reinterpret_cast<LPVOID>(
        GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW"));
    if (!loadLibraryAddr) {
        LogError(L"Fallback: Failed to get LoadLibraryW address: Error " + std::to_wstring(GetLastError()));
        std::wcout << L"Error: Fallback failed to get LoadLibraryW address\n";
        VirtualFreeEx(hProcess, remotePath, NULL, MEM_RELEASE);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryAddr),
        remotePath, 0, nullptr);
    if (!hThread) {
        LogError(L"Fallback: Failed to create remote thread: Error " + std::to_wstring(GetLastError()));
        std::wcout << L"Error: Fallback failed to create remote thread\n";
        VirtualFreeEx(hProcess, remotePath, NULL, MEM_RELEASE);
        return false;
    }

    std::wcout << L"Waiting for fallback remote thread to complete...\n";
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remotePath, NULL, MEM_RELEASE);
    std::wcout << L"Fallback injection completed\n";
    return true;
}

// Main injection function
bool InjectRoblox() {
    if (IsDebuggerPresentAdvanced()) {
        std::wcout << L"Error: Debugger detected, aborting\n";
        return false;
    }

    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    PathRemoveFileSpecW(exePath);
    std::wstring dllPath = std::wstring(exePath) + L"\\test.dll";

    std::wcout << L"Checking for test.dll...\n";
    if (GetFileAttributesW(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        LogError(L"DLL file not found: " + dllPath);
        std::wcout << L"Error: test.dll not found in the same folder.\n";
        return false;
    }
    std::wcout << L"test.dll found\n";

    std::wcout << L"Checking for administrator privileges...\n";
    BOOL isElevated = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD dwSize;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
            isElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    if (!isElevated) {
        LogError(L"Injector not running with administrator privileges");
        std::wcout << L"Error: Please run the injector as administrator.\n";
        return false;
    }
    std::wcout << L"Running with administrator privileges\n";

    std::wcout << L"Waiting for RobloxPlayerBeta to open...\n";
    DWORD pid = 0;
    int timeoutSeconds = 60;
    for (int i = 0; i < timeoutSeconds; i++) {
        pid = FindRobloxPID();
        if (pid != 0) {
            std::wcout << L"Roblox open PID: " << pid << L"\n";
            break;
        }
        Sleep(1000);
    }

    if (pid == 0) {
        LogError(L"RobloxPlayerBeta not found after " + std::to_wstring(timeoutSeconds) + L" seconds");
        std::wcout << L"Error: RobloxPlayerBeta not found after " << timeoutSeconds << L" seconds.\n";
        return false;
    }

    std::wcout << L"Opening Roblox process (PID: " << pid << L")...\n";
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        LogError(L"Failed to open Roblox process (PID: " + std::to_wstring(pid) +
            L"): Error " + std::to_wstring(GetLastError()));
        std::wcout << L"Error: Failed to open Roblox process\n";
        return false;
    }
    std::wcout << L"Roblox process opened\n";

    bool result = false;
    std::wcout << L"Attempting manual mapping injection...\n";
    ManualMapper injector(hProcess);
    result = injector.Inject(dllPath);

    if (!result) {
        std::wcout << L"Manual mapping failed, trying reflective injection...\n";
        result = ReflectiveInject(hProcess, dllPath);
    }

    if (!result) {
        std::wcout << L"Reflective injection failed, trying LoadLibraryW fallback...\n";
        result = FallbackInject(hProcess, dllPath);
    }

    CloseHandle(hProcess);
    if (result) {
        std::wcout << L"Injection successful\n";
    }
    else {
        std::wcout << L"Injection failed. Check injection_log.txt for details.\n";
    }
    return result;
}

// Structured exception handler for crashes
LONG WINAPI CrashHandler(EXCEPTION_POINTERS* ExceptionInfo) {
    std::wstring error = L"Crash detected. Exception code: " +
        std::to_wstring(ExceptionInfo->ExceptionRecord->ExceptionCode) +
        L", Address: " +
        std::to_wstring(reinterpret_cast<SIZE_T>(ExceptionInfo->ExceptionRecord->ExceptionAddress));
    LogError(error);
    std::wcout << L"Error: " << error << L"\nPress any key to exit...\n";
    std::cin.get();
    return EXCEPTION_EXECUTE_HANDLER;
}

int main() {
    SetUnhandledExceptionFilter(CrashHandler);
    AllocConsole();
    FILE* dummy;
    freopen_s(&dummy, "CONOUT$", "w", stdout);
    freopen_s(&dummy, "CONOUT$", "w", stderr);
    std::wcout.imbue(std::locale(""));

    bool result = InjectRoblox();
    std::wcout << L"Press any key to exit...\n";
    std::cin.get();
    return result ? 0 : 1;
}
