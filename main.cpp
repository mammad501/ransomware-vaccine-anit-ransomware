#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <string>
#include <thread>
#include <filesystem>
#include <shlobj.h>

namespace fs = std::filesystem;

// دستورات ممنوعه که باید شناسایی شوند
// Forbidden commands to be detected
std::string forbiddenCommands[] = {
    "wmic shadowcopy delete",
    "vssadmin delete shadows /all",
    "diskshadow",
    "delete shadows all",
    "wmic shadowcopy delete /nointeractive"
};

// بررسی اینکه آیا یک رشته شامل دستور ممنوعه است
// Check if a string contains a forbidden command
bool containsForbiddenCommand(const std::string& command) {
    for (const auto& forbiddenCommand : forbiddenCommands) {
        if (command.find(forbiddenCommand) != std::string::npos) {
            return true;
        }
    }
    return false;
}

// شناسایی PID والد
// Get the parent process ID (PID) of a process
DWORD getParentProcessId(DWORD pid) {
    DWORD ppid = -1;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                ppid = pe.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return ppid;
}

// مانیتورینگ فرآیندهای سیستم
// Monitor system processes
void monitorProcesses() {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Error creating snapshot!"; // خطا در ایجاد snapshot
        return;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32)) {
        std::cerr << "Error getting first process!"; // خطا در دریافت اولین فرآیند
        CloseHandle(hProcessSnap);
        return;
    }

    do {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
        if (hProcess != NULL) {
            char buffer[MAX_PATH];
            if (GetModuleFileNameEx(hProcess, NULL, buffer, MAX_PATH)) {
                std::string processName = buffer;

                if (processName.find("cmd.exe") != std::string::npos || processName.find("powershell.exe") != std::string::npos) {
                    std::cout << "Detected CMD or PowerShell process: " << processName << "\n";

                    // شناسایی فرآیند والد
                    // Identify the parent process
                    DWORD parentPid = getParentProcessId(pe32.th32ProcessID);
                    HANDLE hParentProcess = OpenProcess(PROCESS_TERMINATE, FALSE, parentPid);

                    if (hParentProcess != NULL) {
                        // بستن فرآیند والد
                        // Terminate the parent process
                        TerminateProcess(hParentProcess, 1);
                        CloseHandle(hParentProcess);
                    }

                    // بستن خود فرآیند (CMD یا PowerShell)
                    // Terminate the process itself (CMD or PowerShell)
                    TerminateProcess(hProcess, 1);

                    // قطع اینترنت
                    // Disconnect the internet
                    system("ipconfig /release");

                    // حذف پوشه‌های استارتاپ
                    // Delete the startup folders
                    std::cout << "Deleting startup folders...\n";
                    char userStartupPath[MAX_PATH];
                    char commonStartupPath[MAX_PATH];
                    SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, userStartupPath);
                    SHGetFolderPathA(NULL, CSIDL_COMMON_STARTUP, NULL, 0, commonStartupPath);
                    fs::remove_all(userStartupPath);
                    fs::remove_all(commonStartupPath);

                    // خاموش کردن سیستم
                    // Shutdown the system
                    std::cout << "Shutting down the system...\n";
                    system("shutdown /s /f /t 0");
                }
            }
            CloseHandle(hProcess);
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
}

int main() {
    std::cout << "Monitoring started...\n"; // شروع مانیتورینگ
    while (true) {
        monitorProcesses();
        std::this_thread::sleep_for(std::chrono::milliseconds(250)); // هر 0.25 ثانیه مانیتورینگ را انجام دهید
        // Perform monitoring every 0.25 seconds
    }
    return 0;
}
