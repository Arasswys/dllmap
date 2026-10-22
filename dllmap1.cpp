#include <iostream>
#include <string>
#include <vector>
#include <Windows.h>
#include <TlHelp32.h>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <thread>
#include <chrono>
#include <fstream>
#include <shellapi.h>
#include <set>
#include <map>
#include <stdexcept>

#pragma execution_character_set("utf-8")
#pragma warning(disable: 6387)
#pragma warning(disable: 4996)

// ========== RENKLER ==========
#define RESET     "\033[0m"
#define CYAN      "\033[36m"
#define GREEN     "\033[32m"
#define RED       "\033[31m"
#define YELLOW    "\033[33m"
#define MAGENTA   "\033[35m"
#define BOLD      "\033[1m"

#define C_DARKBLUE   "\033[38;2;0;0;170m"
#define C_LIGHTBLUE  "\033[38;2;85;85;255m"
#define C_PURPLE     "\033[38;2;170;0;170m"
#define C_GRAY       "\033[38;2;170;170;170m"
#define C_BLACK      "\033[38;2;0;0;0m"
#define BG_DARKBLUE  "\033[48;2;0;0;170m"
#define BG_GRAY      "\033[48;2;170;170;170m"
#define BG_PURPLE    "\033[48;2;170;0;170m"

// ========== NATIVE API ==========
typedef struct _MY_CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} MY_CLIENT_ID, * PMY_CLIENT_ID;

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
    HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument,
    ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
    SIZE_T MaximumStackSize, PVOID AttributeList);

typedef NTSTATUS(NTAPI* pRtlCreateUserThread)(
    HANDLE ProcessHandle, PSECURITY_DESCRIPTOR SecurityDescriptor,
    BOOLEAN CreateSuspended, ULONG StackZeroBits, PULONG StackReserved,
    PULONG StackCommit, PVOID StartAddress, PVOID StartParameter,
    PHANDLE ThreadHandle, PMY_CLIENT_ID ClientId);

// ========== GLOBAL DURUM ==========
static HHOOK   g_hHook = NULL;
static HMODULE g_hHookMod = NULL;
static int     g_logIndent = 0;

// Askıya alınan thread'ler: PID -> {TID, ...}
static std::map<DWORD, std::vector<DWORD>> g_suspendedThreads;

// ========== LOG FONKSİYONLARI ==========
static std::string Indent() { return std::string(g_logIndent * 2, ' '); }

void LogInfo(const std::string& msg) { std::cout << CYAN << Indent() << "[BILGI] " << RESET << msg << std::endl; }
void LogSuccess(const std::string& msg) { std::cout << GREEN << Indent() << "[BASARILI] " << RESET << msg << std::endl; }
void LogDebug(const std::string& msg) { std::cout << MAGENTA << Indent() << "[DEBUG] " << RESET << msg << std::endl; }
void LogStep(const std::string& msg) { std::cout << YELLOW << Indent() << "[ADIM] " << RESET << msg << std::endl; }

// LogWarn artık opsiyonel hata kodu alabiliyor (LogError gibi)
void LogWarn(const std::string& msg, DWORD errorCode = 0) {
    std::cout << YELLOW << Indent() << "[UYARI] " << RESET << msg;
    if (errorCode != 0) {
        LPWSTR buf = nullptr;
        DWORD n = FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&buf, 0, NULL);
        if (n && buf) {
            std::wstring w(buf);
            while (!w.empty() && (w.back() == L'\n' || w.back() == L'\r')) w.pop_back();
            std::wcout << L" (Kod: " << errorCode << L" - " << w << L")";
            LocalFree(buf);
        }
        else {
            std::cout << " (Kod: " << errorCode << ")";
        }
    }
    std::cout << std::endl;
}

void LogAddr(const std::string& label, const void* addr) {
    std::ostringstream ss;
    ss << label << " = 0x" << std::hex << std::uppercase << (uintptr_t)addr;
    LogDebug(ss.str());
}
void LogHex(const std::string& label, unsigned long long val) {
    std::ostringstream ss;
    ss << label << " = 0x" << std::hex << std::uppercase << val;
    LogDebug(ss.str());
}
void LogError(const std::string& msg, DWORD errorCode = 0) {
    std::cout << RED << Indent() << "[HATA] " << RESET << msg;
    if (errorCode != 0) {
        LPWSTR buf = nullptr;
        DWORD n = FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&buf, 0, NULL);
        if (n && buf) {
            std::wstring w(buf);
            while (!w.empty() && (w.back() == L'\n' || w.back() == L'\r')) w.pop_back();
            std::wcout << L" (Kod: " << errorCode << L" - " << w << L")";
            LocalFree(buf);
        }
        else {
            std::cout << " (Kod: " << errorCode << ")";
        }
    }
    std::cout << std::endl;
}

struct IndentGuard {
    IndentGuard() { g_logIndent++; }
    ~IndentGuard() { g_logIndent--; }
};

// ========== UNICODE ==========
std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), NULL, 0);
    if (len <= 0) return std::wstring(s.begin(), s.end());
    std::wstring out(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &out[0], len);
    return out;
}
std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), NULL, 0, NULL, NULL);
    if (len <= 0) return std::string(w.begin(), w.end());
    std::string out(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &out[0], len, NULL, NULL);
    return out;
}
std::wstring BaseNameW(const std::wstring& path) {
    size_t p = path.find_last_of(L"\\/");
    return (p == std::wstring::npos) ? path : path.substr(p + 1);
}
std::string HexStr(uintptr_t v) {
    std::ostringstream s; s << "0x" << std::hex << std::uppercase << v; return s.str();
}

// ========== ANİMASYONLAR ==========
void PlayScanAnimation(const std::string& label, int durationMs = 1000) {
    std::cout << YELLOW << "  " << label << " " << RESET;
    const char* frames[] = { "|", "/", "-", "\\" };
    int frameMs = 100;
    int total = durationMs / frameMs;
    for (int i = 0; i < total; ++i) {
        std::cout << "\b" << frames[i % 4] << std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(frameMs));
    }
    std::cout << "\b " << std::endl;
}

void PlayResultAnimation(bool success) {
    std::cout << "\n";
    if (success) {
        std::cout << GREEN << BOLD
            << "  +----------------------------------+\n"
            << "  |      ENJEKSIYON BASARILI!        |\n"
            << "  +----------------------------------+\n"
            << RESET;
    }
    else {
        std::cout << RED << BOLD
            << "  +----------------------------------+\n"
            << "  |      ENJEKSIYON BASARISIZ        |\n"
            << "  +----------------------------------+\n"
            << RESET;
    }
    std::cout << "\n";
}

void PlayInjectionProgressAnimation() {
    std::cout << "\n" << YELLOW << "  Hedefe igne saplaniyor..." << RESET << "\n  ";
    const char* frames[] = { "[ | ]", "[ / ]", "[ - ]", "[ \\ ]" };
    for (int i = 0; i < 8; i++) {
        std::cout << "\b\b\b\b\b" << RED << frames[i % 4] << RESET << std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
    }
    std::cout << "\b\b\b\b\b" << GREEN << "[OK] " << RESET << "\n\n";
}

void PrintAdvancedLogo() {
    std::cout << "\n";
    std::cout << C_GRAY << "       " << RESET
        << C_DARKBLUE << "█" << BG_GRAY << "▀" << RESET << C_DARKBLUE << "▄▄▄█▀" << C_GRAY << " " << C_DARKBLUE << "▄▄▄" << BG_GRAY << "▀▀▀" << RESET << C_DARKBLUE << "█" << C_GRAY << " " << C_DARKBLUE << "▄▄▄" << BG_GRAY << "▀▀▀" << RESET << C_DARKBLUE << "█" << C_GRAY << "                                                   " << RESET << "\n";
    std::cout << C_GRAY << "        " << RESET
        << C_DARKBLUE << "█" << BG_GRAY << "   " << RESET << C_DARKBLUE << "█" << C_GRAY << "   " << C_DARKBLUE << "█" << BG_GRAY << "   " << RESET << C_DARKBLUE << "█" << C_GRAY << "   " << C_DARKBLUE << "█" << BG_GRAY << "   " << RESET << C_DARKBLUE << "█" << C_GRAY << "                                                    " << RESET << "\n";
    std::cout << C_GRAY << "        " << RESET
        << C_DARKBLUE << "█" << BG_GRAY << " ░ " << RESET << C_DARKBLUE << "█" << C_GRAY << "   " << C_DARKBLUE << "█" << BG_GRAY << " ░ " << RESET << C_DARKBLUE << "█" << C_GRAY << "   " << C_DARKBLUE << "█" << BG_GRAY << " ░ " << RESET << C_DARKBLUE << "█" << C_GRAY << "    "
        << C_BLACK << BG_DARKBLUE << "▀" << C_GRAY << BG_DARKBLUE << "▄▄▄▄▄▄▄" << RESET << C_BLACK << BG_DARKBLUE << "▀" << RESET << C_DARKBLUE << "▄" << C_GRAY << BG_DARKBLUE << "▄▄▄▄▄" << RESET << C_BLACK << BG_DARKBLUE << "▀" << RESET << C_GRAY << "     " << C_DARKBLUE << "▄" << BG_GRAY << "▀▀" << RESET << C_GRAY << "▒▀▀▄" << RESET << C_DARKBLUE << "█" << C_GRAY << BG_DARKBLUE << "▄▄" << RESET << C_DARKBLUE << "▄▄▄" << C_GRAY << "   " << RESET << C_BLACK << BG_DARKBLUE << "▀" << RESET << C_GRAY << BG_DARKBLUE << "▄▄▄▄▄▄▄" << RESET << C_BLACK << BG_DARKBLUE << "▀" << RESET << C_GRAY << "  " << RESET << "\n";
    std::cout << C_GRAY << "    " << RESET
        << C_DARKBLUE << "▄▄▄" << C_GRAY << " " << RESET << C_DARKBLUE << "█" << BG_GRAY << "░▒░" << RESET << C_DARKBLUE << "█" << C_GRAY << "   " << C_DARKBLUE << "█" << BG_GRAY << "░▒░" << RESET << C_DARKBLUE << "█" << C_GRAY << "   " << C_DARKBLUE << "█" << BG_GRAY << "░▒░" << RESET << C_DARKBLUE << "█" << C_GRAY << "   " << RESET << C_DARKBLUE << "█" << C_GRAY << BG_DARKBLUE << "█▓█" << RESET << C_DARKBLUE << "█▀█" << C_GRAY << BG_DARKBLUE << "█▓██▒" << RESET << C_DARKBLUE << "██" << C_GRAY << BG_DARKBLUE << "█▓█" << RESET << C_DARKBLUE << "█" << C_GRAY << "   " << C_DARKBLUE << "█" << BG_GRAY << " ░ " << RESET << C_DARKBLUE << "█" << C_GRAY << "   ░" << RESET << C_GRAY << BG_DARKBLUE << "█▓█" << RESET << C_DARKBLUE << "█" << C_GRAY << "   " << C_DARKBLUE << "█" << C_GRAY << BG_DARKBLUE << "█▓█" << RESET << C_DARKBLUE << "█▀█" << C_GRAY << BG_DARKBLUE << "█▓█" << RESET << C_DARKBLUE << "█" << C_GRAY << " " << RESET << "\n";
    std::cout << C_GRAY << " " << RESET
        << C_DARKBLUE << "▄" << C_GRAY << BG_DARKBLUE << "▄" << RESET << C_DARKBLUE << BG_GRAY << "▀▀" << RESET << C_GRAY << BG_DARKBLUE << "▀▀▄" << RESET << C_DARKBLUE << "█" << BG_GRAY << "▒▓▒" << RESET << C_DARKBLUE << "█" << C_GRAY << "   " << C_DARKBLUE << "█" << BG_GRAY << "▒▓▒" << RESET << C_DARKBLUE << "█" << C_GRAY << "   " << C_DARKBLUE << "█" << BG_GRAY << "▒▓▒" << RESET << C_DARKBLUE << "█" << C_GRAY << "  " << RESET << C_DARKBLUE << "█" << C_GRAY << BG_DARKBLUE << "▓▒▓ " << RESET << C_DARKBLUE << "▌" << C_GRAY << " " << RESET << C_DARKBLUE << "▐" << C_GRAY << BG_DARKBLUE << " ▓▒▓" << RESET << C_DARKBLUE << "█▌▐" << C_GRAY << BG_DARKBLUE << " ▓▒▓" << RESET << C_DARKBLUE << "█" << C_GRAY << " " << RESET << C_DARKBLUE << "█" << BG_GRAY << "░▒░" << RESET << C_DARKBLUE << "█" << C_GRAY << "    " << RESET << C_DARKBLUE << "█" << C_GRAY << BG_DARKBLUE << "▓▒▓" << RESET << C_DARKBLUE << "█" << C_GRAY << "  " << RESET << C_DARKBLUE << "█" << C_GRAY << BG_DARKBLUE << "▓▒▓ " << RESET << C_GRAY << "   " << RESET << C_GRAY << BG_DARKBLUE << " ▓▒▓" << RESET << C_DARKBLUE << "█" << RESET << "\n";
    std::cout << C_PURPLE << BG_DARKBLUE << "░" << RESET << C_DARKBLUE << BG_GRAY << " ▒░" << RESET << C_DARKBLUE << "█" << C_GRAY << "  " << RESET << C_DARKBLUE << "██" << BG_GRAY << "▓█▓" << RESET << C_DARKBLUE << "█" << C_GRAY << "   " << C_DARKBLUE << "█" << BG_GRAY << "▓█▓" << RESET << C_PURPLE << BG_DARKBLUE << "░" << RESET << C_GRAY << "   " << RESET << C_DARKBLUE << "█" << BG_GRAY << "▓█▓" << RESET << C_PURPLE << BG_DARKBLUE << "░" << RESET << C_GRAY << "  " << RESET << C_DARKBLUE << "█" << C_GRAY << BG_DARKBLUE << "▒░▒" << RESET << C_DARKBLUE << "▓" << C_GRAY << "   " << RESET << C_DARKBLUE << "▓" << C_GRAY << BG_DARKBLUE << "▒░▒" << RESET << C_DARKBLUE << "█" << C_GRAY << "  " << RESET << C_DARKBLUE << "▓" << C_GRAY << BG_DARKBLUE << "▒░▒" << RESET << C_DARKBLUE << "█" << C_GRAY << " " << RESET << C_DARKBLUE << "█" << BG_GRAY << "▒▓▒" << RESET << C_DARKBLUE << "█" << C_GRAY << "    " << RESET << C_DARKBLUE << "█" << C_GRAY << BG_DARKBLUE << "▒░▒" << RESET << C_PURPLE << BG_DARKBLUE << "░" << RESET << C_GRAY << "  " << RESET << C_DARKBLUE << "█" << C_GRAY << BG_DARKBLUE << "▒░▒" << RESET << C_DARKBLUE << "▓" << C_GRAY << "   " << RESET << C_DARKBLUE << "▓" << C_GRAY << BG_DARKBLUE << "▒░▒" << RESET << C_DARKBLUE << "█" << RESET << "\n";
    std::cout << C_GRAY << BG_DARKBLUE << "▐" << RESET << C_DARKBLUE << BG_GRAY << "░▓▒" << RESET << C_DARKBLUE << "▌" << C_GRAY << "  " << RESET << C_DARKBLUE << "▐" << RESET << C_PURPLE << BG_DARKBLUE << "░" << RESET << C_DARKBLUE << "\033[48;2;170;85;0m█" << RESET << C_LIGHTBLUE << BG_DARKBLUE << "░" << RESET << C_DARKBLUE << BG_GRAY << "█" << RESET << C_DARKBLUE << "█▌" << C_GRAY << "  " << RESET << C_DARKBLUE << "█" << BG_DARKBLUE << " " << RESET << C_LIGHTBLUE << BG_DARKBLUE << "░ " << RESET << C_PURPLE << BG_DARKBLUE << "▒" << RESET << C_GRAY << "   " << RESET << C_DARKBLUE << "█" << BG_DARKBLUE << " " << RESET << C_LIGHTBLUE << BG_DARKBLUE << "░ " << RESET << C_PURPLE << BG_DARKBLUE << "▒" << RESET << C_GRAY << "  " << RESET << C_DARKBLUE << "█" << C_GRAY << BG_DARKBLUE << "░ ░" << RESET << C_DARKBLUE << "▓" << C_GRAY << "   " << RESET << C_DARKBLUE << "▓" << C_GRAY << BG_DARKBLUE << "░ ░" << RESET << C_DARKBLUE << "█" << C_GRAY << "  " << RESET << C_DARKBLUE << "▓" << C_GRAY << BG_DARKBLUE << "░ ░" << RESET << C_DARKBLUE << "█" << C_GRAY << " " << RESET << C_DARKBLUE << "█" << BG_GRAY << "▓█▓" << RESET << C_DARKBLUE << "█" << C_GRAY << "    " << RESET << C_DARKBLUE << "█" << C_GRAY << BG_DARKBLUE << "░ ░" << RESET << C_PURPLE << BG_DARKBLUE << "▒" << RESET << C_GRAY << "  " << RESET << C_DARKBLUE << "█" << C_GRAY << BG_DARKBLUE << "░ ░" << RESET << C_DARKBLUE << "▓" << C_GRAY << "   " << RESET << C_DARKBLUE << "▓" << C_GRAY << BG_DARKBLUE << "░ ░" << RESET << C_DARKBLUE << "█" << RESET << "\n";
    std::cout << C_PURPLE << BG_DARKBLUE << "▓" << RESET << C_DARKBLUE << BG_GRAY << "▓" << RESET << C_DARKBLUE << BG_DARKBLUE << " " << RESET << C_DARKBLUE << BG_GRAY << "▓▓" << RESET << C_GRAY << "   " << RESET << C_PURPLE << BG_DARKBLUE << "▒" << RESET << C_LIGHTBLUE << BG_DARKBLUE << "░▒░" << RESET << C_DARKBLUE << "█▌" << C_GRAY << "  " << RESET << C_DARKBLUE << "█" << C_LIGHTBLUE << BG_DARKBLUE << "░▒░" << RESET << C_PURPLE << BG_DARKBLUE << "▓" << RESET << C_GRAY << "   " << RESET << C_DARKBLUE << "█" << C_LIGHTBLUE << BG_DARKBLUE << "░▒░" << RESET << C_PURPLE << BG_DARKBLUE << "▓" << RESET << C_GRAY << "  " << RESET << C_DARKBLUE << "██" << C_DARKBLUE << BG_DARKBLUE << " " << RESET << C_LIGHTBLUE << BG_DARKBLUE << "░░" << RESET << C_GRAY << "   " << RESET << C_LIGHTBLUE << BG_DARKBLUE << "░░" << RESET << C_DARKBLUE << BG_DARKBLUE << " " << RESET << C_DARKBLUE << "██" << C_GRAY << "  " << RESET << C_LIGHTBLUE << BG_DARKBLUE << "░░" << RESET << C_DARKBLUE << BG_DARKBLUE << " " << RESET << C_DARKBLUE << "██" << C_GRAY << "  " << RESET << C_DARKBLUE << "█" << C_LIGHTBLUE << BG_DARKBLUE << "░▒░ " << RESET << C_DARKBLUE << "▄" << C_GRAY << " " << RESET << C_PURPLE << "▄" << RESET << C_DARKBLUE << "█" << BG_DARKBLUE << " " << RESET << C_LIGHTBLUE << BG_DARKBLUE << "░ " << RESET << C_PURPLE << BG_DARKBLUE << "▓" << RESET << C_GRAY << "  " << RESET << C_DARKBLUE << "██" << BG_DARKBLUE << " " << RESET << C_LIGHTBLUE << BG_DARKBLUE << "░▒ " << RESET << C_DARKBLUE << "▄" << RESET << C_LIGHTBLUE << BG_DARKBLUE << " ▒░" << RESET << C_DARKBLUE << BG_DARKBLUE << " " << RESET << C_DARKBLUE << "█" << C_GRAY << " " << RESET << "\n";
    std::cout << C_GRAY << " " << RESET
        << C_BLACK << BG_PURPLE << "▄" << RESET << C_DARKBLUE << BG_PURPLE << "▀▀▀▀" << RESET << C_PURPLE << BG_DARKBLUE << "▄▄▄" << RESET << C_DARKBLUE << BG_PURPLE << "▀" << RESET << C_LIGHTBLUE << BG_PURPLE << "▀" << RESET << C_PURPLE << "▀▀" << C_GRAY << "   " << RESET << C_DARKBLUE << "█" << BG_PURPLE << "▀▀▀ " << RESET << C_GRAY << "   " << RESET << C_DARKBLUE << "█" << BG_PURPLE << "▀▀▀ " << RESET << C_GRAY << "  " << RESET << C_PURPLE << BG_DARKBLUE << "▄▄" << RESET << C_PURPLE << "▀" << RESET << C_PURPLE << BG_DARKBLUE << "▄▄" << RESET << C_GRAY << "   " << RESET << C_PURPLE << BG_DARKBLUE << "▄▄" << RESET << C_PURPLE << "▀" << RESET << C_PURPLE << BG_DARKBLUE << "▄▄" << RESET << C_GRAY << "  " << RESET << C_PURPLE << BG_DARKBLUE << "▄▄" << RESET << C_PURPLE << "▀" << RESET << C_PURPLE << BG_DARKBLUE << "▄▄" << RESET << C_GRAY << "    " << RESET << C_DARKBLUE << "▀" << RESET << C_PURPLE << "▀▀▀▀" << C_GRAY << "  " << RESET << C_PURPLE << "▀■" << RESET << C_PURPLE << BG_DARKBLUE << "▄" << RESET << C_PURPLE << "█▄" << C_GRAY << " " << RESET << C_DARKBLUE << "█" << C_GRAY << BG_DARKBLUE << "░" << RESET << C_DARKBLUE << "█" << C_GRAY << BG_DARKBLUE << "░" << RESET << C_PURPLE << BG_DARKBLUE << "■▄" << RESET << C_PURPLE << "■" << RESET << C_PURPLE << BG_DARKBLUE << "▄▄▄" << RESET << C_PURPLE << "▀" << C_GRAY << "  " << RESET << "\n";
    std::cout << C_GRAY << "               " << RESET
        << C_DARKBLUE << "▀▀" << C_GRAY << "      " << RESET << C_DARKBLUE << "▀▀" << C_GRAY << "                                           " << RESET << C_DARKBLUE << "█" << C_GRAY << BG_DARKBLUE << "▒" << RESET << C_DARKBLUE << "█" << C_GRAY << BG_DARKBLUE << "▒" << RESET << C_DARKBLUE << "█" << C_GRAY << "        " << RESET << "\n";
    std::cout << C_GRAY << "                                                                    " << RESET
        << C_DARKBLUE << "█" << C_GRAY << BG_DARKBLUE << "▓▄▓" << RESET << C_DARKBLUE << "█" << C_GRAY << "        " << RESET << "\n";
    std::cout << C_GRAY << "                                                                    " << RESET
        << C_DARKBLUE << "▀▀▀▀▀" << C_GRAY << "        " << RESET << "\n";
    std::cout << "\n";
}

// ========== UAC ==========
bool IsRunAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin == TRUE;
}

void ElevateUAC() {
    LogStep("Yonetici haklari kontrol ediliyor...");
    if (IsRunAsAdmin()) {
        LogSuccess("Zaten yonetici olarak calisiyor.");
        return;
    }
    LogWarn("Yonetici izni yok. UAC ile yeniden baslatiliyor...");
    wchar_t szPath[MAX_PATH];
    GetModuleFileNameW(NULL, szPath, MAX_PATH);
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas";
    sei.lpFile = szPath;
    sei.hwnd = NULL;
    sei.nShow = SW_NORMAL;
    if (!ShellExecuteExW(&sei)) {
        LogError("UAC izni reddedildi veya hata olustu.", GetLastError());
        std::cout << "\nDevam etmek icin Enter'a basin...";
        std::cin.get();
        exit(1);
    }
    exit(0);
}

// ========== MİMARİ TESPİTİ ==========
enum class Arch { Unknown, X86, X64, Arm64, Arm32 };

static Arch ClassifyMachine(USHORT machine) {
    switch (machine) {
    case IMAGE_FILE_MACHINE_I386:  return Arch::X86;
    case IMAGE_FILE_MACHINE_AMD64: return Arch::X64;
    case IMAGE_FILE_MACHINE_ARM64: return Arch::Arm64;
    case IMAGE_FILE_MACHINE_ARMNT: return Arch::Arm32;
    default: return Arch::Unknown;
    }
}

const char* ArchName(Arch a) {
    switch (a) {
    case Arch::X86:   return "x86 (32-bit)";
    case Arch::X64:   return "x64 (64-bit)";
    case Arch::Arm64: return "ARM64";
    case Arch::Arm32: return "ARM32";
    default:          return "bilinmiyor";
    }
}

Arch GetProcessArch(DWORD pid) {
    LogDebug("Mimari sorgusu basladi (PID=" + std::to_string(pid) + ")");
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) {
        LogError("OpenProcess (mimari sorgusu) basarisiz.", GetLastError());
        return Arch::Unknown;
    }
    LogAddr("Process handle", hProc);

    Arch result = Arch::Unknown;
    typedef BOOL(WINAPI* pIsWow64Process2)(HANDLE, USHORT*, USHORT*);
    auto fn2 = (pIsWow64Process2)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2");

    bool wow2Succeeded = false;
    if (fn2) {
        LogDebug("IsWow64Process2 mevcut, kullaniliyor.");
        USHORT procMachine = 0, nativeMachine = 0;
        BOOL ok = fn2(hProc, &procMachine, &nativeMachine);
        LogHex("IsWow64Process2 procMachine", procMachine);
        LogHex("IsWow64Process2 nativeMachine", nativeMachine);
        if (ok) {
            wow2Succeeded = true;
            if (procMachine == IMAGE_FILE_MACHINE_UNKNOWN) {
                LogDebug("Native process (WOW64 degil) -> nativeMachine kullaniliyor.");
                result = ClassifyMachine(nativeMachine);
            }
            else {
                LogDebug("WOW64 altinda calisan process -> procMachine kullaniliyor.");
                result = ClassifyMachine(procMachine);
            }
        }
        else {
            LogWarn("IsWow64Process2 basarisiz. IsWow64Process fallback kullanilacak.", GetLastError());
        }
    }

    if (!wow2Succeeded) {
        LogWarn("IsWow64Process fallback kullaniliyor.");
        BOOL wow = FALSE;
        if (IsWow64Process(hProc, &wow)) {
            LogDebug(std::string("IsWow64Process = ") + (wow ? "TRUE" : "FALSE"));
            result = wow ? Arch::X86 : Arch::X64;
        }
        else {
            LogError("IsWow64Process basarisiz.", GetLastError());
        }
    }

    CloseHandle(hProc);
    LogDebug("Sonuc mimari: " + std::string(ArchName(result)));
    return result;
}

Arch GetDllArch(const std::wstring& dllPath) {
    LogDebug("DLL mimari sorgusu basladi: " + WideToUtf8(dllPath));
    std::ifstream f(dllPath, std::ios::binary);
    if (!f) { LogError("DLL dosyasi acilamadi (mimari sorgusu)."); return Arch::Unknown; }

    IMAGE_DOS_HEADER dos{};
    f.read((char*)&dos, sizeof(dos));
    if (!f) { LogError("DOS header okunamadi."); return Arch::Unknown; }
    LogHex("DOS e_magic", dos.e_magic);
    LogHex("DOS e_lfanew", dos.e_lfanew);
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        LogError("Gecersiz DOS imzasi (MZ bekleniyordu).");
        return Arch::Unknown;
    }

    f.seekg(dos.e_lfanew);
    DWORD sig = 0;
    f.read((char*)&sig, sizeof(sig));
    LogHex("NT signature", sig);
    if (!f || sig != IMAGE_NT_SIGNATURE) {
        LogError("Gecersiz NT imzasi (PE bekleniyordu).");
        return Arch::Unknown;
    }

    IMAGE_FILE_HEADER fh{};
    f.read((char*)&fh, sizeof(fh));
    if (!f) { LogError("File header okunamadi."); return Arch::Unknown; }
    LogHex("Machine", fh.Machine);
    LogDebug("Characteristics = 0x" + HexStr(fh.Characteristics));
    LogDebug("SizeOfOptionalHeader = " + std::to_string(fh.SizeOfOptionalHeader));

    Arch a = ClassifyMachine(fh.Machine);
    LogDebug("Sonuc DLL mimarisi: " + std::string(ArchName(a)));
    return a;
}

bool CheckArchitecture(DWORD pid, const std::wstring& dllPath) {
    LogStep("Mimari uyumlulugu kontrol ediliyor...");
    Arch pa = GetProcessArch(pid);
    Arch da = GetDllArch(dllPath);
    std::ostringstream ss;
    ss << "Hedef process mimarisi: " << ArchName(pa)
        << " | DLL mimarisi: " << ArchName(da);
    LogInfo(ss.str());
    if (pa == Arch::Unknown) { LogError("Hedef surecin mimarisi tespit edilemedi. Iptal."); return false; }
    if (da == Arch::Unknown) { LogError("DLL mimarisi tespit edilemedi. Iptal."); return false; }
    if (pa != da) {
        LogError("Mimari uyumsuzlugu! Process=" + std::string(ArchName(pa)) +
            " DLL=" + std::string(ArchName(da)));
        return false;
    }
    LogSuccess("Mimari uyumlu (" + std::string(ArchName(pa)) + ")");
    return true;
}

// ========== HEDEF SÜREÇ ==========
DWORD GetTargetProcess() {
    std::string targetInput;
    std::cout << CYAN << "Hedef Process Adi veya PID Girin: " << RESET;
    std::getline(std::cin, targetInput);
    targetInput.erase(0, targetInput.find_first_not_of(" \t\r\n"));
    targetInput.erase(targetInput.find_last_not_of(" \t\r\n") + 1);
    if (targetInput.empty()) { LogError("Bos giris."); return 0; }

    bool isNumeric = !targetInput.empty() &&
        std::all_of(targetInput.begin(), targetInput.end(), ::isdigit);
    LogDebug(std::string("Giris tipi: ") + (isNumeric ? "PID" : "process adi"));

    if (isNumeric) {
        if (targetInput.length() > 10) { LogError("PID cok buyuk."); return 0; }
        unsigned long long v = 0;
        try { v = std::stoull(targetInput); }
        catch (const std::out_of_range&) { LogError("PID sayisal olarak tasma yapti."); return 0; }
        catch (...) { LogError("PID ayristirilamadi."); return 0; }
        if (v == 0 || v > 0xFFFFFFFFull) { LogError("Gecersiz PID araligi."); return 0; }
        DWORD pid = (DWORD)v;
        LogDebug("PID dogrulaniyor: " + std::to_string(pid));
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!h) { LogError("PID " + std::to_string(pid) + " gecerli bir surece ait degil.", GetLastError()); return 0; }
        DWORD sessionId = 0;
        ProcessIdToSessionId(pid, &sessionId);
        LogDebug("Process SessionID = " + std::to_string(sessionId));
        CloseHandle(h);
        LogSuccess("PID dogrulandi: " + std::to_string(pid));
        return pid;
    }

    std::wstring wTargetName = Utf8ToWide(targetInput);
    if (wTargetName.find(L'.') == std::wstring::npos) {
        wTargetName += L".exe";
        LogDebug("Uzanti eklendi: " + WideToUtf8(wTargetName));
    }

    LogDebug("Surec listesi taraniyor...");
    std::vector<std::pair<DWORD, std::wstring>> matches;
    PROCESSENTRY32W pe{ sizeof(pe) };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) { LogError("Snapshot alinamadi.", GetLastError()); return 0; }

    int totalScanned = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            totalScanned++;
            if (_wcsicmp(wTargetName.c_str(), pe.szExeFile) == 0)
                matches.push_back({ pe.th32ProcessID, pe.szExeFile });
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    LogDebug(std::to_string(totalScanned) + " surec tarandi, " + std::to_string(matches.size()) + " eslesme bulundu.");

    if (matches.empty()) { LogError("Belirtilen isimde process bulunamadi."); return 0; }
    if (matches.size() == 1) {
        LogSuccess("Process bulundu! PID: " + std::to_string(matches[0].first));
        return matches[0].first;
    }

    LogWarn(std::to_string(matches.size()) + " eslesme bulundu:");
    for (size_t i = 0; i < matches.size(); ++i)
        std::cout << "  [" << (i + 1) << "] PID: " << matches[i].first
        << " (" << WideToUtf8(matches[i].second) << ")\n";
    std::cout << CYAN << "Secim (1-" << matches.size() << "): " << RESET;
    std::string sel; std::getline(std::cin, sel);
    try {
        size_t idx = std::stoul(sel);
        if (idx < 1 || idx > matches.size()) { LogError("Gecersiz secim."); return 0; }
        LogSuccess("Secilen PID: " + std::to_string(matches[idx - 1].first));
        return matches[idx - 1].first;
    }
    catch (const std::out_of_range&) { LogError("Secim sayisal olarak tasma yapti."); return 0; }
    catch (const std::invalid_argument&) { LogError("Gecersiz secim (sayi degil)."); return 0; }
    catch (...) { LogError("Gecersiz secim."); return 0; }
}

// ========== MODÜL YARDIMCILARI ==========
bool IsModuleLoadedInProcess(DWORD pid, const std::wstring& dllFileName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W me{ sizeof(me) };
    bool found = false;
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, dllFileName.c_str()) == 0) { found = true; break; }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

// ========== ORTAK: Thread sonucu doğrulama ==========
static bool WaitThreadAndVerifyLibrary(HANDLE hThread, DWORD timeoutMs) {
    LogDebug("Thread tamamlanmasi bekleniyor (timeout=" + std::to_string(timeoutMs) + " ms)...");
    DWORD wait = WaitForSingleObject(hThread, timeoutMs);
    if (wait == WAIT_TIMEOUT) {
        LogError("Thread zaman asimina ugradi (timeout=" + std::to_string(timeoutMs) + " ms).");
        return false;
    }
    if (wait != WAIT_OBJECT_0) {
        LogError("WaitForSingleObject basarisiz.", GetLastError());
        return false;
    }
    LogDebug("Thread tamamlandi.");

    DWORD exitCode = 0;
    if (!GetExitCodeThread(hThread, &exitCode)) {
        LogError("GetExitCodeThread basarisiz.", GetLastError());
        return false;
    }
    LogHex("Thread cikis kodu (HMODULE)", exitCode);
    if (exitCode == 0) {
        LogError("LoadLibraryW basarisiz (exit code 0). DLL yuklenmedi.");
        return false;
    }
    LogSuccess("LoadLibraryW basarili (HMODULE=0x" + HexStr(exitCode) + ")");
    return true;
}

// ========== YÖNTEM 1: CreateRemoteThread ==========
bool Method_CreateRemoteThread(DWORD pid, const std::wstring& dllPath) {
    IndentGuard ig;
    LogStep("[Yontem 1] CreateRemoteThread baslatiliyor...");

    LogDebug("OpenProcess cagriliyor (izinler: CREATE_THREAD|QUERY|VM_OPERATION|VM_WRITE|VM_READ)");
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProcess) { LogError("OpenProcess basarisiz.", GetLastError()); return false; }
    LogAddr("Process handle", hProcess);

    size_t size = (dllPath.length() + 1) * sizeof(wchar_t);
    LogDebug("DLL yolu icin ayrilacak boyut: " + std::to_string(size) + " byte (UTF-16)");
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) { LogError("VirtualAllocEx basarisiz.", GetLastError()); CloseHandle(hProcess); return false; }
    LogAddr("VirtualAllocEx uzak bellek", remoteMem);

    LogDebug("WriteProcessMemory cagriliyor...");
    if (!WriteProcessMemory(hProcess, remoteMem, dllPath.c_str(), size, NULL)) {
        LogError("WriteProcessMemory basarisiz.", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE); CloseHandle(hProcess); return false;
    }
    LogDebug("DLL yolu hedef surece yazildi (" + std::to_string(size) + " byte).");

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LogAddr("Yerel kernel32.dll base", hKernel32);
    auto loadLib = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
    if (!loadLib) {
        LogError("LoadLibraryW adresi alinamadi.", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE); CloseHandle(hProcess); return false;
    }
    LogAddr("LoadLibraryW adresi", (const void*)loadLib);

    LogDebug("CreateRemoteThread cagriliyor...");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, loadLib, remoteMem, 0, NULL);
    if (!hThread) {
        LogError("CreateRemoteThread basarisiz.", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE); CloseHandle(hProcess); return false;
    }
    LogAddr("Uzak thread handle", hThread);

    bool ok = WaitThreadAndVerifyLibrary(hThread, 10000);

    LogDebug("Uzak bellek serbest birakiliyor...");
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    LogDebug("Kaynaklar temizlendi.");
    return ok;
}

// ========== YÖNTEM 2: NtCreateThreadEx ==========
bool Method_NtCreateThreadEx(DWORD pid, const std::wstring& dllPath) {
    IndentGuard ig;
    LogStep("[Yontem 2] NtCreateThreadEx baslatiliyor...");

    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProcess) { LogError("OpenProcess basarisiz.", GetLastError()); return false; }
    LogAddr("Process handle", hProcess);

    size_t size = (dllPath.length() + 1) * sizeof(wchar_t);
    LogDebug("Ayrilacak bellek boyutu: " + std::to_string(size) + " byte");
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) { LogError("VirtualAllocEx basarisiz.", GetLastError()); CloseHandle(hProcess); return false; }
    LogAddr("VirtualAllocEx uzak bellek", remoteMem);

    if (!WriteProcessMemory(hProcess, remoteMem, dllPath.c_str(), size, NULL)) {
        LogError("WriteProcessMemory basarisiz.", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE); CloseHandle(hProcess); return false;
    }
    LogDebug("DLL yolu yazildi.");

    auto loadLib = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    LogAddr("LoadLibraryW adresi", (const void*)loadLib);

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    LogAddr("ntdll.dll base", hNtdll);
    auto fn = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    if (!fn) {
        LogError("NtCreateThreadEx bulunamadi.");
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE); CloseHandle(hProcess); return false;
    }
    LogAddr("NtCreateThreadEx adresi", (const void*)fn);

    HANDLE hThread = NULL;
    LogDebug("NtCreateThreadEx cagriliyor...");
    NTSTATUS st = fn(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, loadLib, remoteMem, 0, 0, 0, 0, NULL);
    LogHex("NTSTATUS", (unsigned long long)st);
    if (st != 0 || !hThread) {
        LogError("NtCreateThreadEx basarisiz.");
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE); CloseHandle(hProcess); return false;
    }
    LogAddr("Uzak thread handle", hThread);

    bool ok = WaitThreadAndVerifyLibrary(hThread, 10000);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hThread); CloseHandle(hProcess);
    LogDebug("Kaynaklar temizlendi.");
    return ok;
}

// ========== YÖNTEM 3: RtlCreateUserThread ==========
bool Method_RtlCreateUserThread(DWORD pid, const std::wstring& dllPath) {
    IndentGuard ig;
    LogStep("[Yontem 3] RtlCreateUserThread baslatiliyor...");

    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProcess) { LogError("OpenProcess basarisiz.", GetLastError()); return false; }
    LogAddr("Process handle", hProcess);

    size_t size = (dllPath.length() + 1) * sizeof(wchar_t);
    LogDebug("Ayrilacak bellek boyutu: " + std::to_string(size) + " byte");
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) { LogError("VirtualAllocEx basarisiz.", GetLastError()); CloseHandle(hProcess); return false; }
    LogAddr("VirtualAllocEx uzak bellek", remoteMem);

    if (!WriteProcessMemory(hProcess, remoteMem, dllPath.c_str(), size, NULL)) {
        LogError("WriteProcessMemory basarisiz.", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE); CloseHandle(hProcess); return false;
    }
    LogDebug("DLL yolu yazildi.");

    auto loadLib = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    LogAddr("LoadLibraryW adresi", (const void*)loadLib);

    auto fn = (pRtlCreateUserThread)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserThread");
    if (!fn) {
        LogError("RtlCreateUserThread bulunamadi.");
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE); CloseHandle(hProcess); return false;
    }
    LogAddr("RtlCreateUserThread adresi", (const void*)fn);

    HANDLE hThread = NULL; MY_CLIENT_ID cid{};
    LogDebug("RtlCreateUserThread cagriliyor...");
    NTSTATUS st = fn(hProcess, NULL, FALSE, 0, 0, 0, loadLib, remoteMem, &hThread, &cid);
    LogHex("NTSTATUS", (unsigned long long)st);
    if (st != 0 || !hThread) {
        LogError("RtlCreateUserThread basarisiz.");
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE); CloseHandle(hProcess); return false;
    }
    LogAddr("Uzak thread handle", hThread);
    LogHex("ClientId.UniqueThread", (unsigned long long)(uintptr_t)cid.UniqueThread);

    bool ok = WaitThreadAndVerifyLibrary(hThread, 10000);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hThread); CloseHandle(hProcess);
    LogDebug("Kaynaklar temizlendi.");
    return ok;
}

// ========== YÖNTEM 4: QueueUserAPC ==========
bool Method_QueueUserAPC(DWORD pid, const std::wstring& dllPath) {
    IndentGuard ig;
    LogStep("[Yontem 4] QueueUserAPC baslatiliyor...");

    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
    if (!hProcess) { LogError("OpenProcess basarisiz.", GetLastError()); return false; }
    LogAddr("Process handle", hProcess);

    size_t size = (dllPath.length() + 1) * sizeof(wchar_t);
    LogDebug("Ayrilacak bellek boyutu: " + std::to_string(size) + " byte");
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) { LogError("VirtualAllocEx basarisiz.", GetLastError()); CloseHandle(hProcess); return false; }
    LogAddr("VirtualAllocEx uzak bellek", remoteMem);

    if (!WriteProcessMemory(hProcess, remoteMem, dllPath.c_str(), size, NULL)) {
        LogError("WriteProcessMemory basarisiz.", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE); CloseHandle(hProcess); return false;
    }
    LogDebug("DLL yolu yazildi.");

    auto loadLib = (PAPCFUNC)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    LogAddr("LoadLibraryW adresi (APC)", (const void*)loadLib);

    LogDebug("Thread listesi aliniyor...");
    THREADENTRY32 te{ sizeof(te) };
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        LogError("Thread snapshot alinamadi.", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE); CloseHandle(hProcess); return false;
    }

    int queuedCount = 0;
    int totalThreads = 0;
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            totalThreads++;
            LogDebug("Thread bulundu: TID=" + std::to_string(te.th32ThreadID));
            HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
            if (hThread) {
                if (QueueUserAPC(loadLib, hThread, (ULONG_PTR)remoteMem)) {
                    queuedCount++;
                    LogDebug("  -> APC kuyruguna eklendi.");
                }
                else {
                    LogWarn("  -> QueueUserAPC basarisiz.", GetLastError());
                }
                CloseHandle(hThread);
            }
            else {
                LogWarn("  -> OpenThread basarisiz.", GetLastError());
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);

    LogInfo(std::to_string(totalThreads) + " thread tarandi, " + std::to_string(queuedCount) + " tanesine APC eklendi.");

    if (queuedCount == 0) {
        LogError("Hicbir thread'e APC kuyruklanamadi.");
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE); CloseHandle(hProcess); return false;
    }

    std::wstring dllName = BaseNameW(dllPath);
    LogInfo("DLL'in yuklenmesi bekleniyor (polling, modul adi: " + WideToUtf8(dllName) + ")...");
    bool loaded = false;
    const int maxTries = 30;
    for (int i = 0; i < maxTries; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        if (IsModuleLoadedInProcess(pid, dllName)) {
            loaded = true;
            LogDebug("Deneme #" + std::to_string(i + 1) + ": DLL yuklu bulundu!");
            break;
        }
        LogDebug("Deneme #" + std::to_string(i + 1) + "/" + std::to_string(maxTries) + ": DLL henuz yuklu degil.");
    }

    if (loaded) {
        LogSuccess("DLL hedef surecte yuklendi olarak dogrulandi.");
        LogDebug("Uzak bellek serbest birakiliyor (yukleme dogrulandi).");
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    }
    else {
        LogError("APC kuyruklandi ancak DLL'in yuklendigi dogrulanamadi.");
        LogWarn("Bellek serbest BIRAKILMIYOR (pending APC riski). Hedef surec kapaninca Windows temizler.");
        LogWarn("Uzak bellek adresi (sizinti): " + HexStr((uintptr_t)remoteMem));
    }

    CloseHandle(hProcess);
    return loaded;
}

// ========== YÖNTEM 5: SetWindowsHookEx ==========
bool Method_SetWindowsHookEx(DWORD pid, const std::wstring& dllPath) {
    IndentGuard ig;
    LogStep("[Yontem 5] SetWindowsHookEx baslatiliyor...");

    if (g_hHook) {
        LogDebug("Onceki hook temizleniyor...");
        UnhookWindowsHookEx(g_hHook);
        g_hHook = NULL;
    }
    if (g_hHookMod) { FreeLibrary(g_hHookMod); g_hHookMod = NULL; }

    LogDebug("DLL kendi surecimize yukleniyor (hook icin gerekli): " + WideToUtf8(dllPath));
    HMODULE hMod = LoadLibraryW(dllPath.c_str());
    if (!hMod) { LogError("DLL kendi surecimize yuklenemedi.", GetLastError()); return false; }
    LogAddr("Yerel DLL modul handle", hMod);

    LogDebug("GetMsgProc export'u araniyor...");
    FARPROC proc = GetProcAddress(hMod, "GetMsgProc");
    if (!proc) {
        LogError("DLL'de 'GetMsgProc' export'u yok. Hook kurulamaz.");
        LogWarn("Bu yontem icin DLL'de GetMsgProc fonksiyonu export edilmis olmalidir.");
        FreeLibrary(hMod);
        return false;
    }
    LogAddr("GetMsgProc adresi", (const void*)proc);

    LogDebug("Hedef surecte thread araniyor...");
    THREADENTRY32 te{ sizeof(te) };
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        LogError("Thread snapshot alinamadi.", GetLastError());
        FreeLibrary(hMod); return false;
    }
    DWORD tid = 0;
    int totalThreads = 0;
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            totalThreads++;
            if (tid == 0) tid = te.th32ThreadID;
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    LogDebug("Toplam " + std::to_string(totalThreads) + " thread bulundu.");
    if (!tid) { LogError("Hedef surecte thread bulunamadi."); FreeLibrary(hMod); return false; }
    LogDebug("Hook kurulacak thread ID: " + std::to_string(tid));

    LogDebug("SetWindowsHookExW(WH_GETMESSAGE) cagriliyor...");
    HHOOK h = SetWindowsHookExW(WH_GETMESSAGE, (HOOKPROC)proc, hMod, tid);
    if (!h) {
        LogError("SetWindowsHookEx basarisiz.", GetLastError());
        FreeLibrary(hMod);
        return false;
    }
    LogAddr("HHOOK", h);

    g_hHook = h;
    g_hHookMod = hMod;

    LogInfo("Hook kuruldu. DLL'in hedef surecte yuklenmesi bekleniyor (mesaj tetiklemesi gerekli)...");
    std::wstring dllName = BaseNameW(dllPath);
    bool loaded = false;
    const int maxTries = 15; // 15 * 200ms = 3 sn
    for (int i = 0; i < maxTries; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        if (IsModuleLoadedInProcess(pid, dllName)) {
            loaded = true;
            LogDebug("Deneme #" + std::to_string(i + 1) + ": DLL yuklu bulundu!");
            break;
        }
        LogDebug("Deneme #" + std::to_string(i + 1) + "/" + std::to_string(maxTries) + ": DLL henuz yuklu degil.");
    }

    if (loaded) {
        LogSuccess("DLL hedef surecte yuklendi olarak dogrulandi.");
        return true;
    }
    else {
        LogError("Hook kuruldu ancak DLL'in yuklendigi dogrulanamadi.");
        LogWarn("Hedef thread mesaj almiyor olabilir (GUI olmayan surec).");
        LogWarn("Hook kalici olarak kurulu kaldi; program kapanirken temizlenecek.");
        return false;
    }
}

void DoRemoveHook() {
    LogStep("Hook temizligi...");
    if (g_hHook) {
        LogAddr("Kaldirilacak HHOOK", g_hHook);
        if (UnhookWindowsHookEx(g_hHook)) LogSuccess("Hook kaldirildi.");
        else LogError("UnhookWindowsHookEx basarisiz.", GetLastError());
        g_hHook = NULL;
    }
    else {
        LogInfo("Aktif hook yok.");
    }
    if (g_hHookMod) {
        LogDebug("Yerel modul serbest birakiliyor...");
        FreeLibrary(g_hHookMod);
        g_hHookMod = NULL;
    }
}

// ========== ANA ENJEKSİYON ==========
void DoAdvancedDLLInjection() {
    LogStep("=== GELISMIS DLL ENJEKSIYONU ===");

    std::string dllPathStr;
    std::cout << CYAN << "DLL Dosya Yolunu Girin: " << RESET;
    std::getline(std::cin, dllPathStr);
    if (!dllPathStr.empty() && dllPathStr.front() == '"' && dllPathStr.back() == '"' && dllPathStr.size() >= 2)
        dllPathStr = dllPathStr.substr(1, dllPathStr.size() - 2);

    std::wstring dllPath = Utf8ToWide(dllPathStr);
    LogDebug("DLL yolu (UTF-8): " + dllPathStr);
    LogDebug("DLL yolu (UTF-16 uzunluk): " + std::to_string(dllPath.length()) + " karakter");

    LogDebug("DLL dosyasi varligi kontrol ediliyor...");
    DWORD attrs = GetFileAttributesW(dllPath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        LogError("DLL dosyasi bulunamadi: " + dllPathStr, GetLastError());
        return;
    }
    LogHex("Dosya ozellikleri", attrs);
    if (attrs & FILE_ATTRIBUTE_DIRECTORY) { LogError("Yol bir klasordur, DLL degil."); return; }
    LogSuccess("DLL dosyasi dogrulandi.");

    DWORD pid = GetTargetProcess();
    if (pid == 0) return;

    PlayScanAnimation("Hedef analiz ediliyor...", 800);

    if (!CheckArchitecture(pid, dllPath)) return;

    PlayInjectionProgressAnimation();

    struct Method { const char* name; bool (*fn)(DWORD, const std::wstring&); };
    Method methods[] = {
        { "CreateRemoteThread",  Method_CreateRemoteThread },
        { "NtCreateThreadEx",    Method_NtCreateThreadEx },
        { "RtlCreateUserThread", Method_RtlCreateUserThread },
        { "QueueUserAPC",        Method_QueueUserAPC },
        { "SetWindowsHookEx",    Method_SetWindowsHookEx }
    };

    bool success = false;
    const char* usedMethod = nullptr;
    int tried = 0;
    for (auto& m : methods) {
        tried++;
        LogInfo(">>> " + std::string(m.name) + " DENENIYOR (" + std::to_string(tried) + "/5)...");
        if (m.fn(pid, dllPath)) {
            success = true;
            usedMethod = m.name;
            LogSuccess("<<< " + std::string(m.name) + " BASARILI!");
            break;
        }
        LogWarn("<<< " + std::string(m.name) + " BASARISIZ. Yedek yonteme geciliyor...\n");
    }

    PlayResultAnimation(success);
    if (success) LogSuccess(std::string("=== ENJEKSIYON TAMAMLANDI (").append(usedMethod).append(") ==="));
    else LogError("=== TUM YONTEMLER BASARISIZ ===");
}

// ========== SÜREÇ ASKIYA ALMA ==========
void DoSuspendProcess() {
    LogStep("=== SUREK ASKIYA ALMA ===");
    DWORD pid = GetTargetProcess();
    if (pid == 0) return;

    LogDebug("Thread snapshot aliniyor...");
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) { LogError("Snapshot alinamadi.", GetLastError()); return; }

    THREADENTRY32 te{ sizeof(te) };
    int total = 0, suspended = 0, failed = 0;
    std::vector<DWORD> failedTids;
    std::vector<DWORD> successTids;

    PlayScanAnimation("Thread'ler askiya aliniyor...", 500);

    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            total++;
            LogDebug("Thread TID=" + std::to_string(te.th32ThreadID) + " isleniyor...");
            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            if (hThread) {
                DWORD prev = SuspendThread(hThread);
                if (prev != (DWORD)-1) {
                    suspended++;
                    successTids.push_back(te.th32ThreadID);
                    LogDebug("  -> Askiya alindi. Onceki suspend sayisi: " + std::to_string(prev));
                }
                else {
                    failed++;
                    failedTids.push_back(te.th32ThreadID);
                    LogWarn("  -> SuspendThread basarisiz.", GetLastError());
                }
                CloseHandle(hThread);
            }
            else {
                failed++;
                failedTids.push_back(te.th32ThreadID);
                LogWarn("  -> OpenThread basarisiz.", GetLastError());
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);

    if (total == 0) { LogError("Hedef surecte thread bulunamadi."); return; }
    if (suspended > 0) LogSuccess(std::to_string(suspended) + "/" + std::to_string(total) + " thread askiya alindi.");
    if (failed > 0) {
        LogWarn(std::to_string(failed) + " thread askiya alinamadi. TID'ler:");
        for (DWORD t : failedTids) std::cout << "  - TID " << t << "\n";
        LogWarn("Surec kismen calismaya devam ediyor olabilir.");
    }

    if (!successTids.empty()) {
        g_suspendedThreads[pid] = successTids;
        LogInfo("PID " + std::to_string(pid) + " icin " + std::to_string(successTids.size()) +
            " thread kaydedildi. Devam ettirmek icin [6] kullanin.");
    }

    if (suspended == total && total > 0) LogSuccess("Tum thread'ler basariyla askiya alindi.");
}

// ========== SÜREÇ DEVAM ETTİRME ==========
void DoResumeProcess() {
    LogStep("=== SUREK DEVAM ETTIRME (RESUME) ===");

    if (g_suspendedThreads.empty()) {
        LogInfo("Kayitli askiya alinmis thread yok. Once [2] ile askiya alin.");
        return;
    }

    std::cout << CYAN << "Devam ettirilebilecek PID'ler:\n" << RESET;
    for (auto& p : g_suspendedThreads)
        std::cout << "  - PID " << p.first << " (" << p.second.size() << " thread)\n";

    std::cout << CYAN << "PID girin (hepsi icin 'all'): " << RESET;
    std::string input;
    std::getline(std::cin, input);
    if (input.empty()) { LogError("Bos giris."); return; }

    std::vector<DWORD> pidsToResume;
    if (input == "all" || input == "ALL" || input == "All") {
        for (auto& p : g_suspendedThreads) pidsToResume.push_back(p.first);
    }
    else {
        try {
            DWORD pid = (DWORD)std::stoul(input);
            if (g_suspendedThreads.find(pid) == g_suspendedThreads.end()) {
                LogError("PID " + std::to_string(pid) + " kayitli degil.");
                return;
            }
            pidsToResume.push_back(pid);
        }
        catch (const std::out_of_range&) { LogError("PID tasma yapti."); return; }
        catch (const std::invalid_argument&) { LogError("Gecersiz PID."); return; }
        catch (...) { LogError("Gecersiz giris."); return; }
    }

    for (DWORD pid : pidsToResume) {
        IndentGuard ig;
        LogStep("PID " + std::to_string(pid) + " devam ettiriliyor...");
        auto& tids = g_suspendedThreads[pid];
        int resumed = 0, failed = 0;
        for (DWORD tid : tids) {
            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
            if (hThread) {
                DWORD prev = ResumeThread(hThread);
                if (prev != (DWORD)-1) {
                    resumed++;
                    LogDebug("  TID " + std::to_string(tid) + " devam ettirildi (onceki suspend sayisi: " + std::to_string(prev) + ")");
                }
                else {
                    failed++;
                    LogWarn("  TID " + std::to_string(tid) + " ResumeThread basarisiz.", GetLastError());
                }
                CloseHandle(hThread);
            }
            else {
                failed++;
                LogWarn("  TID " + std::to_string(tid) + " OpenThread basarisiz.", GetLastError());
            }
        }
        LogSuccess(std::to_string(resumed) + "/" + std::to_string(tids.size()) + " thread devam ettirildi.");
        if (failed == 0) {
            g_suspendedThreads.erase(pid);
            LogDebug("PID " + std::to_string(pid) + " kayittan silindi.");
        }
        else {
            LogWarn("Bazi thread'ler devam ettirilemedi, kayit korundu.");
        }
    }
}

// ========== MODÜL LİSTELEME ==========
void DoListModules(DWORD pid) {
    LogStep("=== MODUL LISTELEME ===");
    LogDebug("Modul snapshot aliniyor...");
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE) { LogError("Modul snapshot alinamadi.", GetLastError()); return; }

    MODULEENTRY32W me{ sizeof(me) };
    int count = 0;
    if (Module32FirstW(hSnap, &me)) {
        do {
            std::wcout << L"[MODUL] " << me.szModule << L" (Base: 0x"
                << std::hex << std::uppercase << (uintptr_t)me.modBaseAddr
                << L", Size: " << std::dec << me.modBaseSize << L" byte)" << std::endl;
            count++;
        } while (Module32NextW(hSnap, &me));
    }
    CloseHandle(hSnap);
    LogInfo("Toplam modul: " + std::to_string(count));
}

// ========== MODÜL BOŞALTMA ==========
static const std::set<std::wstring>& GetCriticalModules() {
    static const std::set<std::wstring> critical = {
        L"ntdll.dll", L"kernel32.dll", L"kernelbase.dll", L"user32.dll",
        L"gdi32.dll", L"advapi32.dll", L"msvcrt.dll", L"ucrtbase.dll",
        L"rpcrt4.dll", L"sechost.dll", L"sspicli.dll", L"combase.dll",
        L"ole32.dll", L"oleaut32.dll", L"shell32.dll", L"shlwapi.dll",
        L"kernel.appcore.dll", L"windows.storage.dll", L"clbcatq.dll",
        L"ntdll", L"kernel32", L"kernelbase"
    };
    return critical;
}

void DoUnloadModuleManually() {
    LogStep("=== MANUEL MODUL BOSALTMA ===");
    DWORD pid = GetTargetProcess();
    if (pid == 0) return;

    DoListModules(pid);

    std::string input;
    std::cout << CYAN << "\nBosaltmak istediginiz DLL adini girin (Ornek: version.dll) (Hepsi icin 'all'): " << RESET;
    std::getline(std::cin, input);
    if (input.empty()) { LogError("Bos giris."); return; }

    bool unloadAll = (input == "all" || input == "ALL" || input == "All");
    LogDebug(std::string("Mod: ") + (unloadAll ? "'all'" : "'tek modul'"));

    LogDebug("OpenProcess cagriliyor...");
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION, FALSE, pid);
    if (!hProcess) { LogError("OpenProcess basarisiz.", GetLastError()); return; }
    LogAddr("Process handle", hProcess);

    auto freeLib = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "FreeLibrary");
    if (!freeLib) {
        LogError("FreeLibrary adresi alinamadi.", GetLastError());
        CloseHandle(hProcess); return;
    }
    LogAddr("FreeLibrary adresi", (const void*)freeLib);

    std::wstring wInput = Utf8ToWide(input);
    if (!unloadAll && wInput.find(L'.') == std::wstring::npos) wInput += L".dll";

    const auto& critical = GetCriticalModules();

    LogDebug("Hedef moduller toplaniyor...");
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE) {
        LogError("Modul snapshot alinamadi.", GetLastError());
        CloseHandle(hProcess); return;
    }

    std::vector<std::pair<std::wstring, HMODULE>> targets;
    MODULEENTRY32W me{ sizeof(me) };
    if (Module32FirstW(hSnap, &me)) {
        do {
            if (unloadAll) {
                if (critical.count(std::wstring(me.szModule)) == 0)
                    targets.push_back({ me.szModule, (HMODULE)me.modBaseAddr });
            }
            else {
                if (_wcsicmp(me.szModule, wInput.c_str()) == 0)
                    targets.push_back({ me.szModule, (HMODULE)me.modBaseAddr });
            }
        } while (Module32NextW(hSnap, &me));
    }
    CloseHandle(hSnap);

    if (targets.empty()) {
        LogError(unloadAll ? "Bosaltilabilir modul bulunamadi." : "Belirtilen modul hedef surecte bulunamadi.");
        CloseHandle(hProcess);
        return;
    }

    LogInfo(std::to_string(targets.size()) + " modul bosaltma listesine alindi.");
    if (unloadAll) {
        LogWarn("DIKKAT: 'all' secenegi uygulamanin ihtiyac duydugu DLL'leri de kaldirmayi deneyebilir.");
    }

    int unloadedCount = 0, failedCount = 0;
    for (auto& t : targets) {
        IndentGuard ig;
        std::wstring name = t.first;
        HMODULE base = t.second;
        LogStep("Isleniyor: " + WideToUtf8(name));
        LogAddr("  Modul base adresi", base);

        LogDebug("  CreateRemoteThread(FreeLibrary) cagriliyor...");
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, freeLib, (LPVOID)base, 0, NULL);
        if (!hThread) {
            LogError("  FreeLibrary thread olusturulamadi.", GetLastError());
            failedCount++;
            continue;
        }
        LogAddr("  Thread handle", hThread);

        LogDebug("  Thread tamamlanmasi bekleniyor (timeout=3000 ms)...");
        DWORD wait = WaitForSingleObject(hThread, 3000);
        DWORD exitCode = 0;
        bool threadOk = (wait == WAIT_OBJECT_0);
        if (threadOk) {
            GetExitCodeThread(hThread, &exitCode);
            LogHex("  FreeLibrary cikis kodu", exitCode);
        }
        else if (wait == WAIT_TIMEOUT) {
            LogError("  FreeLibrary thread zaman asimi.");
        }
        else {
            LogError("  WaitForSingleObject basarisiz.", GetLastError());
        }
        CloseHandle(hThread);

        if (!threadOk) { failedCount++; continue; }
        if (exitCode == 0) {
            LogError("  FreeLibrary basarisiz (exit=0). Modul hala yuklu olabilir.");
            failedCount++;
            continue;
        }

        LogDebug("  Modulun kalktigi modul snapshot ile dogrulaniyor...");
        if (IsModuleLoadedInProcess(pid, name)) {
            LogWarn("  FreeLibrary OK dondu ancak modul hala listede.");
            failedCount++;
        }
        else {
            LogSuccess("  Modul basariyla bosaltildi (dogrulandi).");
            unloadedCount++;
        }
    }

    CloseHandle(hProcess);
    std::cout << "\n";
    LogInfo("Ozet: " + std::to_string(unloadedCount) + " basarili, " +
        std::to_string(failedCount) + " basarisiz.");
}

// ========== MAIN ==========
int main() {
    ElevateUAC();

    SetConsoleTitleW(L"DLL MAP - Advanced Injection Tool");
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hConsole, &dwMode);
    SetConsoleMode(hConsole, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    while (true) {
        system("cls");
        PrintAdvancedLogo();

        std::cout << BOLD << CYAN << " [1] " << RESET << "Gelismis DLL Enjekte Et (5 Yedekli Yontem)\n";
        std::cout << BOLD << CYAN << " [2] " << RESET << "Hedef Process'in Tum Thread'lerini Askiya Al (Suspend)\n";
        std::cout << BOLD << CYAN << " [3] " << RESET << "Hedef Process'in Yuklu Modullerini Listele\n";
        std::cout << BOLD << CYAN << " [4] " << RESET << "Manuel Modul Bosalt (Unload DLL, 'all' destekli)\n";
        std::cout << BOLD << CYAN << " [5] " << RESET << "Aktif Hook'u Kaldir (SetWindowsHookEx temizligi)\n";
        std::cout << BOLD << CYAN << " [6] " << RESET << "Askiya Alinan Thread'leri Devam Ettir (Resume)\n";
        std::cout << BOLD << RED << " [0] " << RESET << "Cikis\n\n";
        std::cout << BOLD << YELLOW << " Seciminiz: " << RESET;

        std::string choice;
        std::getline(std::cin, choice);

        if (choice == "0") break;

        system("cls");

        if (choice == "1") DoAdvancedDLLInjection();
        else if (choice == "2") DoSuspendProcess();
        else if (choice == "3") {
            DWORD pid = GetTargetProcess();
            if (pid != 0) DoListModules(pid);
        }
        else if (choice == "4") DoUnloadModuleManually();
        else if (choice == "5") DoRemoveHook();
        else if (choice == "6") DoResumeProcess();
        else LogError("Gecersiz secim!");

        std::cout << "\nDevam etmek icin Enter'a basin...";
        std::cin.get();
    }

    DoRemoveHook();
    return 0;
}
