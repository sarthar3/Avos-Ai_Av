/*
 * AVOS AI - Payment Security Shield
 * API Hooking: WinINet / WinHTTP for browser-based financial form protection
 * Blocks keyloggers, form-jacking on UPI / Net Banking pages
 *
 * Injection: Loaded as DLL into browser processes via CSO
 */

#include <windows.h>
#include <wininet.h>
#include <winhttp.h>
#include <detours.h>
#include <string>
#include <regex>
#include <vector>
#include <sstream>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "detours.lib")

// ─── Financial Pattern Detection ────────────────────────────────────────────
namespace AvosPayment {

    // Regex patterns for sensitive financial data in POST bodies
    static const std::vector<std::pair<std::string, std::string>> SENSITIVE_PATTERNS = {
        {"card_number",    R"(\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b)"},
        {"cvv",            R"(\bcvv\s*=\s*\d{3,4}\b)"},
        {"upi_id",         R"(\b[\w\.\-]+@[a-z]{2,}\b)"},       // UPI VPA
        {"net_banking",    R"(\b(ibank|netbanking|login.*password|userid.*pin)\b)"},
        {"card_expiry",    R"(\bexp(?:iry|date)?\s*=\s*\d{2}[\/\-]\d{2,4}\b)"},
        {"aadhaar",        R"(\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b)"},
    };

    // Financial domains to monitor
    static const std::vector<std::string> FINANCIAL_DOMAINS = {
        "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
        "paytm.com", "phonepe.com", "gpay.com", "bhimupi.org",
        "razorpay.com", "payumoney.com", "billdesk.com",
        "netbanking", "ibanking", "onlinebanking"
    };

    // Alert pipe name for CSO notification
    static const wchar_t* ALERT_PIPE = L"\\\\.\\pipe\\AvosPaymentAlert";

    bool ContainsSensitiveData(const std::string& payload) {
        std::string lower = payload;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        for (const auto& [name, pattern] : SENSITIVE_PATTERNS) {
            std::regex re(pattern, std::regex::icase);
            if (std::regex_search(lower, re)) {
                return true;
            }
        }
        return false;
    }

    bool IsFinancialDomain(const std::string& host) {
        std::string lower = host;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        for (const auto& domain : FINANCIAL_DOMAINS) {
            if (lower.find(domain) != std::string::npos) return true;
        }
        return false;
    }

    void AlertCSO(const char* threat_type, const char* host) {
        HANDLE hPipe = CreateFileA(
            "\\\\.\\pipe\\AvosPaymentAlert",
            GENERIC_WRITE,
            0, NULL,
            OPEN_EXISTING,
            0, NULL);

        if (hPipe != INVALID_HANDLE_VALUE) {
            char buf[512];
            snprintf(buf, sizeof(buf),
                "{\"event\":\"payment_threat\",\"type\":\"%s\",\"host\":\"%s\",\"pid\":%lu}",
                threat_type, host, GetCurrentProcessId());
            DWORD written;
            WriteFile(hPipe, buf, (DWORD)strlen(buf), &written, NULL);
            CloseHandle(hPipe);
        }
    }
}

// ─── WinINet Hooks ───────────────────────────────────────────────────────────

// Original function pointers
static decltype(HttpSendRequestA)*  Real_HttpSendRequestA  = HttpSendRequestA;
static decltype(HttpSendRequestW)*  Real_HttpSendRequestW  = HttpSendRequestW;
static decltype(InternetConnectA)*  Real_InternetConnectA  = InternetConnectA;

// Hooked HttpSendRequestA
BOOL WINAPI Hooked_HttpSendRequestA(
    HINTERNET hRequest,
    LPCSTR lpszHeaders,
    DWORD dwHeadersLength,
    LPVOID lpOptional,
    DWORD dwOptionalLength)
{
    // Inspect POST body for sensitive data
    if (lpOptional && dwOptionalLength > 0) {
        std::string body(static_cast<char*>(lpOptional), dwOptionalLength);
        if (AvosPayment::ContainsSensitiveData(body)) {
            // Get server name
            char hostBuf[256] = {0};
            DWORD hostLen = sizeof(hostBuf);
            InternetQueryOptionA(hRequest, INTERNET_OPTION_URL, hostBuf, &hostLen);
            AvosPayment::AlertCSO("form_jacking_wiinet", hostBuf);
            // Block the transmission — return FALSE with custom error
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
    }
    return Real_HttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
}

// Hooked HttpSendRequestW
BOOL WINAPI Hooked_HttpSendRequestW(
    HINTERNET hRequest,
    LPCWSTR lpszHeaders,
    DWORD dwHeadersLength,
    LPVOID lpOptional,
    DWORD dwOptionalLength)
{
    if (lpOptional && dwOptionalLength > 0) {
        // Convert wide body to narrow for analysis
        std::string body(static_cast<char*>(lpOptional), dwOptionalLength);
        if (AvosPayment::ContainsSensitiveData(body)) {
            AvosPayment::AlertCSO("form_jacking_wiinet_w", "unknown_host");
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
    }
    return Real_HttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
}

// Hooked InternetConnectA — log financial domain connections
HINTERNET WINAPI Hooked_InternetConnectA(
    HINTERNET hInternet,
    LPCSTR lpszServerName,
    INTERNET_PORT nServerPort,
    LPCSTR lpszUserName,
    LPCSTR lpszPassword,
    DWORD dwService,
    DWORD dwFlags,
    DWORD_PTR dwContext)
{
    if (lpszServerName && AvosPayment::IsFinancialDomain(lpszServerName)) {
        AvosPayment::AlertCSO("financial_domain_connect", lpszServerName);
    }
    return Real_InternetConnectA(hInternet, lpszServerName, nServerPort,
                                  lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
}

// ─── WinHTTP Hooks ───────────────────────────────────────────────────────────
static decltype(WinHttpSendRequest)* Real_WinHttpSendRequest = WinHttpSendRequest;

BOOL WINAPI Hooked_WinHttpSendRequest(
    HINTERNET hRequest,
    LPCWSTR lpszHeaders,
    DWORD dwHeadersLength,
    LPVOID lpOptional,
    DWORD dwOptionalLength,
    DWORD dwTotalLength,
    DWORD_PTR dwContext)
{
    if (lpOptional && dwOptionalLength > 0) {
        std::string body(static_cast<char*>(lpOptional), dwOptionalLength);
        if (AvosPayment::ContainsSensitiveData(body)) {
            AvosPayment::AlertCSO("form_jacking_winhttp", "winhttp_target");
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
    }
    return Real_WinHttpSendRequest(hRequest, lpszHeaders, dwHeadersLength,
                                    lpOptional, dwOptionalLength, dwTotalLength, dwContext);
}

// ─── DLL Entry Point ─────────────────────────────────────────────────────────
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(lpReserved);

    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Install hooks using Microsoft Detours
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)Real_HttpSendRequestA,  Hooked_HttpSendRequestA);
        DetourAttach(&(PVOID&)Real_HttpSendRequestW,  Hooked_HttpSendRequestW);
        DetourAttach(&(PVOID&)Real_InternetConnectA,  Hooked_InternetConnectA);
        DetourAttach(&(PVOID&)Real_WinHttpSendRequest, Hooked_WinHttpSendRequest);
        DetourTransactionCommit();
        break;

    case DLL_PROCESS_DETACH:
        // Remove hooks
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)Real_HttpSendRequestA,  Hooked_HttpSendRequestA);
        DetourDetach(&(PVOID&)Real_HttpSendRequestW,  Hooked_HttpSendRequestW);
        DetourDetach(&(PVOID&)Real_InternetConnectA,  Hooked_InternetConnectA);
        DetourDetach(&(PVOID&)Real_WinHttpSendRequest, Hooked_WinHttpSendRequest);
        DetourTransactionCommit();
        break;
    }
    return TRUE;
}
