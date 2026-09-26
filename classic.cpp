#include <windows.h>
#include <winternl.h>
#include <sddl.h>

typedef NTSTATUS(NTAPI* pfnNtOpenSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

// Busca de substring customizada para nao depender do wcsstr do CRT
const wchar_t* WcsStr(const wchar_t* str, const wchar_t* strSearch) {
    if (!str || !strSearch || !*strSearch) return str;

    for (; *str; str++) {
        if (*str == *strSearch) {
            const wchar_t* h = str;
            const wchar_t* n = strSearch;
            while (*h && *n && *h == *n) {
                h++;
                n++;
            }
            if (!*n) return str;
        }
    }
    return NULL;
}

// Conversao manual de numero para string sem dependencias
void NumberToWString(DWORD number, wchar_t* buffer) {
    wchar_t temp[16];
    int i = 0;
    
    if (number == 0) {
        temp[i++] = L'0';
    } else {
        while (number > 0) {
            temp[i++] = L'0' + (number % 10);
            number /= 10;
        }
    }

    int j = 0;
    while (i > 0) {
        buffer[j++] = temp[--i];
    }
    buffer[j] = L'\0';
}

void CorrigirMetricasJanelaWindows11(bool habilitandoTemaClassico) {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Control Panel\\Desktop\\WindowMetrics", 0, KEY_READ | KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        if (habilitandoTemaClassico) {
            wchar_t buffer[32] = { 0 };
            DWORD size = sizeof(buffer);
            bool precisaAjustar = false;

            if (RegQueryValueExW(hKey, L"CaptionHeight", NULL, NULL, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
                int alturaAtual = 0;
                wchar_t* p = buffer;
                if (*p == L'-') p++;
                while (*p >= L'0' && *p <= L'9') {
                    alturaAtual = alturaAtual * 10 + (*p - L'0');
                    p++;
                }
                if (buffer[0] == L'-') alturaAtual = -alturaAtual;

                if (alturaAtual > -280) {
                    precisaAjustar = true;
                }
            } else {
                precisaAjustar = true;
            }

            if (precisaAjustar) {
                const wchar_t* novaMetrica = L"-300";
                RegSetValueExW(hKey, L"CaptionHeight", 0, REG_SZ, (BYTE*)novaMetrica, (DWORD)(lstrlenW(novaMetrica) + 1) * sizeof(wchar_t));
                RegSetValueExW(hKey, L"CaptionWidth", 0, REG_SZ, (BYTE*)novaMetrica, (DWORD)(lstrlenW(novaMetrica) + 1) * sizeof(wchar_t));

                NONCLIENTMETRICSW ncm = { sizeof(NONCLIENTMETRICSW) };
                if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0)) {
                    ncm.iCaptionHeight = 19;
                    ncm.iCaptionWidth = 19;
                    SystemParametersInfoW(SPI_SETNONCLIENTMETRICS, sizeof(ncm), &ncm, SPIF_SENDCHANGE | SPIF_UPDATEINIFILE);
                }
                
                SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, SPI_SETNONCLIENTMETRICS, 0, SMTO_ABORTIFHUNG, 2000, NULL);
            }
        } else {
            const wchar_t* valorPadrao = L"-195";
            RegSetValueExW(hKey, L"CaptionHeight", 0, REG_SZ, (BYTE*)valorPadrao, (DWORD)(lstrlenW(valorPadrao) + 1) * sizeof(wchar_t));
            RegSetValueExW(hKey, L"CaptionWidth", 0, REG_SZ, (BYTE*)valorPadrao, (DWORD)(lstrlenW(valorPadrao) + 1) * sizeof(wchar_t));
            
            SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, SPI_SETNONCLIENTMETRICS, 0, SMTO_ABORTIFHUNG, 2000, NULL);
        }

        RegCloseKey(hKey);
    }
}

void SetClassicTheme(bool disable) {
    DWORD sessionId = 0;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &sessionId)) {
        return;
    }

    wchar_t sessionStr[16];
    NumberToWString(sessionId, sessionStr);

    wchar_t themeSectionPath[128] = L"\\Sessions\\";
    lstrcatW(themeSectionPath, sessionStr);
    lstrcatW(themeSectionPath, L"\\Windows\\ThemeSection");

    UNICODE_STRING uPath = { 0 };
    uPath.Length = (USHORT)(lstrlenW(themeSectionPath) * sizeof(wchar_t));
    uPath.MaximumLength = (USHORT)((lstrlenW(themeSectionPath) + 1) * sizeof(wchar_t));
    uPath.Buffer = themeSectionPath;

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return;

    pfnNtOpenSection NtOpenSection = (pfnNtOpenSection)GetProcAddress(hNtdll, "NtOpenSection");
    if (!NtOpenSection) return;

    HANDLE hSection = NULL;
    NTSTATUS status = NtOpenSection(&hSection, WRITE_DAC | READ_CONTROL, &objAttr);

    if (status != 0) {
        return;
    }

    const wchar_t* sddl = disable 
        ? L"O:BAG:SYD:(A;;CCLCRC;;;IU)(A;;CCDCLCSWRPSDRCWDWO;;;SY)" 
        : L"O:BAG:SYD:(A;;RC;;;IU)(A;;DCSWRPSDRCWDWO;;;SY)";

    PSECURITY_DESCRIPTOR pSD = NULL;
    ULONG sdSize = 0;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &pSD, &sdSize)) {
        CloseHandle(hSection);
        return;
    }

    BOOL success = SetKernelObjectSecurity(hSection, DACL_SECURITY_INFORMATION, pSD);

    if (pSD != NULL) LocalFree(pSD);
    if (hSection != NULL) CloseHandle(hSection);

    if (!success) {
        return;
    }

    CorrigirMetricasJanelaWindows11(!disable);
}

// Ponto de entrada totalmente livre de dependencias C Runtime (CRT)
extern "C" void Entry() {
    bool disable = false;

    LPWSTR cmdLine = GetCommandLineW();
    if (cmdLine != NULL && WcsStr(cmdLine, L"-Disable") != NULL) {
        disable = true;
    }

    SetClassicTheme(disable);
    ExitProcess(0);
}