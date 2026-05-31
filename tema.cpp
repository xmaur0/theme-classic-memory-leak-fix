#include <windows.h>
#include <sddl.h>
#include <iostream>
#include <cstdio>

// Definições necessárias para a API nativa NtOpenSection
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef NTSTATUS(NTAPI* pfnNtOpenSection)(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
);

void SetClassicTheme(bool disable) {
    DWORD sessionId = WTSGetActiveConsoleSessionId();
    
    wchar_t themeSectionPath[MAX_PATH];
    swprintf(themeSectionPath, MAX_PATH, L"\\Sessions\\%lu\\Windows\\ThemeSection", sessionId);

    UNICODE_STRING unicodeString;
    unicodeString.Buffer = themeSectionPath;
    unicodeString.Length = static_cast<USHORT>(wcslen(themeSectionPath) * sizeof(wchar_t));
    unicodeString.MaximumLength = unicodeString.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES objectAttributes = { 0 };
    objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
    objectAttributes.ObjectName = &unicodeString;

    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtDll) return;

    pfnNtOpenSection NtOpenSection = (pfnNtOpenSection)GetProcAddress(hNtDll, "NtOpenSection");
    if (!NtOpenSection) return;

    HANDLE sectionHandle = nullptr;
    NTSTATUS status = NtOpenSection(&sectionHandle, 0x00040000L, &objectAttributes);
    
    if (status != 0 || sectionHandle == nullptr) {
        return; 
    }

    PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
    const wchar_t* sddl = disable ? L"D:(A;;CCLCRC;;;IU)(A;;CCDCLCSWRPSDRCWDWO;;;SY)" : L"D:(A;;RC;;;IU)(A;;DCSWRPSDRCWDWO;;;SY)";

    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &securityDescriptor, nullptr)) {
        SetKernelObjectSecurity(sectionHandle, 4, securityDescriptor);
        LocalFree(securityDescriptor);
    }

    CloseHandle(sectionHandle);
}

int main(int argc, char* argv[]) {
    bool disable = false;

    if (argc > 1 && strcmp(argv[1], "-Disable") == 0) {
        disable = true;
    }

    SetClassicTheme(disable);
    return 0;
}