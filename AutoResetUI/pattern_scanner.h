#pragma once
#include <Windows.h>
#include <Psapi.h>

MODULEINFO get_module_info(LPCSTR name = NULL) {
    MODULEINFO modinfo = { 0 };
    HMODULE module = GetModuleHandleA(name);

    if (module == 0)
        return modinfo;

    GetModuleInformation(GetCurrentProcess(), module, &modinfo, sizeof(MODULEINFO));
    return modinfo;
}

DWORD pattern_scan(const char* pattern, const char* mask, int offset = 0) {
    MODULEINFO mInfo = get_module_info();

    DWORD base = (DWORD)mInfo.lpBaseOfDll;
    DWORD size = (DWORD)mInfo.SizeOfImage;

    DWORD pattern_length = (DWORD)strlen(mask);

    for (DWORD i = 0; i < size - pattern_length; i++) {
        bool found = true;
        for (DWORD j = 0; j < pattern_length; j++)
        {
            if ((char*)(base + i + j) != nullptr)
                found &= mask[j] == '?' || pattern[j] == *(char*)(base + i + j);
        }

        if (found)
            return base + i + offset;
    }

    return NULL;
}
