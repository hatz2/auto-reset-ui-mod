#pragma once
#include <Windows.h>

bool hook(void* to_hook, void* our_func, const int len)
{
    if (len < 5) return false;

    DWORD curProtection;
    VirtualProtect(to_hook, len, PAGE_EXECUTE_READWRITE, &curProtection);

    memset(to_hook, 0x90, len);

    DWORD relativeAdress = ((DWORD)our_func - (DWORD)to_hook) - 5;

    *(BYTE*)to_hook = 0xE9;
    *(DWORD*)((DWORD)to_hook + 1) = relativeAdress;

    DWORD temp;
    VirtualProtect(to_hook, len, curProtection, &temp);

    return true;
}
