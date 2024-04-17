#include <Windows.h>
#include <string>
#include <sstream>
#include "pattern_scanner.h"
#include "function_hook.h"

void error(std::string msg) {
    MessageBoxA(NULL, msg.c_str(), "AutoResetUI error", MB_ICONERROR);
}

void auto_reset_ui_mod() {
    constexpr int hook_size = 5;
    LPVOID allocated_mem = NULL;
    DWORD return_address = NULL;
    BYTE asm_code[] = {
        0x60,                           // pushad
        0x9C,                           // pushfd

        0xE8, 0x00, 0x00, 0x00, 0x00,   // call reset_ui

        0x9D,                           // popfd
        0x61,                           // popad

        0x55,                           // push ebp
        0x8B, 0xEC,                     // mov ebp, esp
        0x51,                           // push ecx
        0x53,                           // push ebx
        0xE9, 0x00, 0x00, 0x00, 0x00    // jmp return_adress
    };
    
    // Get addresses for both the change resolution and reset ui functions
    DWORD change_resolution_address = pattern_scan(
        "\x55\x8b\xec\x51\x53\x56\x57\x8b\xf9\x8b\xf2\x8b\xd8\xc6\x45\x00\x00\x8b\x45",
        "xxxxxxxxxxxxxxx??xx"
    );

    DWORD reset_ui_address = pattern_scan(
        "\x53\xa1\x00\x00\x00\x00\x8b\x15",
        "xx????xx"
    );

    if (change_resolution_address == NULL || reset_ui_address == NULL) {
        error("Addresses not found");
        return;
    }

    // Calculate address to return
    return_address = change_resolution_address + hook_size;

    // Create a new memory page to write our code with execution, read and write permission
    allocated_mem = VirtualAlloc(NULL, sizeof(asm_code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (allocated_mem == NULL) {
        error("Failed on VirtualAlloc");
        return;
    }

    // Fill the missing relative addresses in the asm code
    DWORD reset_ui_relative_addr = reset_ui_address - (reinterpret_cast<DWORD>(allocated_mem) + 2) - 5;
    DWORD return_relative_addr = return_address - (reinterpret_cast<DWORD>(allocated_mem) + 14) - 5;
    memcpy(&asm_code[3], &reset_ui_relative_addr, sizeof(DWORD));
    memcpy(&asm_code[15], &return_relative_addr, sizeof(DWORD));

    // Copy the asm code into the allocated memory
    memcpy(allocated_mem, &asm_code, sizeof(asm_code));

    // Hook the original function to execute our custom function
    if (!hook(reinterpret_cast<void*>(change_resolution_address), allocated_mem, hook_size)) {
        error("Error hooking function");
        VirtualFree(allocated_mem, 0, MEM_RELEASE);
        return;
    }
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        auto_reset_ui_mod();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

