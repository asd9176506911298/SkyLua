// dllmain.cpp
#include "pch.h"
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string>
#include <queue>

BOOL initialized = FALSE;
uint64_t state = 0;
CRITICAL_SECTION script_queue_cs;
std::queue<std::string> script_queue;

const uint8_t update_bytes[] = { 0x55, 0x41, 0x57, 0x41, 0x56, 0x56, 0x57, 0x53, 0x48, 0x81, 0xEC, 0x28, 0x01, 0x00, 0x00, 0x48, 0x8D, 0xAC, 0x24, 0x80, 0x00, 0x00, 0x00, 0x48, 0x83, 0xE4, 0xE0, 0x41, 0x83, 0xF9, 0x1F };
const char* update_mask = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

uintptr_t update_ptr = 0;

const uint8_t debugdostring_bytes[] = { 0x55, 0x56, 0x57, 0x53, 0x48, 0x81, 0xEC, 0x38, 0x09, 0x00, 0x00, 0x48, 0x8D, 0xAC, 0x24, 0x80, 0x00, 0x00, 0x00, 0x48, 0x89, 0xD6, 0x48, 0x89, 0xCB, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0 };
const char* debugdostring_mask = "xxxxxxxxxxxxxxxxxxxxxxxxxx????xx";
uintptr_t debugdostring_ptr = 0;

typedef uint64_t(*update)(uint64_t a1, uint64_t a2, uint64_t a3, unsigned int a4);
update original_update = NULL;

typedef uint64_t(*debugdostring)(uint64_t state, const char* str);
debugdostring evaluate = NULL;

// === 工作執行緒：監聽 named pipe ===
DWORD WINAPI PipeListener(LPVOID)
{
    const wchar_t* pipeName = L"\\\\.\\pipe\\sky_lua_pipe";
    HANDLE hPipe;

    while (true)
    {
        hPipe = CreateNamedPipeW(
            pipeName, PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, NULL);

        if (hPipe == INVALID_HANDLE_VALUE) {
            Sleep(1000);
            continue;
        }

        if (ConnectNamedPipe(hPipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED)
        {
            char buffer[4096];
            DWORD bytesRead;
            if (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0)
            {
                buffer[bytesRead] = '\0';
                EnterCriticalSection(&script_queue_cs);
                script_queue.push(std::string(buffer));
                LeaveCriticalSection(&script_queue_cs);
            }
        }
        CloseHandle(hPipe);
    }
    return 0;
}

// === Hook 函數：每幀檢查 queue ===
uint64_t on_update(uint64_t a1, uint64_t a2, uint64_t a3, unsigned int a4)
{
    if (!initialized)
    {
        state = *(uint64_t*)(a2 + 32);
        initialized = TRUE;
    }

    // 檢查是否有新指令
    EnterCriticalSection(&script_queue_cs);
    if (!script_queue.empty() && state && evaluate)
    {
        std::string script = script_queue.front();
        script_queue.pop();
        LeaveCriticalSection(&script_queue_cs);

        evaluate(state, script.c_str());
    }
    else
    {
        LeaveCriticalSection(&script_queue_cs);
    }

    return original_update(a1, a2, a3, a4);
}

// === Hook 寫入 ===
void write_update_hook(uint8_t* target)
{
    void* trampoline = VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!trampoline) return;

    memcpy(trampoline, target, 23);
    uint8_t* jmp_back = (uint8_t*)trampoline + 23;
    jmp_back[0] = 0xFF; jmp_back[1] = 0x25;
    jmp_back[2] = 0x00; jmp_back[3] = 0x00;
    jmp_back[4] = 0x00; jmp_back[5] = 0x00;
    *(uint64_t*)(jmp_back + 6) = (uint64_t)(target + 23);

    DWORD old_protect;
    VirtualProtect(target, 14, PAGE_EXECUTE_READWRITE, &old_protect);
    target[0] = 0xFF; target[1] = 0x25;
    target[2] = 0x00; target[3] = 0x00;
    target[4] = 0x00; target[5] = 0x00;
    *(uint64_t*)(target + 6) = (uint64_t)&on_update;
    VirtualProtect(target, 14, old_protect, &old_protect);

    original_update = (update)trampoline;
}

uintptr_t find_pattern(const uint8_t* pattern, const char* mask, size_t len) {
    MEMORY_BASIC_INFORMATION mbi;
    uint8_t* current = (uint8_t*)GetModuleHandle(NULL);

    if (strlen(mask) != len) { //failsafe for bad use of function
        return 0;
    }

    while (VirtualQuery(current, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) {
            const uint8_t* start = (uint8_t*)mbi.BaseAddress;
            const uint8_t* end = start + mbi.RegionSize - len;

            for (const uint8_t* addr = start; addr <= end; ++addr) {
                size_t matched;
                for (matched = 0; matched < len; ++matched) {
                    if (mask[matched] != '?' &&
                        pattern[matched] != addr[matched]) break;
                }
                if (matched == len && addr != pattern) {
                    return (uintptr_t)addr;
                }
            }
        }
        current = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
    {
        AllocConsole();
        freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
        freopen_s((FILE**)stderr, "CONOUT$", "w", stderr);

        uintptr_t update_ptr = find_pattern(update_bytes, update_mask, sizeof(update_bytes));
        uintptr_t debugdostring_ptr = find_pattern(debugdostring_bytes, debugdostring_mask, sizeof(debugdostring_bytes));

        InitializeCriticalSection(&script_queue_cs);
        evaluate = (debugdostring)debugdostring_ptr;
        write_update_hook((uint8_t*)update_ptr);

        CreateThread(NULL, 0, PipeListener, NULL, 0, NULL);

        printf("[DLL] Lua injector ready! Use pipe: \\\\.\\pipe\\sky_lua_pipe\n");
        break;
    }
    case DLL_PROCESS_DETACH:
    {
        DeleteCriticalSection(&script_queue_cs);
        FreeConsole();
        break;
    }
    }
    return TRUE;
}