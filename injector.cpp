#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>

DWORD GetPid(const std::wstring& name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name.c_str()) == 0) {
                CloseHandle(snap);
                return pe.th32ProcessID;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return 0;
}

bool Inject(DWORD pid, const std::wstring& dll) {
    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!proc) {
        std::wcerr << L"[x] OpenProcess " << GetLastError() << L"\n";
        return false;
    }

    size_t sz = (dll.size() + 1) * sizeof(wchar_t);
    LPVOID mem = VirtualAllocEx(proc, nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) {
        std::wcerr << L"[x] Alloc " << GetLastError() << L"\n";
        CloseHandle(proc);
        return false;
    }

    if (!WriteProcessMemory(proc, mem, dll.c_str(), sz, nullptr)) {
        std::wcerr << L"[x] Write " << GetLastError() << L"\n";
        VirtualFreeEx(proc, mem, 0, MEM_RELEASE);
        CloseHandle(proc);
        return false;
    }

    FARPROC load = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    if (!load) {
        std::wcerr << L"[x] Resolve " << GetLastError() << L"\n";
        VirtualFreeEx(proc, mem, 0, MEM_RELEASE);
        CloseHandle(proc);
        return false;
    }

    HANDLE thr = CreateRemoteThread(
        proc, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(load),
        mem, 0, nullptr
    );

    if (!thr) {
        std::wcerr << L"[x] Thread " << GetLastError() << L"\n";
        VirtualFreeEx(proc, mem, 0, MEM_RELEASE);
        CloseHandle(proc);
        return false;
    }

    WaitForSingleObject(thr, INFINITE);

    DWORD rc = 0;
    GetExitCodeThread(thr, &rc);

    CloseHandle(thr);
    VirtualFreeEx(proc, mem, 0, MEM_RELEASE);
    CloseHandle(proc);

    return rc != 0;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        std::wcout << L"injector.exe <proc> <dll>\n";
        return 1;
    }

    std::wstring proc = argv[1];
    std::wstring dll = argv[2];

    wchar_t full[MAX_PATH];
    if (GetFullPathNameW(dll.c_str(), MAX_PATH, full, nullptr))
        dll = full;

    DWORD attr = GetFileAttributesW(dll.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        std::wcerr << L"[x] Dll missing\n";
        return 1;
    }

    DWORD pid = GetPid(proc);
    if (!pid) {
        std::wcerr << L"[x] Proc not found\n";
        return 1;
    }

    std::wcout << L"[+] Pid " << pid << L"\n";

    if (Inject(pid, dll))
        std::wcout << L"[+] Done\n";
    else
        std::wcerr << L"[x] Fail\n";

    return 0;
}
