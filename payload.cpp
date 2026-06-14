#include <Windows.h>

BOOL APIENTRY DllMain(HMODULE mod, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(mod);
        MessageBoxW(nullptr, L"Loaded.", L"Ok", MB_OK);
    }
    return TRUE;
}
