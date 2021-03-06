#include <windows.h>
#include <stdio.h>
#include <Shlwapi.h>
#include <psapi.h>
#pragma comment(lib, "shlwapi.lib")

int hook(DWORD pid)
{
    WCHAR dllpath[MAX_PATH];
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    BOOL wow64 = FALSE;
    if (!hProcess)
        return 0;
#ifdef _WIN64
    BOOL is_64bit = TRUE;
#else
    BOOL is_64bit = FALSE;
    IsWow64Process(GetCurrentProcess(), &is_64bit);
#endif
    IsWow64Process(hProcess, &wow64);
    GetModuleFileNameW(GetModuleHandleW(NULL), dllpath, MAX_PATH);
    if (wow64 || !is_64bit)
    {
        PathCombineW(dllpath, dllpath, L"..\\icon16bitfix32.dll");
    }
    else
    {
        PathCombineW(dllpath, dllpath, L"..\\icon16bitfix64.dll");
    }
    HMODULE hModule;
    DWORD cb;
    WCHAR process_name[MAX_PATH] = { 0 };
    K32GetProcessImageFileNameW(hProcess, process_name, ARRAYSIZE(process_name));
    if (_wcsicmp(PathFindFileNameW(process_name), L"explorer.exe"))
    {
        CloseHandle(hProcess);
        return 1;
    }
    void *datamemory = VirtualAllocEx(hProcess, NULL, sizeof(dllpath), MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hProcess, datamemory, (void *)dllpath, sizeof(dllpath), NULL);

    HMODULE kernel32 = GetModuleHandleW(L"kernel32");
    FARPROC loadlibrary = GetProcAddress(kernel32, "LoadLibraryW");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadlibrary, datamemory, 0, NULL);
    if (!hThread)
    {
        return 0;
    }
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, datamemory, sizeof(dllpath), MEM_RELEASE);
    CloseHandle(hProcess);
    return 1;
}
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    DWORD process[65536];
    DWORD process_count;
    K32EnumProcesses(process, sizeof(process), &process_count);
    for (DWORD i = 0; i < process_count; i++)
    {
        hook(process[i]);
    }
    return 0;
}
