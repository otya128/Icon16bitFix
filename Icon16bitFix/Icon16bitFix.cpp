#include <windows.h>
#include <detours.h>
typedef UINT (WINAPI *PrivateExtractIconsW_t)(
    LPCWSTR szFileName,
    int nIconIndex,
    int cxIcon,
    int cyIcon,
    HICON *phicon,
    UINT *piconid,
    UINT nIcons,
    UINT flags);
PrivateExtractIconsW_t OldPrivateExtractIconsW;
extern "C" UINT NE_ExtractIcon(LPCWSTR lpszExeFileName,
    HICON * RetPtr,
    INT nIconIndex,
    UINT nIcons,
    UINT cxDesired,
    UINT cyDesired,
    UINT *pIconId,
    UINT flags);
UINT WINAPI MyPrivateExtractIconsW(
    LPCWSTR szFileName,
    int nIconIndex,
    int cxIcon,
    int cyIcon,
    HICON *phicon,
    UINT *piconid,
    UINT nIcons,
    UINT flags)
{
    UINT a = OldPrivateExtractIconsW(szFileName, nIconIndex, cxIcon, cyIcon, phicon, piconid, nIcons, flags);
    if (a)
        return a;
    return NE_ExtractIcon(szFileName, phicon, nIconIndex, nIcons, cxIcon, cyIcon, piconid, flags);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{

    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
    {
        const char *dll = "user32.dll";//"ext-ms-win-ntuser-misc-l1-5-1.dll";
        HMODULE user32 = LoadLibraryA(dll);
        OldPrivateExtractIconsW = (PrivateExtractIconsW_t)GetProcAddress(user32, "PrivateExtractIconsW");
        DetourRestoreAfterWith();

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)OldPrivateExtractIconsW, MyPrivateExtractIconsW);
        LONG error = DetourTransactionCommit();

        break;
    }
    case DLL_PROCESS_DETACH:
    {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)OldPrivateExtractIconsW, MyPrivateExtractIconsW);
        LONG error = DetourTransactionCommit();
    }
    }
    return TRUE;
}
