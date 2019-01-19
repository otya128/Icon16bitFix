#include <Windows.h>
#include <pshpack1.h>
#define WARN(x)
#define FIXME(x)
#define TRACE(x)
typedef WORD HANDLE16;
/*
 * Resource table structures.
 */
typedef struct
{
    WORD     offset;
    WORD     length;
    WORD     flags;
    WORD     id;
    HANDLE16 handle;
    WORD     usage;
} NE_NAMEINFO;
typedef DWORD FARPROC16;
typedef struct
{
    WORD        type_id;   /* Type identifier */
    WORD        count;     /* Number of resources of this type */
    FARPROC16   resloader; /* SetResourceHandler() */
    /*
     * Name info array.
     */
} NE_TYPEINFO;

#define NE_RSCTYPE_CURSOR             0x8001
#define NE_RSCTYPE_BITMAP             0x8002
#define NE_RSCTYPE_ICON               0x8003
#define NE_RSCTYPE_MENU               0x8004
#define NE_RSCTYPE_DIALOG             0x8005
#define NE_RSCTYPE_STRING             0x8006
#define NE_RSCTYPE_FONTDIR            0x8007
#define NE_RSCTYPE_FONT               0x8008
#define NE_RSCTYPE_ACCELERATOR        0x8009
#define NE_RSCTYPE_RCDATA             0x800a
#define NE_RSCTYPE_GROUP_CURSOR       0x800c
#define NE_RSCTYPE_GROUP_ICON         0x800e
#define NE_RSCTYPE_SCALABLE_FONTPATH  0x80cc   /* Resource found in .fot files */

/*************************************************************************
*			USER32_LoadResource
*/
static BYTE * USER32_LoadResource(LPBYTE peimage, NE_NAMEINFO* pNInfo, WORD sizeShift, ULONG *uSize)
{
    TRACE("%p %p 0x%08x\n", peimage, pNInfo, sizeShift);

    *uSize = (DWORD)pNInfo->length << sizeShift;
    return peimage + ((DWORD)pNInfo->offset << sizeShift);
}
typedef struct
{
    BYTE        bWidth;          /* Width, in pixels, of the image	*/
    BYTE        bHeight;         /* Height, in pixels, of the image	*/
    BYTE        bColorCount;     /* Number of colors in image (0 if >=8bpp) */
    BYTE        bReserved;       /* Reserved ( must be 0)		*/
    WORD        wPlanes;         /* Color Planes			*/
    WORD        wBitCount;       /* Bits per pixel			*/
    DWORD       dwBytesInRes;    /* How many bytes in this resource?	*/
    DWORD       dwImageOffset;   /* Where in the file is this image?	*/
} icoICONDIRENTRY, *LPicoICONDIRENTRY;
typedef struct
{
    WORD            idReserved;   /* Reserved (must be 0) */
    WORD            idType;       /* Resource Type (RES_ICON or RES_CURSOR) */
    WORD            idCount;      /* How many images */
    icoICONDIRENTRY idEntries[1]; /* An entry for each image (idCount of 'em) */
} icoICONDIR, *LPicoICONDIR;
/*************************************************************************
*                      ICO_LoadIcon
*/
static BYTE * ICO_LoadIcon(LPBYTE peimage, LPicoICONDIRENTRY lpiIDE, ULONG *uSize)
{
    TRACE("%p %p\n", peimage, lpiIDE);

    *uSize = lpiIDE->dwBytesInRes;
    return peimage + lpiIDE->dwImageOffset;
}
char *get_search_path()
{
    return NULL;
}

UINT NE_ExtractIcon(LPCWSTR lpszExeFileName,
    HICON * RetPtr,
    INT nIconIndex,
    UINT nIcons,
    UINT cxDesired,
    UINT cyDesired,
    UINT *pIconId,
    UINT flags)
{
    //user32/exticon.c

    UINT		ret = 0;
    UINT		cx1, cx2, cy1, cy2;
    LPBYTE		pData;
    DWORD		sig;
    HANDLE		hFile;
    UINT16		iconDirCount = 0, iconCount = 0;
    LPBYTE		image;
    HANDLE		fmapping;
    DWORD		fsizeh, fsizel;
    WCHAR		szExePath[MAX_PATH];
    DWORD		dwSearchReturn;

    char *path = get_search_path();
    dwSearchReturn = SearchPathW(NULL, lpszExeFileName, NULL, sizeof(szExePath) / sizeof(szExePath[0]), szExePath, NULL);
    HeapFree(GetProcessHeap(), 0, path);
    if ((dwSearchReturn == 0) || (dwSearchReturn > sizeof(szExePath) / sizeof(szExePath[0])))
    {
        WARN("File %s not found or path too long\n", debugstr_w(lpszExeFileName));
        return -1;
    }
    hFile = CreateFileW(szExePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
    if (hFile == INVALID_HANDLE_VALUE) return 0;
    fsizel = GetFileSize(hFile, &fsizeh);

    /* Map the file */
    fmapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY | SEC_COMMIT, 0, 0, NULL);
    CloseHandle(hFile);
    if (!fmapping)
    {
        WARN("CreateFileMapping error %d\n", GetLastError());
        return 0xFFFFFFFF;
    }

    if (!(image = MapViewOfFile(fmapping, FILE_MAP_READ, 0, 0, 0)))
    {
        WARN("MapViewOfFile error %d\n", GetLastError());
        CloseHandle(fmapping);
        return 0xFFFFFFFF;
    }
    CloseHandle(fmapping);
    cx1 = LOWORD(cxDesired);
    cx2 = HIWORD(cxDesired);
    cy1 = LOWORD(cyDesired);
    cy2 = HIWORD(cyDesired);

    if (pIconId) /* Invalidate first icon identifier */
        *pIconId = 0xFFFFFFFF;

    if (!pIconId) /* if no icon identifier array present use the icon handle array as intermediate storage */
        pIconId = (UINT*)RetPtr;
    const IMAGE_DOS_HEADER *mz_header = image;
    const IMAGE_OS2_HEADER *ne_header;

    if (fsizel < sizeof(*mz_header)) goto end;
    if (mz_header->e_magic != IMAGE_DOS_SIGNATURE) goto end;
    ne_header = (const IMAGE_OS2_HEADER *)((const char *)image + mz_header->e_lfanew);
    if (mz_header->e_lfanew + sizeof(*ne_header) > fsizel) goto end;
    if (ne_header->ne_magic == IMAGE_NT_SIGNATURE) goto end;  /* win32 exe */
    if (ne_header->ne_magic != IMAGE_OS2_SIGNATURE) goto end;

    pData = image + mz_header->e_lfanew + ne_header->ne_rsrctab;
    /* end ico file */
    if (ne_header->ne_rsrctab < ne_header->ne_restab)
    {
        BYTE		*pCIDir = 0;
        NE_TYPEINFO	*pTInfo = (NE_TYPEINFO*)(pData + 2);
        NE_NAMEINFO	*pIconStorage = NULL;
        NE_NAMEINFO	*pIconDir = NULL;
        LPicoICONDIR	lpiID = NULL;
        ULONG		uSize = 0;


        if (pData == (BYTE*)-1)
        {
            FIXME("ICO_GetIconDirectory\n");
            /*
            pCIDir = ICO_GetIconDirectory(peimage, &lpiID, &uSize);	// check for .ICO file
            if (pCIDir)
            {
                iconDirCount = 1; iconCount = lpiID->idCount;
                TRACE("-- icon found %p 0x%08x 0x%08x 0x%08x\n", pCIDir, uSize, iconDirCount, iconCount);
            }
            */
        }
        else while (pTInfo->type_id && !(pIconStorage && pIconDir))
        {
            if (pTInfo->type_id == NE_RSCTYPE_GROUP_ICON)	/* find icon directory and icon repository */
            {
                iconDirCount = pTInfo->count;
                pIconDir = ((NE_NAMEINFO*)(pTInfo + 1));
                TRACE("\tfound directory - %i icon families\n", iconDirCount);
            }
            if (pTInfo->type_id == NE_RSCTYPE_ICON)
            {
                iconCount = pTInfo->count;
                pIconStorage = ((NE_NAMEINFO*)(pTInfo + 1));
                TRACE("\ttotal icons - %i\n", iconCount);
            }
            pTInfo = (NE_TYPEINFO *)((char*)(pTInfo + 1) + pTInfo->count * sizeof(NE_NAMEINFO));
        }

        if ((pIconStorage && pIconDir) || lpiID)	  /* load resources and create icons */
        {
            if (nIcons == 0)
            {
                ret = iconDirCount;
                if (lpiID)	/* *.ico file, deallocate heap pointer*/
                    HeapFree(GetProcessHeap(), 0, pCIDir);
            }
            else if (nIconIndex < iconDirCount)
            {
                UINT16   i, icon;
                if (nIcons > iconDirCount - nIconIndex)
                    nIcons = iconDirCount - nIconIndex;

                for (i = 0; i < nIcons; i++)
                {
                    /* .ICO files have only one icon directory */
                    if (lpiID == NULL)	/* not *.ico */
                        pCIDir = USER32_LoadResource(image, pIconDir + i + nIconIndex, *(WORD*)pData, &uSize);
                    pIconId[i] = LookupIconIdFromDirectoryEx(pCIDir, TRUE, cx1, cy1, flags);
                    if (cx2 && cy2) pIconId[++i] = LookupIconIdFromDirectoryEx(pCIDir, TRUE, cx2, cy2, flags);
                }
                if (lpiID)	/* *.ico file, deallocate heap pointer*/
                    HeapFree(GetProcessHeap(), 0, pCIDir);

                for (icon = 0; icon < nIcons; icon++)
                {
                    pCIDir = NULL;
                    if (lpiID)
                        pCIDir = ICO_LoadIcon(image, lpiID->idEntries + (int)pIconId[icon], &uSize);
                    else
                        for (i = 0; i < iconCount; i++)
                            if (pIconStorage[i].id == ((int)pIconId[icon] | 0x8000))
                                pCIDir = USER32_LoadResource(image, pIconStorage + i, *(WORD*)pData, &uSize);

                    if (pCIDir)
                    {
                        RetPtr[icon] = CreateIconFromResourceEx(pCIDir, uSize, TRUE, 0x00030000,
                            cx1, cy1, flags);
                        if (cx2 && cy2)
                            RetPtr[++icon] = CreateIconFromResourceEx(pCIDir, uSize, TRUE, 0x00030000,
                                cx2, cy2, flags);
                    }
                    else
                        RetPtr[icon] = 0;
                }
                ret = icon;	/* return number of retrieved icons */
            }
        }
    }
    else
    {

    }
end:
    UnmapViewOfFile(image);	/* success */
    return ret;
}


