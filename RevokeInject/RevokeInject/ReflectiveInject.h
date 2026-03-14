#pragma once
//来自https://github.com/stephenfewer/ReflectiveDLLInjection
#include <Windows.h>


DWORD GetReflectiveLoaderOffset(VOID* lpReflectiveDllBuffer);

HANDLE WINAPI LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter);


#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

typedef ULONG_PTR(WINAPI* REFLECTIVELOADER)(VOID);
typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);
