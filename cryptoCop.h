 #pragma once

#include <fileapi.h>


// Real functions
BOOL(WINAPI *Real_WriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) = WriteFile;

// Fake functions
BOOL WINAPI Fake_WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);