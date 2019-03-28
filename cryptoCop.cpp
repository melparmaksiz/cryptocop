#pragma comment(lib, "detours/detours.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "Shlwapi.lib")

#include <mutex>
#include <vector>
#include <sstream> 
#include <string>
#include <unordered_set>
#include <windows.h>
#include <shlwapi.h>
#include <Tlhelp32.h> 
#include <psapi.h>

#include "detours/detours.h"
#include "cryptocop.h"


#define LOG(msg) \
do  { \
std::ostringstream oss; \
oss << msg << std::endl; \
storeMsg(oss.str()); \
 } while(0);


namespace {
	constexpr int THRESHOLD = 100;
	constexpr int HIGH = 20;
	constexpr int LOW = 1;
	const std::string LOG_PREFIX("\\\\%SHARED_FOLDER_PATH%\\report-");
}

HANDLE handleLogFile = NULL;

std::mutex mutex_;
int maliciousScore = 0;

std::unordered_set<std::string> fileSet;
const std::vector<std::string> highProtectedFolders = { "C:\\%USER_HOME%\\Desktop", "C:\\%USER_HOME%\\Documents", "C:\\%USER_HOME%\\Pictures" };
const std::vector<std::string> nonProtectedFolders = { "C:\\%USER_HOME%\\AppData", "C:\\Windows", "C:\\Program Files" };

const std::string getTime();
void storeMsg(std::string & msg);
bool isSuspicious(const std::string& filePath);
void gracefulExit();


BOOL WINAPI Fake_WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
	char filePath[MAX_PATH];
	DWORD dwRet = GetFinalPathNameByHandle(hFile, filePath, sizeof(filePath), FILE_NAME_NORMALIZED);
	if (dwRet >= MAX_PATH || dwRet == 0)
		filePath[0] = '\0';

	{
		std::unique_lock<std::mutex>  lock(mutex_);
		if (isSuspicious(filePath)) {
			gracefulExit();
		}
	}
	return Real_WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}


BOOL WINAPI DllMain(HMODULE hModule, DWORD Reason, LPVOID lpReserved) {

	switch (Reason) {
	case DLL_PROCESS_ATTACH: {
		DisableThreadLibraryCalls(hModule);
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)Real_WriteFile, Fake_WriteFile);

		DetourTransactionCommit();

		LOG(getTime() << " [ATTACHED]");
		break;
	}
	case DLL_PROCESS_DETACH: {
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)Real_WriteFile, Fake_WriteFile);

		DetourTransactionCommit();
		LOG(getTime() << " [DETACHED]");
		break;
	}

	case DLL_THREAD_ATTACH: // fallthrough
	case DLL_THREAD_DETACH: // fallthrough
	default:
		break;
	}

	return TRUE;
}

const std::string getTime() {
	unsigned __int64 currentTime = std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::system_clock::now().time_since_epoch()).count();
	return std::to_string(currentTime);
}

std::string getExecName() {
	char szExeName[MAX_PATH];
	char* pszExeName = szExeName;
	GetModuleFileNameA(0, szExeName, MAX_PATH);

	PCHAR psz = szExeName;
	while (*psz) {
		psz++;
	}

	while (psz > szExeName && psz[-1] != ':' && psz[-1] != '\\' && psz[-1] != '/') {
		psz--;
	}
	pszExeName = psz;
	while (*psz && *psz != '.') {
		psz++;
	}
	*psz = '\0';

	return  std::string(pszExeName);
}

void storeMsg(std::string& msg) {
	if (handleLogFile == NULL || handleLogFile == INVALID_HANDLE_VALUE) {
		std::ostringstream logfile;
		logfile << LOG_PREFIX << getExecName() << "-" << GetCurrentProcessId() << ".dll";
		handleLogFile = CreateFile(logfile.str().c_str(), FILE_APPEND_DATA, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	}
	DWORD dwBytesWritten = 0;
	Real_WriteFile(handleLogFile, msg.c_str(), msg.size(), &dwBytesWritten, NULL);
}

bool isInFolders(const std::string& filePath, const std::vector<std::string>& folders) {
	const auto pos = filePath.find_first_not_of(":?/\\");
	const char *begin = filePath.c_str() + pos;

	for (const auto & folder : folders) {
		if (PathIsPrefix(folder.c_str(), begin)) {
			return true;
		}
	}
	return false;
}

void recalculateMaliciousScore(const std::string& filePath) {
	if (isInFolders(filePath, nonProtectedFolders)) {
		LOG(getTime() <<" [NONPROTECTED] " << filePath);
		return;
	}

	bool isHighProtected = isInFolders(filePath, highProtectedFolders);

	auto result = fileSet.insert(filePath);
	if (result.second) {
		maliciousScore += isHighProtected ? HIGH : LOW;
		LOG(getTime() << (isHighProtected ? " [HIGH] " : " [LOW] ") << maliciousScore << " "<<filePath);
	}
}

bool isSuspicious(const std::string& filePath) {
	recalculateMaliciousScore(filePath);
	if (maliciousScore < THRESHOLD)
		return false;

	LOG(getTime() << " [MAXWRITE_EXCEEDED]");
	return true;
}

std::string getProcessName(DWORD procID) {
	HANDLE myProc = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
	if (!myProc) {
		LOG(getTime() <<  " " << procID << " Open Process Failed. Return empty as name. Error Code:" << GetLastError());
		return std::string();
	}

	char buffer[MAX_PATH];
	std::string result;
	if (GetProcessImageFileName(myProc, buffer, MAX_PATH)) {
		char* basename = strrchr(buffer, '\\');
		result.assign(basename ? basename + 1: buffer);
	} else {
		LOG(getTime() << " " <<procID << " Process Name is assigneed empty string. Error Code:" << GetLastError());
	}
	CloseHandle(myProc);
	return result;
}

void KillProcess(DWORD procID) {
	LOG(getTime() << " [KILL PROCESS] " << procID);
	HANDLE hChildProc = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
	if (hChildProc) {
		::TerminateProcess(hChildProc, 1);
		::CloseHandle(hChildProc);
	}
}

void __fastcall KillProcessTree(DWORD procID, DWORD killerID){
	LOG(getTime() << " [KILL PROCESS TREE] " << getProcessName(procID) << ":" << procID << "  KILLER PROCESS:" << killerID);
	// this cant happen but just to be safe
	if (!procID) return;
	//do not kill self now.
	if (procID == killerID) return;

	PROCESSENTRY32 pe;

	memset(&pe, 0, sizeof(PROCESSENTRY32));
	pe.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	BOOL flag = ::Process32First(hSnap, &pe);

	while(flag)  {
		if (pe.th32ParentProcessID == procID) {
			KillProcessTree(pe.th32ProcessID, killerID); //recursion
		}
		flag = ::Process32Next(hSnap, &pe);
	}
	KillProcess(procID);
}

// todo : getParentProcess should consider start times in case PIDs are reused by OS
// pass start time as parameter, if I am younger than my child then I am not the parent :)
DWORD getParentProcess(DWORD procID) {
	std::string exeName = getProcessName(procID);
	LOG(getTime() << " [PARENT PROCESS SEARCH] " << exeName << ":" << procID);

	if (strcmp(exeName.c_str(), "cmd.exe") == 0 || strcmp(exeName.c_str(), "explorer.exe") == 0 ||
		strcmp(exeName.c_str(), "services.exe") == 0 || strcmp(exeName.c_str(), "wininit.exe") == 0)
	{
			LOG(getTime() << " Parent is CMD||Explorer||Services||wininit. Accepted 0.");
			return 0;
	}

	PROCESSENTRY32 pe;
	memset(&pe, 0, sizeof(PROCESSENTRY32));
	pe.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	BOOL flag = ::Process32First(hSnap, &pe);

	while (flag) {
		if (pe.th32ProcessID == procID) {
			if (pe.th32ParentProcessID == 0 || pe.th32ParentProcessID == 4) {
				return procID;
			}

			LOG(getTime() << " Parent: " << pe.th32ParentProcessID << " Child: " << procID);
			DWORD parentId = getParentProcess(pe.th32ParentProcessID);
			return parentId ? parentId : procID;
		}
		flag = ::Process32Next(hSnap, &pe);
	}
	LOG(getTime() << " Parent not exist " << exeName << " : "<< procID);
	return procID;
}

void gracefulExit() {
	LOG(getTime() << " [EXIT_PROCESS]");

	DWORD currentProcId = GetCurrentProcessId();
	DWORD parentProcId = getParentProcess(currentProcId);

	KillProcessTree(parentProcId, currentProcId);

	LOG(getTime() << " [KILL MAIN]");
	CloseHandle(handleLogFile);
	KillProcess(currentProcId);
}
