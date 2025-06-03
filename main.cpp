//DISCLAIMER -- This injector is not meant for malicious purposes and is meant to be a light dev tool for beginners.

/*
This injector was originally made for Call of Duty: Vanguard (cracked/offline) to inject custom code, such as GSC loading etc.
It should work as I changed the process finding stuff to mw2019 shit.
If you get any odd errors, something is wrong with your PC or Windows installation.
Build this app in "Release x64" not debug to avoid issues.

            - purrplee

*/

//includes for functions and other stuff

#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <string>
#include <shlwapi.h>
#include <fstream>     
#include <thread>
#include <chrono>      

// you should be running as admin to begin with, but this is for dummies

bool IsRunningAsAdmin() { //admin handling shit, for people who pressed no on the initial UAC (are you kidding me?)
    BOOL isAdmin = FALSE;
    PSID adminsGroup = NULL;

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminsGroup)) {
        if (!CheckTokenMembership(NULL, adminsGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(adminsGroup);
    }
    return isAdmin == TRUE;
}

void ChangeConsoleTitle(const std::wstring& title) { //changes console window title
    SetConsoleTitleW(title.c_str());
}

void RelaunchAsAdmin() { //relaunch program for admin stuff
    wchar_t szFile[MAX_PATH];
    if (GetModuleFileNameW(NULL, szFile, MAX_PATH)) {
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.fMask = SEE_MASK_DEFAULT;
        sei.hwnd = NULL;
        sei.lpVerb = L"runas";  
        sei.lpFile = szFile;    
        sei.lpParameters = NULL;
        sei.lpDirectory = NULL;
        sei.nShow = SW_SHOWNORMAL;

        ShellExecuteExW(&sei);
    }
}

DWORD GetProcessIdByName(const std::wstring& processName) { //find mw2019 stuff
    DWORD processId = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(snapshot, &pe)) {
            do {
                if (_wcsicmp(processName.c_str(), pe.szExeFile) == 0) {
                    processId = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &pe));
        }
    }
    CloseHandle(snapshot);
    return processId;
}

bool IsVanguardRunning() { //ported to mw2019, don't mind the function name
    DWORD processId = GetProcessIdByName(L"ModernWarfare.exe");
    return processId != 0;
}

bool InjectDLL(const std::wstring& dllPath) { //inject logic + errors
    
    std::ifstream file(dllPath);
    if (!file.good()) {
        std::wcerr << L"DLL file does not exist at: " << dllPath << std::endl;
        return false;
    }

    DWORD processId = GetProcessIdByName(L"ModernWarfare.exe"); //if mw2019 isn't running, error will display
    if (processId == 0) {
        std::wcerr << L"[-] Modern Warfare is not running!" << std::endl;
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId); //failure here usually means invalid perms, if not, make sure mw2019 isn't running with an anticheat/protection
    if (!hProcess) {
        std::wcerr << L"[-] Failed to open handle in mw." << std::endl;
        return false;
    }

    LPVOID remoteMemory = VirtualAllocEx(hProcess, nullptr, dllPath.length() * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); //failure handling for no memory allocation
    if (!remoteMemory) {
        std::wcerr << L"[-] Failed to allocate memory in mw." << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, remoteMemory, dllPath.c_str(), dllPath.length() * sizeof(wchar_t), nullptr)) { //if writing fails, it will exit (and injection will fail)
        std::wcerr << L"[-] Failed to write memory in mw." << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HMODULE kernel32Module = GetModuleHandle(L"kernel32.dll"); //gets kernel32 for functions (no, it does not mean the injector is "kernel level")
    if (!kernel32Module) {
        std::wcerr << L"[-] Failed to get kernel32.dll (this shouldn't happen)." << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    FARPROC loadLibraryWAddr = GetProcAddress(kernel32Module, "LoadLibraryW"); //gets LoadLibrary for injection
    if (!loadLibraryWAddr) {
        std::wcerr << L"[-] Failed to get LoadLibraryW address (you're cooked)" << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)loadLibraryWAddr, remoteMemory, 0, nullptr); //creates thread for injection
    if (!hThread) {
        std::wcerr << L"[-] Failed to create remote thread (idk why it wouldn't tbh)" << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return true;
}

std::wstring GetInjectorFolderPath() { //gets injector path to find dll
    wchar_t path[MAX_PATH];
    if (GetModuleFileNameW(NULL, path, MAX_PATH)) {
        PathRemoveFileSpecW(path);
        return std::wstring(path);
    }
    return L"";
}

int main() {
    std::wstring title = L"Made by purrplee | Injector"; //don't think about changing it, it's not yours lol (unless you heavily mod it, in that case it's alright.)
    ChangeConsoleTitle(title);
    std::wcout << L"[+] Starting the injector..." << std::endl; //not really needed, but oh well, it's not ur code anyway lol

    if (!IsRunningAsAdmin()) {
        std::wcerr << L"[-] This program needs to be run as administrator. Relaunching..." << std::endl;
        RelaunchAsAdmin();
        return 0;
    }

    std::wstring injectorFolder = GetInjectorFolderPath();
    if (injectorFolder.empty()) {
        std::wcerr << L"[-] Failed to get injector folder path." << std::endl; //if this happens you're cooked
        return 1;
    }

    std::wstring dllPath = injectorFolder + L"\\payload.dll"; //dll path finding stuff

   
    std::wcout << L"[+] DLL Path: " << dllPath << std::endl; //displays path of dll for debugging

    if (!InjectDLL(dllPath)) {
        std::wcerr << L"[-] DLL injection failed!" << std::endl; //probably didn't run it as admin, idk how you would fuck that up tbh
        std::this_thread::sleep_for(std::chrono::seconds(3)); 
        return 1;
    }

    if (IsVanguardRunning()) {
        std::wcout << L"[+] DLL injected successfully!" << std::endl; //nice lol
    }
    else {
        std::wcerr << L" is not running!" << std::endl; //run the game first lmao (second check here just in case something messes up)
        std::this_thread::sleep_for(std::chrono::seconds(3)); 
        return 0;
    }

    std::wcout << L"[+] Press any key to exit..." << std::endl; //done (hopefully nothing fucked up lol)
    std::cin.get();

    return 0;
}

/*
Don't call this your own if you distribute it, it's not yours, it's not gonna be undetected either, this is for use in offline games only.
This is for light, easy DLL injection into a target process, it's not meant for loading cheats into online games etc. (you'll get slammed by the anticheat)
If you want a kernel-level injector, make one yourself, or find a base on Unknown Cheats or similar forums.
*/