#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

FARPROC TargetFuncAddress = NULL;
char originByte[6] = "";

// The proxy function will intercept and change the execute flow when API calls the original function
int __stdcall ProxyFunc(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {

	// Unhooking function, rewrite the original bytes
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)TargetFuncAddress, originByte, 6, NULL);
	return MessageBoxA(NULL, "Success", "Success", MB_OK);
}


void InstallHook() {
	HINSTANCE hLib;						// Library handle
	void* HookedFuncAddress = NULL;		// Hooked function address	
	char patch[6] = "";					// A patch contains push instruction
	int oldProtect = 0;					// Protect value, 0 is off

	// Get the address of target function to be hooked, in this case is MessageBoxA
	hLib = LoadLibraryA("user32.dll");
	TargetFuncAddress = GetProcAddress(hLib, "MessageBoxA");

	// Read first 5 bytes of target function
	ReadProcessMemory(GetCurrentProcess(), (LPCVOID)TargetFuncAddress, originByte, 6, NULL);

	// Create a patch contain push instruction: push <HookedFuncAddress>; ret
	HookedFuncAddress = reinterpret_cast<void*>(&ProxyFunc);
	memcpy_s(patch, 1, "\x68", 1);
	memcpy_s(patch + 1, 4, &HookedFuncAddress, 4);
	memcpy_s(patch + 5, 1, "\xC3", 1);

	// Write the path to overwrite the first 5 bytes of target function
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)TargetFuncAddress, patch, 6, NULL);
}


int main(int agrc, char* argv[]) {

	// Call original MessageBox function
	MessageBoxA(NULL, "Origin", "Origin", MB_OK);

	// Install the hook
	InstallHook();

	// Call original MessageBox function with the same params again, this time the text will be modified by Proxy
	MessageBoxA(NULL, "Origin", "Origin", MB_OK);

	return 0;
}