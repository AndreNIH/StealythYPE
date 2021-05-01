#include "stealthy/StealthYPE.h"
#include <cassert>
typedef int(__stdcall* pMessageBoxW)(
	HWND    hWnd,
	LPCWSTR lpText,
	LPCWSTR lpCaption,
	UINT    uType
	);

int main() {
	StealthYPE locator;
	auto messagebox = (pMessageBoxW)locator.getProcedure(
		CCRC32("USER32.dll"),
		CCRC32("MessageBoxW")
	);

	auto messagebox2 = (pMessageBoxW)locator.getProcedure(
		"USER32.dll",
		"MessageBoxW"
	);
	
	assert(messagebox == MessageBoxW, "Resolved address does not match with the real address");
	assert(messagebox == messagebox2, "Address resolved using CRC and plaintext are different");
	messagebox(0, L"Hello, World", L"StealtYPE", MB_OK);
	messagebox2(0, L"and goodbye.", L"StealtYPE", MB_OK);
	
}