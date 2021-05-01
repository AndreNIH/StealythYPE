# StealythYPE
Dynamically resolve API function addreses without WINAPI . StealthYPE is the succesor of [MAZE](https://github.com/AndreNIH/MAZE)

# How to use
All operations are performed through the StealtYPE class. 
All of the library's actions are performed through the `StealthYPE` class.
Once you instatiate an object of this class you can obtain the addresses of individual modules and procedures either by their name or through a CRC-32 "hash", using the following methods:
* StealtYPE::getModule
* getModule::getProcedure

If you want to calculate the CRC32 value of a string without having to use any external toos you can use the provided `CCRC32` macro


Note: *The purpose of being able to locate stuff using CRC-32 is to facilitate hiding the name of the desired module or procedure.CRC-32 was used due to it being lightweight and having readily avaliable implementations both at run-time and compile-time, The implemntations used in this solution do not depend  on heavy cryptographic libraries. But the algorithm is hardly sufficient enough for its intended purposes. In the future this is expected to change to adapt a proper hashing algorithm that is more useful for hiding the name of the desired procedure or module against static analysis.*

# Example
```c++
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

	messagebox(0, L"Hello, World", L"StealtYPE", MB_OK);	
}
```

A more complete example can be found in https://github.com/AndreNIH/StealythYPE/blob/master/StealthYPE/example.cpp.

# Credits
Daniel Bahr's [CRC++ library](https://github.com/d-bahr/CRCpp)

Ivor Wanders [C++ Compile Time CRC32](https://gist.github.com/iwanders/8e1cb7b92af2ccf8d1a73450d771f483)

