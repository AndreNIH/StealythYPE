#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
#include "StealthYPE.h"
#include "CRC/CRC.h"
#include <codecvt>
#include <filesystem>
#include <DbgHelp.h>
#pragma comment( lib, "dbghelp.lib" )

//Utils
std::string ws2s(const std::wstring& wstr) {
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;
	return converterX.to_bytes(wstr);
}

//Lib
PEB* StealthYPE::getPEB(){
	PEB* pPEB = nullptr;
	__asm {
		mov eax, fs: [30h]
		mov pPEB, eax
	}
	return pPEB;
}

auto StealthYPE::getLDRE(const PEB* pPEB) {
	std::vector<LDR_DATA_TABLE_ENTRY> ldrData;
	LIST_ENTRY* first = pPEB->Ldr->InMemoryOrderModuleList.Flink;
	LIST_ENTRY* current = first;
	do {
		auto r = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (r->DllBase)
			ldrData.push_back(*r);
		current = current->Flink;
	} while (first != current);
	return ldrData;
}

PVOID StealthYPE::getModule(uint32_t CRC){
	auto module = std::find_if(
		m_ldrDataEntry.cbegin(),
		m_ldrDataEntry.cend(),
		[CRC](const LDR_DATA_TABLE_ENTRY& e) {
			namespace fs = std::filesystem;
			const std::string file = ws2s(e.FullDllName.Buffer);
			std::string name = fs::path(file).filename().string();
			return CRC == CRC::Calculate(name.data(), name.size(), CRC::CRC_32());
		});
	if (module == m_ldrDataEntry.cend()) return nullptr;
	return module->DllBase;
}

PVOID StealthYPE::getModule(const char* moduleName){
	uint32_t crc = CRC::Calculate(moduleName, std::strlen(moduleName), CRC::CRC_32());
	return getModule(crc);
}

PVOID StealthYPE::getProcedure(PVOID module, uint32_t procedureCRC){
	PIMAGE_NT_HEADERS header = ImageNtHeader(module);
	uint32_t base = reinterpret_cast<uint32_t>(module);
	DWORD exportDescriptorOffset = header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	IMAGE_EXPORT_DIRECTORY* exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + exportDescriptorOffset);
	DWORD* names = reinterpret_cast<DWORD*>(base + exports->AddressOfNames);
	WORD* ordinals = reinterpret_cast<WORD*>(base + exports->AddressOfNameOrdinals);
	DWORD* functions = reinterpret_cast<DWORD*>(base + exports->AddressOfFunctions);
	PVOID target = nullptr;
	for (int i = 0; i < exports->NumberOfNames; i++) {
		std::string name(reinterpret_cast<char*>(base + names[i]));
		if (CRC::Calculate(name.data(),name.size(), CRC::CRC_32()) == procedureCRC) {
			target = reinterpret_cast<PVOID>(base + functions[ordinals[i]]);
			break;
		}
	}
	return target;
}

PVOID StealthYPE::getProcedure(PVOID module, const char* procedureName){
	uint32_t crc = CRC::Calculate(procedureName, std::strlen(procedureName), CRC::CRC_32());
	return getProcedure(module,crc);
}


PVOID StealthYPE::getProcedure(uint32_t moduleCRC, uint32_t procedureCRC){
	PVOID mod = getModule(moduleCRC);
	if (mod) return getProcedure(mod, procedureCRC);
	return nullptr;
}

PVOID StealthYPE::getProcedure(const char* moduleName, const char* procedureName){
	uint32_t crcProc = CRC::Calculate(procedureName, std::strlen(procedureName), CRC::CRC_32());
	uint32_t crcMod = CRC::Calculate(moduleName, std::strlen(moduleName), CRC::CRC_32());
	return getProcedure(crcMod, crcProc);
}

void StealthYPE::rescan(){
	m_ldrDataEntry = getLDRE(m_peb);
}

StealthYPE::StealthYPE() : m_peb(getPEB()) { rescan(); }