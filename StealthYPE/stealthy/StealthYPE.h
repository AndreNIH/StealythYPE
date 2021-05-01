#pragma once
#include <Windows.h>
#include <winternl.h>
#include <vector>
#include "CRC/CCRC.h"
class StealthYPE {
private:
	PEB* m_peb = nullptr;
	std::vector<LDR_DATA_TABLE_ENTRY> m_ldrDataEntry;

	PEB* getPEB();
	auto getLDRE(const PEB* pPEB);

public:
	PVOID getModule(uint32_t CRC);
	PVOID getModule(const char* moduleName);
	
	PVOID getProcedure(PVOID module, uint32_t procedureCRC);
	PVOID getProcedure(PVOID module, const char* procedureName);

	PVOID getProcedure(uint32_t moduleCRC, uint32_t procedureCRC);
	PVOID getProcedure(const char* moduleName, const char* procedureName);

	void rescan();
	StealthYPE();
};

