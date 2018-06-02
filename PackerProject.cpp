#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <tchar.h>
#include <string.h>
#include <stdio.h>
#include "aPLib\aplib.h"
#pragma comment (lib, ".\\aPLib\\aplib.lib")

#define db(x) __asm _emit x

#define UPX_BACKUP_SIZE 0x3000
#define UPX_SECTION_SIZE 0x1000
#define UPX_ALIGN_BOUND 0x1000
#define PADDING_IMPORT 0x400

class PE32StandardInfo {
public:
	CHAR ImagePath[MAX_PATH];

	HANDLE hFile;
	HANDLE hMap;
	LPVOID lpBase;

	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS32 pNtHeader;
	PIMAGE_SECTION_HEADER pSectionHeader;

	PIMAGE_IMPORT_DESCRIPTOR pIID;

	PIMAGE_EXPORT_DIRECTORY pEAT;
	PDWORD pAddrOfFunc;
	PDWORD pAddrOfNamePtr;
	PWORD pAddrOfOrdinal;

	PE32StandardInfo(LPCSTR ImagePath)
	{
		strcpy(this->ImagePath, ImagePath);

		hFile = CreateFileA(this->ImagePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
		hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, NULL, GetFileSize(hFile, NULL), NULL);
		lpBase = MapViewOfFile(hMap, FILE_MAP_READ, NULL, NULL, NULL);

		pDosHeader = (PIMAGE_DOS_HEADER)lpBase;
		pNtHeader = (PIMAGE_NT_HEADERS32)((DWORD)lpBase + pDosHeader->e_lfanew);
		pSectionHeader = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(pNtHeader);

		pIID = (PIMAGE_IMPORT_DESCRIPTOR)this->RvaToRaw(pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		if (pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
		{
			pEAT = (PIMAGE_EXPORT_DIRECTORY)this->RvaToRaw(pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			pAddrOfFunc = (PDWORD)this->RvaToRaw(pEAT->AddressOfFunctions);
			pAddrOfNamePtr = (PDWORD)this->RvaToRaw(pEAT->AddressOfNames);
			pAddrOfOrdinal = (PWORD)this->RvaToRaw(pEAT->AddressOfNameOrdinals);
		}
	}

	LPVOID RvaToRaw(DWORD dwRVA)
	{
		for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
		{
			if (pSectionHeader[i].VirtualAddress < dwRVA && dwRVA < (pSectionHeader[i].VirtualAddress + pSectionHeader[i].Misc.VirtualSize))
			{
				return (LPVOID)((DWORD)lpBase + dwRVA - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData);
			}
		}

		return NULL;
	}

	DWORD RawToRva(DWORD dwRaw)
	{
		for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
		{
			if (pSectionHeader[i].PointerToRawData < dwRaw && dwRaw < pSectionHeader[i + 1].PointerToRawData)
			{
				return dwRaw - pSectionHeader[i].PointerToRawData + pSectionHeader[i].VirtualAddress;
			}
		}
	}

	~PE32StandardInfo()
	{
		CloseHandle(hFile);
		CloseHandle(hMap);
	}
};

unsigned int align_to_boundary(unsigned int address, unsigned int boundary) {
	return (((address + boundary - 1) / boundary) * boundary);
}

__declspec(naked) int ShellcodeStart(void)
{
	__asm {
			nop						// 32비트의 주소를 맞추기 위하여 nop 명령어를 사용한다.
			nop
			nop
			push   0xAAAAAAAA		// Source.
			nop
			nop
			nop
			push   0xBBBBBBBB		// Destination.

			pushad
			mov    esi, [esp + 36]
			mov    edi, [esp + 32]
			cld
			mov    dl, 80h
			xor    ebx, ebx

		literally:
			movsb
			mov    bl, 2

			nexttag :
			call   getbit
			jnc    literally
			xor    ecx, ecx
			call   getbit
			jnc    codepair
			xor    eax, eax
			call   getbit
			jnc    shortmatch
			mov    bl, 2
			inc    ecx
			mov    al, 10h

		getmorebits :
			call   getbit
			adc    al, al
			jnc    getmorebits
			jnz    domatch
			stosb
			jmp    nexttag

		codepair :
			call   getgamma_no_ecx
			sub    ecx, ebx
			jnz    normalcodepair
			call   getgamma
			jmp    domatch_lastpos

		shortmatch :
			lodsb
			shr    eax, 1
			jz     donedepacking
			adc    ecx, ecx
			jmp    domatch_with_2inc

		normalcodepair :
			xchg   eax, ecx
			dec    eax
			shl    eax, 8
			lodsb
			call   getgamma
			cmp    eax, 32000
			jae    domatch_with_2inc
			cmp    ah, 5
			jae    domatch_with_inc
			cmp    eax, 7fh
			ja     domatch_new_lastpos

		domatch_with_2inc :
			inc    ecx

		domatch_with_inc :
			inc    ecx

		domatch_new_lastpos :
			xchg   eax, ebp

		domatch_lastpos :
			mov    eax, ebp
			mov    bl, 1

		domatch :
			push   esi
			mov    esi, edi
			sub    esi, eax
			rep    movsb
			pop    esi
			jmp    nexttag

		getbit :
			add    dl, dl
			jnz    stillbitsleft
			mov    dl, [esi]
			inc    esi
			adc    dl, dl

		stillbitsleft :
			ret

		getgamma :
			xor    ecx, ecx

		getgamma_no_ecx :
			inc    ecx

		getgammaloop :
			call   getbit
			adc    ecx, ecx
			call   getbit
			jc     getgammaloop
			ret

		donedepacking :
			popad
	}
}

VOID ShellCodeEnd() {}

LPBYTE GetPackedBufferWithHeaders(PE32StandardInfo * lpFile);
BOOL SetImportRecoveryData(PE32StandardInfo * lpFile, LPBYTE lpPackedBase);
BOOL GetFuncNameWithOrdinal(HMODULE hMod, WORD Ordinal, PCHAR Name);
BOOL SetNewImportTable(PE32StandardInfo * lpFile, LPBYTE lpPackedBase);
BOOL GetSectionsData(PE32StandardInfo * lpFile);
BOOL SetUnpackCode(PE32StandardInfo * lpFile, LPBYTE lpPackedBase);
BOOL MovePackedBuffer(LPBYTE lpPackedBase);

HANDLE hHeap;
LPBYTE lpPackedBase = NULL;

LPBYTE lpOrigBuffer = NULL, lpPackedBuffer = NULL, lpWorkMemBuffer;
DWORD dwOrigSize = NULL, dwPackedSize = NULL, dwWorkMemSize = NULL;

DWORD dwUPX0, dwUPX1, dwUPX2, dwUPX3, dwUPX4;
DWORD dwRvaUPX0, dwRvaUPX1, dwRvaUPX2, dwRvaUPX3, dwRvaUPX4;

DWORD posOrgIDT, posDongIDT, VirtualAddressIDT, IDTSize, IDTSection, IDTSectionSize;
DWORD GarbageMemory, JumpToMedium, JumpToRealCode, posIATRVA, Temp;
DWORD g_posKERNEL32, g_posLoadLibraryA, g_posGetProcAddress, g_posVirtualProtect, posName;

int main() {
	PE32StandardInfo SrcFile("C:\\LinkParser.exe");
	lpPackedBase = GetPackedBufferWithHeaders(&SrcFile);
	GetSectionsData(&SrcFile);
	SetNewImportTable(&SrcFile, lpPackedBase);
	SetImportRecoveryData(&SrcFile, lpPackedBase);
	MovePackedBuffer(lpPackedBase);
	SetUnpackCode(&SrcFile, lpPackedBase);

	DWORD dwNum;
	HANDLE hFile = CreateFile("C:\\LinkParser_Packed.exe", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(hFile, (LPVOID)lpPackedBase, UPX_ALIGN_BOUND + dwPackedSize + UPX_SECTION_SIZE * 2 + UPX_BACKUP_SIZE, &dwNum, NULL);
	CloseHandle(hFile);

	HeapFree(hHeap, NULL, lpPackedBase);
	HeapDestroy(hHeap);

	free(lpOrigBuffer);
	free(lpPackedBuffer);
	free(lpWorkMemBuffer);

	getchar();
	return 0;
}

LPBYTE GetPackedBufferWithHeaders(PE32StandardInfo * lpFile)
{
	LPBYTE lpPackedBase = NULL; // 패킹된 바이너리의 베이스

	IMAGE_DOS_HEADER DosHeader = { 0, }; // 헤더 구조체 할당
	IMAGE_NT_HEADERS32 NtHeader = { 0, };
	IMAGE_SECTION_HEADER SectionHeader[5] = { 0, };

	for (INT i = 0; i < lpFile->pNtHeader->FileHeader.NumberOfSections; i++) // 원본 바이너리의 메모리에 올려진 상태의 크기 구하기
		dwOrigSize += align_to_boundary(lpFile->pSectionHeader[i].Misc.VirtualSize, lpFile->pNtHeader->OptionalHeader.SectionAlignment);

	dwPackedSize = align_to_boundary(aP_max_packed_size(dwOrigSize), UPX_ALIGN_BOUND); // 압축된 상태의 크기 구하기
	dwWorkMemSize = aP_workmem_size(dwOrigSize); // 압축하는데 필요한 버퍼의 크기 구하기

	lpOrigBuffer = (LPBYTE)malloc(dwOrigSize); // 이후 사용할 버퍼를 할당한다
	lpPackedBuffer = (LPBYTE)malloc(dwPackedSize);
	lpWorkMemBuffer = (LPBYTE)malloc(dwWorkMemSize);

	GetSectionsData(lpFile); // 미리 압축을 시도하여 패킹된 바이너리의 크기를 구한다
	dwPackedSize = align_to_boundary(aP_pack(lpOrigBuffer, lpPackedBuffer, dwOrigSize, lpWorkMemBuffer, NULL, NULL), UPX_ALIGN_BOUND);

	dwOrigSize = align_to_boundary(dwOrigSize, UPX_ALIGN_BOUND);

	SecureZeroMemory(lpOrigBuffer, dwOrigSize); // 사용한 버퍼를 널로 초기화
	SecureZeroMemory(lpPackedBuffer, align_to_boundary(aP_max_packed_size(dwOrigSize), UPX_ALIGN_BOUND));

	// DOS HEADER 구성하기
	DosHeader.e_magic = IMAGE_DOS_SIGNATURE; 
	DosHeader.e_lfanew = sizeof(IMAGE_DOS_HEADER);

	NtHeader.Signature = IMAGE_NT_SIGNATURE; // NT 시그니처
	
	// FILE HEADER 구성하기
	NtHeader.FileHeader.Machine = IMAGE_FILE_MACHINE_I386; 
	NtHeader.FileHeader.Characteristics = lpFile->pNtHeader->FileHeader.Characteristics;
	NtHeader.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
	NtHeader.FileHeader.NumberOfSections = 5;

	// Optional Header 구성하기
	NtHeader.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
	NtHeader.OptionalHeader.AddressOfEntryPoint = UPX_ALIGN_BOUND + dwOrigSize + dwPackedSize; // UPX2의 RVA = SizeOfHeaders + UPX0's RVA + UPX1's RVA
	NtHeader.OptionalHeader.FileAlignment = 0x1000;
	NtHeader.OptionalHeader.SectionAlignment = 0x1000; // 코딩을 간편하게 하기 위해 FileAlignment와 SectionAlignment를 같게 한다.
	NtHeader.OptionalHeader.ImageBase = lpFile->pNtHeader->OptionalHeader.ImageBase;
	NtHeader.OptionalHeader.MajorOperatingSystemVersion = lpFile->pNtHeader->OptionalHeader.MajorOperatingSystemVersion;
	NtHeader.OptionalHeader.MajorSubsystemVersion = lpFile->pNtHeader->OptionalHeader.MajorSubsystemVersion;
	NtHeader.OptionalHeader.Subsystem = lpFile->pNtHeader->OptionalHeader.Subsystem;
	NtHeader.OptionalHeader.SizeOfImage = UPX_ALIGN_BOUND + dwOrigSize + dwPackedSize + UPX_SECTION_SIZE * 2 + UPX_BACKUP_SIZE; // SizeOfHeaders + UPX0~4
	NtHeader.OptionalHeader.BaseOfCode = 0x1000;
	NtHeader.OptionalHeader.BaseOfData = 0x1000 + dwOrigSize + dwPackedSize + UPX_SECTION_SIZE;
	NtHeader.OptionalHeader.SizeOfCode = dwOrigSize + dwPackedSize + UPX_SECTION_SIZE;
	NtHeader.OptionalHeader.SizeOfInitializedData = UPX_SECTION_SIZE + UPX_BACKUP_SIZE;
	NtHeader.OptionalHeader.SizeOfUninitializedData = 0;
	NtHeader.OptionalHeader.SizeOfHeaders = 0x1000;
	NtHeader.OptionalHeader.SizeOfHeapCommit = 0x1000;
	NtHeader.OptionalHeader.SizeOfHeapReserve = 0x100000;
	NtHeader.OptionalHeader.SizeOfStackCommit = 0x1000;
	NtHeader.OptionalHeader.SizeOfStackReserve = 0x100000;
	NtHeader.OptionalHeader.NumberOfRvaAndSizes = 0x10;

	// UPX3 RVA
	NtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = UPX_ALIGN_BOUND + dwOrigSize + dwPackedSize + UPX_SECTION_SIZE;
	NtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2;

	// 리소스 섹션 RVA는 원본 그대로
	if (lpFile->pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress != NULL)
	{
		NtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = lpFile->pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
		NtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = lpFile->pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
	}

	// 섹션 헤더 구성
	_tcscpy((PCHAR)SectionHeader[0].Name, ".Uchiha");
	SectionHeader[0].Misc.VirtualSize = dwOrigSize;
	SectionHeader[0].SizeOfRawData = NULL;
	SectionHeader[0].VirtualAddress = UPX_ALIGN_BOUND;
	SectionHeader[0].PointerToRawData = UPX_ALIGN_BOUND;
	SectionHeader[0].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;

	dwUPX0 = SectionHeader[0].PointerToRawData;
	dwRvaUPX0 = SectionHeader[0].VirtualAddress;

	_tcscpy((PCHAR)SectionHeader[1].Name, ".Uchiha");
	SectionHeader[1].Misc.VirtualSize = dwPackedSize;
	SectionHeader[1].SizeOfRawData = dwPackedSize;
	SectionHeader[1].VirtualAddress = SectionHeader[0].VirtualAddress + SectionHeader[0].Misc.VirtualSize;
	SectionHeader[1].PointerToRawData = SectionHeader[0].PointerToRawData + SectionHeader[0].SizeOfRawData;
	SectionHeader[1].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;

	dwUPX1 = SectionHeader[1].PointerToRawData;
	dwRvaUPX1 = SectionHeader[1].VirtualAddress;

	_tcscpy((PCHAR)SectionHeader[2].Name, ".Uchiha");
	SectionHeader[2].Misc.VirtualSize = UPX_SECTION_SIZE;
	SectionHeader[2].SizeOfRawData = UPX_SECTION_SIZE;
	SectionHeader[2].VirtualAddress = SectionHeader[1].VirtualAddress + SectionHeader[1].Misc.VirtualSize;
	SectionHeader[2].PointerToRawData = SectionHeader[1].PointerToRawData + SectionHeader[1].SizeOfRawData;
	SectionHeader[2].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;

	dwUPX2 = SectionHeader[2].PointerToRawData;
	dwRvaUPX2 = SectionHeader[2].VirtualAddress;

	_tcscpy((PCHAR)SectionHeader[3].Name, ".Uchiha");
	SectionHeader[3].Misc.VirtualSize = UPX_SECTION_SIZE;
	SectionHeader[3].SizeOfRawData = UPX_SECTION_SIZE;
	SectionHeader[3].VirtualAddress = SectionHeader[2].VirtualAddress + SectionHeader[2].Misc.VirtualSize;
	SectionHeader[3].PointerToRawData = SectionHeader[2].PointerToRawData + SectionHeader[2].SizeOfRawData;
	SectionHeader[3].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

	dwUPX3 = SectionHeader[3].PointerToRawData;
	dwRvaUPX3 = SectionHeader[3].VirtualAddress;

	_tcscpy((PCHAR)SectionHeader[4].Name, ".Uchiha");
	SectionHeader[4].Misc.VirtualSize = UPX_BACKUP_SIZE;
	SectionHeader[4].SizeOfRawData = UPX_BACKUP_SIZE;
	SectionHeader[4].VirtualAddress = SectionHeader[3].VirtualAddress + SectionHeader[3].Misc.VirtualSize;
	SectionHeader[4].PointerToRawData = SectionHeader[3].PointerToRawData + SectionHeader[3].SizeOfRawData;
	SectionHeader[4].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;

	dwUPX4 = SectionHeader[4].PointerToRawData;
	dwRvaUPX4 = SectionHeader[4].VirtualAddress;

	// 패킹된 PE가 쓰여질 메모리 할당
	hHeap = GetProcessHeap();
	lpPackedBase = (LPBYTE)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, (UPX_ALIGN_BOUND + dwPackedSize + UPX_SECTION_SIZE * 2 + UPX_BACKUP_SIZE));

	CopyMemory(lpPackedBase, &DosHeader, sizeof(IMAGE_DOS_HEADER));
	CopyMemory(lpPackedBase + sizeof(IMAGE_DOS_HEADER), &NtHeader, sizeof(IMAGE_NT_HEADERS32));
	CopyMemory(lpPackedBase + sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS32), SectionHeader, sizeof(SectionHeader));

	return lpPackedBase;
}

BOOL SetImportRecoveryData(PE32StandardInfo * lpFile, LPBYTE lpPackedBase)	// 함수명 옮김
{
	LPBYTE lpImportBackup = lpPackedBase + dwUPX4;
	DWORD WrittenByte = 0;

	PIMAGE_IMPORT_DESCRIPTOR pIID = lpFile->pIID;
	PIMAGE_IMPORT_BY_NAME pIBN = NULL;

	HMODULE hMod;
	WORD wOrdinal;
	LPDWORD lpdwRvaINT = NULL;
	TCHAR szFuncName[100];

	memcpy(lpImportBackup, lpFile->pIID, lpFile->pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
	WrittenByte += lpFile->pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

	while (pIID->Name != 0x00000000 && pIID->FirstThunk != 0x00000000)
	{
		if (pIID->OriginalFirstThunk == 0x00000000)	// INT가 0이라면
			lpdwRvaINT = (LPDWORD)lpFile->RvaToRaw(pIID->FirstThunk);
		else
			lpdwRvaINT = (LPDWORD)lpFile->RvaToRaw(pIID->OriginalFirstThunk);

		memset(lpImportBackup + WrittenByte++, 0xDE, sizeof(BYTE));
		memset(lpImportBackup + WrittenByte++, 0xAD, sizeof(BYTE));

		memcpy(lpImportBackup + WrittenByte, lpFile->RvaToRaw(pIID->Name), strlen((PCHAR)lpFile->RvaToRaw(pIID->Name)));
		WrittenByte += strlen((PCHAR)lpFile->RvaToRaw(pIID->Name));

		memset(lpImportBackup + WrittenByte++, 0x00, sizeof(BYTE));

		while (*lpdwRvaINT != 0x00000000)
		{
			pIBN = (PIMAGE_IMPORT_BY_NAME)(lpFile->RvaToRaw(*lpdwRvaINT));

			if ((*lpdwRvaINT & 0x80000000) == 0x80000000)	// Ordinal로 함수를 임포트할때
			{
				hMod = LoadLibraryA((LPCSTR)lpFile->RvaToRaw(pIID->Name));
				wOrdinal = (WORD)*lpdwRvaINT;

				GetFuncNameWithOrdinal(hMod, wOrdinal, szFuncName);

				memcpy(lpImportBackup + WrittenByte, szFuncName, strlen(szFuncName)), WrittenByte += strlen(szFuncName);
				memset(lpImportBackup + WrittenByte++, 0x00, sizeof(BYTE));

				*((LPDWORD)((LPBYTE)lpdwRvaINT - (LPBYTE)lpFile->lpBase + lpOrigBuffer - UPX_ALIGN_BOUND)) = 0x00000000;	// 외부 Ordinal 지움
			}
			else
			{
				memcpy(lpImportBackup + WrittenByte, pIBN->Name, strlen(pIBN->Name));
				WrittenByte += strlen(pIBN->Name);
				memset(lpImportBackup + WrittenByte++, 0x00, sizeof(BYTE));

				memset(lpOrigBuffer + *lpdwRvaINT - UPX_ALIGN_BOUND, NULL, strlen(pIBN->Name) + sizeof(BYTE) * 2);	// 함수명, Ordinal 지움
			}

			memset(lpOrigBuffer + pIID->Name - UPX_ALIGN_BOUND, NULL, strlen((PCHAR)lpFile->RvaToRaw(pIID->Name)));	// DLL이름 지움
			lpdwRvaINT++;
		}
		pIID++;
	}

	return 0;
}

BOOL GetFuncNameWithOrdinal(HMODULE hMod, WORD Ordinal, PCHAR Name)		// 모듈에서 함수가 Ordinal로 익스포트되는 경우
{
	LPBYTE LibraryBase = (LPBYTE)hMod;

	LPDWORD AddressOfNamesRVA;
	LPWORD AddressOfNameOrdinalsRVA;

	DWORD NameIndex = 0;

	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)LibraryBase;
	PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)(LibraryBase + pIDH->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pIED;

	pIED = (PIMAGE_EXPORT_DIRECTORY)(LibraryBase + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	AddressOfNamesRVA = (LPDWORD)(LibraryBase + pIED->AddressOfNames);
	AddressOfNameOrdinalsRVA = (LPWORD)(LibraryBase + pIED->AddressOfNameOrdinals);

	while (TRUE)
	{
		if (AddressOfNameOrdinalsRVA[NameIndex] == (Ordinal - pIED->Base))
			break;

		NameIndex++;
	}

	strcpy(Name, (PCHAR)(LibraryBase + AddressOfNamesRVA[NameIndex]));

	return 0;
}

BOOL SetNewImportTable(PE32StandardInfo * lpFile, LPBYTE lpPackedBase)
{
	IMAGE_IMPORT_DESCRIPTOR KERNEL32 = { 0, };

	KERNEL32.FirstThunk = dwRvaUPX3 + PADDING_IMPORT;
	KERNEL32.Name = KERNEL32.FirstThunk + PADDING_IMPORT;

	memcpy(lpPackedBase + dwUPX3, &KERNEL32, sizeof(IMAGE_IMPORT_DESCRIPTOR));

	memcpy(lpPackedBase + KERNEL32.Name - dwRvaUPX3 + dwUPX3, "KERNEL32.dll\0", strlen("KERNEL32.dll") + sizeof(BYTE));

	g_posKERNEL32 = lpFile->pNtHeader->OptionalHeader.ImageBase + KERNEL32.Name;

	DWORD posLoadLibraryA = KERNEL32.Name + strlen("KERNEL32.dll") + sizeof(BYTE);
	memcpy(lpPackedBase + posLoadLibraryA - dwRvaUPX3 + dwUPX3, "\0\0LoadLibraryA\0", strlen("LoadLibraryA") + sizeof(BYTE) * 3);

	DWORD posGetProcAddress = posLoadLibraryA + sizeof(BYTE) * 2 + strlen("LoadLibraryA") + sizeof(BYTE);
	memcpy(lpPackedBase + posGetProcAddress - dwRvaUPX3 + dwUPX3, "\0\0GetProcAddress\0", strlen("GetProcAddress") + sizeof(BYTE) * 3);

	DWORD posVirtualProtect = posGetProcAddress + sizeof(BYTE) * 2 + strlen("GetProcAddress") + sizeof(BYTE);
	memcpy(lpPackedBase + posVirtualProtect - dwRvaUPX3 + dwUPX3, "\0\0VirtualProtect\0", strlen("VirtualProtect") + sizeof(BYTE) * 3);

	DWORD posExitProcess = posVirtualProtect + sizeof(BYTE) * 2 + strlen("VirtualProtect") + sizeof(BYTE);
	memcpy(lpPackedBase + posExitProcess - dwRvaUPX3 + dwUPX3, "\0\0ExitProcess\0", strlen("ExitProcess") + sizeof(BYTE) * 3);

	DWORD posIAT = KERNEL32.FirstThunk;

	g_posLoadLibraryA = lpFile->pNtHeader->OptionalHeader.ImageBase + posIAT;
	memcpy(lpPackedBase + posIAT - dwRvaUPX3 + dwUPX3, &posLoadLibraryA, sizeof(DWORD)), posIAT += sizeof(DWORD);

	g_posGetProcAddress = lpFile->pNtHeader->OptionalHeader.ImageBase + posIAT;
	memcpy(lpPackedBase + posIAT - dwRvaUPX3 + dwUPX3, &posGetProcAddress, sizeof(DWORD)), posIAT += sizeof(DWORD);

	g_posVirtualProtect = lpFile->pNtHeader->OptionalHeader.ImageBase + posIAT;
	memcpy(lpPackedBase + posIAT - dwRvaUPX3 + dwUPX3, &posVirtualProtect, sizeof(DWORD)), posIAT += sizeof(DWORD);

	memcpy(lpPackedBase + posIAT - dwRvaUPX3 + dwUPX3, &posExitProcess, sizeof(DWORD)), posIAT += sizeof(DWORD);
	memset(lpPackedBase + posIAT - dwRvaUPX3 + dwUPX3, 0x00, sizeof(DWORD));

	return TRUE;
}

BOOL GetSectionsData(PE32StandardInfo * lpFile)
{
	LPBYTE lpSrc, lpDst = lpOrigBuffer;

	for (INT i = 0; i < lpFile->pNtHeader->FileHeader.NumberOfSections; i++)
	{
		lpSrc = (LPBYTE)lpFile->lpBase + lpFile->pSectionHeader[i].PointerToRawData;
		CopyMemory(lpDst, lpSrc, lpFile->pSectionHeader[i].SizeOfRawData);
		lpDst += align_to_boundary(lpFile->pSectionHeader[i].Misc.VirtualSize, lpFile->pNtHeader->OptionalHeader.SectionAlignment);
	}

	return TRUE;
}

BOOL MovePackedBuffer(LPBYTE lpPackedBase)
{
	LPBYTE lpDst = lpPackedBase + dwUPX1;
	aP_pack(lpOrigBuffer, lpPackedBuffer, dwOrigSize, lpWorkMemBuffer, NULL, NULL);
	CopyMemory(lpDst, lpPackedBuffer, dwPackedSize);

	return 1;
}

BOOL SetUnpackCode(PE32StandardInfo * lpFile, LPBYTE lpPackedBase)
{
	DWORD ImageBase = lpFile->pNtHeader->OptionalHeader.ImageBase;
	DWORD OriginalEntryPoint = ImageBase + lpFile->pNtHeader->OptionalHeader.AddressOfEntryPoint;

	LPBYTE posDecodeSection = lpPackedBase + dwUPX2;
	DWORD Counter = 0;

	IDTSize = lpFile->pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	VirtualAddressIDT = ImageBase + dwRvaUPX3;

	IDTSection = ImageBase + dwRvaUPX3;
	IDTSectionSize = UPX_SECTION_SIZE;

	posOrgIDT = ImageBase + dwRvaUPX3;
	posDongIDT = ImageBase + dwRvaUPX4;

	GarbageMemory = ImageBase + dwRvaUPX3 + UPX_SECTION_SIZE - 0x8;

	DWORD dwShellCodeSize = ((DWORD)ShellCodeEnd - (DWORD)ShellcodeStart);
	HANDLE hHeap = HeapCreate(0, 0, dwShellCodeSize);
	LPVOID lpHeap = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwShellCodeSize);

	CopyMemory(lpHeap, ShellcodeStart, dwShellCodeSize);

	for (DWORD i = 0; i < dwShellCodeSize; i++) {
		if (*((LPDWORD)lpHeap + i) == 0xAAAAAAAA) {
			*((LPDWORD)lpHeap + i) = lpFile->pNtHeader->OptionalHeader.ImageBase + dwRvaUPX1;
			break;
		}
	}

	for (DWORD i = 0; i < dwShellCodeSize; i++) {
		if (*((LPDWORD)lpHeap + i) == 0xBBBBBBBB) {
			*((LPDWORD)lpHeap + i) = lpFile->pNtHeader->OptionalHeader.ImageBase + dwRvaUPX0;
			break;
		}
	}

	// 언패킹 코드를 써주기
	CopyMemory(lpPackedBase + dwUPX2, lpHeap, dwShellCodeSize);
	posDecodeSection += dwShellCodeSize;

	HeapFree(hHeap, 0, lpHeap);
	HeapDestroy(hHeap);

	// ....... KERNEL32.dll 로드하고, IDT영역에 PAGE_READWRITE 권한을 줌 .......
	// PUSH KERNERL32.dll
	posDecodeSection[Counter++] = 0x68;
	memcpy(&posDecodeSection[Counter], &g_posKERNEL32, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// CALL DWORD PTR DS:[posLoadLibrary] 
	posDecodeSection[Counter++] = 0xFF;
	posDecodeSection[Counter++] = 0x15;
	memcpy(&posDecodeSection[Counter], &g_posLoadLibraryA, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// PUSH GarbageMemory
	posDecodeSection[Counter++] = 0x68;
	memcpy(&posDecodeSection[Counter], &GarbageMemory, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// PUSH 0x04     (PAGE_READWRITE)
	posDecodeSection[Counter++] = 0x68;
	posDecodeSection[Counter++] = 0x04;
	memset(&posDecodeSection[Counter], 0x00, sizeof(BYTE) * 3);
	Counter += sizeof(BYTE) * 3;


	// PUSH IDTSize
	posDecodeSection[Counter++] = 0x68;
	memcpy(&posDecodeSection[Counter], &IDTSize, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// PUSH VirtualAddressIDT
	posDecodeSection[Counter++] = 0x68;
	memcpy(&posDecodeSection[Counter], &VirtualAddressIDT, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// CALL DWORD PTR DS:[posVirtualProtect]
	posDecodeSection[Counter++] = 0xFF;
	posDecodeSection[Counter++] = 0x15;
	memcpy(&posDecodeSection[Counter], &g_posVirtualProtect, sizeof(DWORD));
	Counter += sizeof(DWORD);
	// ...................................................................


	// ....................... IDT를 복구 .......................
	// XOR ECX, ECX
	posDecodeSection[Counter++] = 0x31;		// Opcode
	posDecodeSection[Counter++] = 0xC9;		// ModR/M


											// MOV EBX, IDTSize ( NULL 구조체는 따로 삽입 할 필요 없음 )
	posDecodeSection[Counter++] = 0xBB;		// Opcode
	memcpy(&posDecodeSection[Counter], &IDTSize, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// MOV DL, BYTE PTR DS:[posDongIDT + ECX]
	JumpToRealCode = ImageBase + dwRvaUPX2 + Counter;
	posDecodeSection[Counter++] = 0x8A;		// Opcode
	posDecodeSection[Counter++] = 0x91;		// ModR/M
	memcpy(&posDecodeSection[Counter], &posDongIDT, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// MOV BYTE PTR DS:[posOrgIDT + ECX], DL
	posDecodeSection[Counter++] = 0x88;		// Opcode
	posDecodeSection[Counter++] = 0x91;		// ModR/M
	memcpy(&posDecodeSection[Counter], &posOrgIDT, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// INC ECX
	posDecodeSection[Counter++] = 0x41;


	// CMP ECX, EBX
	posDecodeSection[Counter++] = 0x39;
	posDecodeSection[Counter++] = 0xD9;


	// JNE JumpTo
	JumpToMedium = JumpToRealCode - 0x6 - (ImageBase + dwRvaUPX2 + Counter);
	posDecodeSection[Counter++] = 0x0F;					// 2 BYTE Opcode
	posDecodeSection[Counter++] = 0x85;
	memcpy(&posDecodeSection[Counter], &JumpToMedium, sizeof(DWORD));
	Counter += sizeof(DWORD);
	// .................................................


	// ...................... IAT를 복구 .......................
	// 끝에 NULL구조체의 크기와 0xDE, 0xAD 두 바이트의 크기를 더함, IAT의 위치값
	posName = ImageBase + dwRvaUPX4 + IDTSize + sizeof(BYTE) * 2;
	posIATRVA = ImageBase + dwRvaUPX4 + sizeof(DWORD) * 4;


	// VirtualProtect()를 사용하여 IAT를 쓸 수 있도록 함
	// PUSH GarbageMemory
	posDecodeSection[Counter++] = 0x68;
	memcpy(&posDecodeSection[Counter], &GarbageMemory, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// PUSH 0x04     (PAGE_READWRITE)
	posDecodeSection[Counter++] = 0x68;
	posDecodeSection[Counter++] = 0x04;
	memset(&posDecodeSection[Counter], 0x00, sizeof(BYTE) * 3);
	Counter += sizeof(BYTE) * 3;


	// PUSH IDTSectionSize
	posDecodeSection[Counter++] = 0x68;
	memcpy(&posDecodeSection[Counter], &IDTSectionSize, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// PUSH IDTSection
	posDecodeSection[Counter++] = 0x68;
	memcpy(&posDecodeSection[Counter], &IDTSection, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// CALL DWORD PTR DS:[posVirtualProtect]
	posDecodeSection[Counter++] = 0xFF;
	posDecodeSection[Counter++] = 0x15;
	memcpy(&posDecodeSection[Counter], &g_posVirtualProtect, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// MOV ESI, 1
	posDecodeSection[Counter++] = 0xBE;
	posDecodeSection[Counter++] = 0x01;
	memset(&posDecodeSection[Counter], 0x00, sizeof(BYTE) * 3);
	Counter += sizeof(BYTE) * 3;


	// MOV EBX, posIATRVA
	posDecodeSection[Counter++] = 0xBB;
	memcpy(&posDecodeSection[Counter], &posIATRVA, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// MOV EDI, ImageBase
	posDecodeSection[Counter++] = 0xBF;
	memcpy(&posDecodeSection[Counter], &ImageBase, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// ADD EDI, [EBX]
	posDecodeSection[Counter++] = 0x03;		// Opcode
	posDecodeSection[Counter++] = 0x3B;		// ModR/M


											// PUSH [posName]
	posDecodeSection[Counter++] = 0x68;
	memcpy(&posDecodeSection[Counter], &posName, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// CALL DWORD PTR DS:[posLoadLibraryA]
	posDecodeSection[Counter++] = 0xFF;
	posDecodeSection[Counter++] = 0x15;
	memcpy(&posDecodeSection[Counter], &g_posLoadLibraryA, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// XOR ECX, ECX
	posDecodeSection[Counter++] = 0x31;
	posDecodeSection[Counter++] = 0xC9;


	// MOV EDX, EAX
	posDecodeSection[Counter++] = 0x89;
	posDecodeSection[Counter++] = 0xC2;


	// CMP BYTE PTR DS:[posName + ECX], 0
	posDecodeSection[Counter++] = 0x80;
	posDecodeSection[Counter++] = 0xB9;
	memcpy(&posDecodeSection[Counter], &posName, sizeof(DWORD));
	Counter += sizeof(DWORD);
	posDecodeSection[Counter++] = 0x00;


	// JNE JumpTo
	JumpToRealCode = ImageBase + dwRvaUPX2 + 0x10A;
	JumpToMedium = JumpToRealCode - 0x6 - (ImageBase + dwRvaUPX2 + Counter);
	posDecodeSection[Counter++] = 0x0F;
	posDecodeSection[Counter++] = 0x85;
	memcpy(&posDecodeSection[Counter], &JumpToMedium, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// INC ECX
	posDecodeSection[Counter++] = 0x41;


	// CMP BYTE PTR DS:[posName + ECX], 0xDE
	posDecodeSection[Counter++] = 0x80;
	posDecodeSection[Counter++] = 0xB9;
	memcpy(&posDecodeSection[Counter], &posName, sizeof(DWORD));
	Counter += sizeof(DWORD);
	posDecodeSection[Counter++] = 0xDE;


	// JNE JumpTo
	JumpToRealCode = ImageBase + dwRvaUPX2 + 0xD2;
	JumpToMedium = JumpToRealCode - 0x6 - (ImageBase + dwRvaUPX2 + Counter);
	posDecodeSection[Counter++] = 0x0F;
	posDecodeSection[Counter++] = 0x85;
	memcpy(&posDecodeSection[Counter], &JumpToMedium, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// CMP BYTE PTR DS:[posName + ECX + ESI], 0xAD
	posDecodeSection[Counter++] = 0x80;
	posDecodeSection[Counter++] = 0xBC;
	posDecodeSection[Counter++] = 0x0E;
	memcpy(&posDecodeSection[Counter], &posName, sizeof(DWORD));
	Counter += sizeof(DWORD);
	posDecodeSection[Counter++] = 0xAD;


	// JNE JumpTo
	JumpToRealCode = ImageBase + dwRvaUPX2 + 0xD2;
	JumpToMedium = JumpToRealCode - 0x6 - (ImageBase + dwRvaUPX2 + Counter);
	posDecodeSection[Counter++] = 0x0F;
	posDecodeSection[Counter++] = 0x85;
	memcpy(&posDecodeSection[Counter], &JumpToMedium, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// ADD ECX, 2
	posDecodeSection[Counter++] = 0x81;
	posDecodeSection[Counter++] = 0xC1;
	posDecodeSection[Counter++] = 0x02;
	memset(&posDecodeSection[Counter], 0x00, sizeof(BYTE) * 3);
	Counter += sizeof(BYTE) * 3;


	// MOV ESI, posName
	posDecodeSection[Counter++] = 0xBE;
	memcpy(&posDecodeSection[Counter], &posName, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// ADD ESI, ECX
	posDecodeSection[Counter++] = 0x01;
	posDecodeSection[Counter++] = 0xCE;


	// PUSH ESI
	posDecodeSection[Counter++] = 0x56;


	// MOV ESI, ECX
	posDecodeSection[Counter++] = 0x89;
	posDecodeSection[Counter++] = 0xCE;


	// CALL DWORD PTR DS:[posLoadLibraryA]
	posDecodeSection[Counter++] = 0xFF;
	posDecodeSection[Counter++] = 0x15;
	memcpy(&posDecodeSection[Counter], &g_posLoadLibraryA, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// MOV ECX, ESI
	posDecodeSection[Counter++] = 0x89;
	posDecodeSection[Counter++] = 0xF1;


	// ADD EBX, Temp
	Temp = sizeof(DWORD) * 5;
	posDecodeSection[Counter++] = 0x83;
	posDecodeSection[Counter++] = 0xC3;
	memcpy(&posDecodeSection[Counter], &Temp, sizeof(BYTE));
	Counter += sizeof(BYTE);


	// MOV EDI, ImageBase
	posDecodeSection[Counter++] = 0xBF;
	memcpy(&posDecodeSection[Counter], &ImageBase, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// ADD EDI, [EBX]
	posDecodeSection[Counter++] = 0x03;
	posDecodeSection[Counter++] = 0x3B;


	// MOV EDX, EAX
	posDecodeSection[Counter++] = 0x89;
	posDecodeSection[Counter++] = 0xC2;


	// MOV ESI, 1
	posDecodeSection[Counter++] = 0xBE;
	posDecodeSection[Counter++] = 0x01;
	memset(&posDecodeSection[Counter], 0x00, sizeof(BYTE) * 3);
	Counter += sizeof(BYTE) * 3;


	// JMP JumpTo  ( 1 )
	JumpToRealCode = ImageBase + dwRvaUPX2 + 0x7B;
	JumpToMedium = JumpToRealCode - 0x5 - (ImageBase + dwRvaUPX2 + Counter);
	posDecodeSection[Counter++] = 0xE9;
	memcpy(&posDecodeSection[Counter], &JumpToMedium, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// CMP BYTE PTR DS:[posName + ECX], 0
	posDecodeSection[Counter++] = 0x80;
	posDecodeSection[Counter++] = 0xB9;
	memcpy(&posDecodeSection[Counter], &posName, sizeof(DWORD));
	Counter += sizeof(DWORD);
	posDecodeSection[Counter++] = 0x00;


	// JNE JumpTo
	JumpToRealCode = ImageBase + dwRvaUPX2 + 0xE4;
	JumpToMedium = JumpToRealCode - 0x6 - (ImageBase + dwRvaUPX2 + Counter);
	posDecodeSection[Counter++] = 0x0F;
	posDecodeSection[Counter++] = 0x85;
	memcpy(&posDecodeSection[Counter], &JumpToMedium, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// JMP OEP
	JumpToRealCode = OriginalEntryPoint - 0x5 - (ImageBase + dwRvaUPX2 + Counter + dwShellCodeSize);
	posDecodeSection[Counter++] = 0xE9;
	memcpy(&posDecodeSection[Counter], &JumpToRealCode, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// MOV ESI, posName
	posDecodeSection[Counter++] = 0xBE;
	memcpy(&posDecodeSection[Counter], &posName, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// ADD ESI, ECX
	posDecodeSection[Counter++] = 0x01;
	posDecodeSection[Counter++] = 0xCE;

	// PUSH EDX
	posDecodeSection[Counter++] = 0x52;


	// PUSH ESI
	posDecodeSection[Counter++] = 0x56;


	// MOV ESI, ECX
	posDecodeSection[Counter++] = 0x89;
	posDecodeSection[Counter++] = 0xCE;


	// PUSH EDX
	posDecodeSection[Counter++] = 0x52;


	// CALL DWORD PTR DS:[posGetProcAddress]
	posDecodeSection[Counter++] = 0xFF;
	posDecodeSection[Counter++] = 0x15;
	memcpy(&posDecodeSection[Counter], &g_posGetProcAddress, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// MOV EDX, ECX
	posDecodeSection[Counter++] = 0x89;
	posDecodeSection[Counter++] = 0xCA;


	// POP EDX
	posDecodeSection[Counter++] = 0x5A;


	// MOV ECX, ESI
	posDecodeSection[Counter++] = 0x89;
	posDecodeSection[Counter++] = 0xF1;


	// MOV DWORD PTR DS:[EDI], EAX
	posDecodeSection[Counter++] = 0x89;
	posDecodeSection[Counter++] = 0x07;


	// ADD EDI, 4
	posDecodeSection[Counter++] = 0x83;
	posDecodeSection[Counter++] = 0xC7;
	posDecodeSection[Counter++] = 0x04;


	// MOV ESI, 1
	posDecodeSection[Counter++] = 0xBE;
	posDecodeSection[Counter++] = 0x01;
	memset(&posDecodeSection[Counter], 0x00, sizeof(BYTE) * 3);
	Counter += sizeof(BYTE) * 3;


	// JMP JumpTo ( 1 )
	JumpToRealCode = ImageBase + dwRvaUPX2 + 0x7B;
	JumpToMedium = JumpToRealCode - 0x5 - (ImageBase + dwRvaUPX2 + Counter);
	posDecodeSection[Counter++] = 0xE9;
	memcpy(&posDecodeSection[Counter], &JumpToMedium, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// INC ECX
	posDecodeSection[Counter++] = 0x41;


	// JMP JumpTo ( 1 )
	JumpToRealCode = ImageBase + dwRvaUPX2 + 0x7B;
	JumpToMedium = JumpToRealCode - 0x5 - (ImageBase + dwRvaUPX2 + Counter);
	posDecodeSection[Counter++] = 0xE9;
	memcpy(&posDecodeSection[Counter], &JumpToMedium, sizeof(DWORD));
	Counter += sizeof(DWORD);
	// ..........................................................


	printf("....................... OK !\n");
	return 0;
}