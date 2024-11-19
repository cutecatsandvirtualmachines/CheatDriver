#include <SharedCheatLibrary\internal.hpp>
#include <SharedCheatLibrary\communication.hpp>
#include <thread>

#include "loader.h"
#include "vdm.hpp"
#include "comms.h"
#include "memory.h"

bool bDetected = false;
bool bWarned = false;

DWORD64 gameCr3 = 0;
PVOID pIdentity = 0;
ULONG64 callbackAddress = 0;
ULONG64 gameEprocess = 0;
SKLibVdm vdm;

uint32_t GetProcessPid(std::wstring processName)
{
	uint32_t pid = -1;
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry))
		while (Process32Next(snapshot, &entry))
			if (!_wcsicmp(entry.szExeFile, processName.c_str()))
				pid = entry.th32ProcessID;

	CloseHandle(snapshot);
	return pid;
}

class RW {
private:
	DWORD64 _cr3;
	DWORD64 _vmcallKey;

public:
	RW(DWORD64 cr3, DWORD64 vmcallKey) : _cr3(cr3), _vmcallKey(vmcallKey) {};

	template<typename T>
	T Read(PVOID pAddress) {
		PREAD_DATA readData = nullptr;
		char buffer[sizeof(READ_DATA) * 2] = { 0 };
		if (PAGE_ALIGN(buffer) != PAGE_ALIGN(buffer + sizeof(READ_DATA))) {
			readData = (PREAD_DATA)PAGE_ALIGN(buffer + sizeof(READ_DATA));
		}
		else {
			readData = (PREAD_DATA)buffer;
		}

		T out;
		readData->length = sizeof(T);
		readData->pOutBuf = &out;
		readData->pTarget = pAddress;

		NTSTATUS ntStatus = CPU::CPUIDVmCall(VMCALL_READ_VIRT, (ULONG64)readData, _cr3, _vmcallKey);
		if (ntStatus != 0) {
			Log("[RW] Failed reading %p: 0x%x", pAddress, ntStatus);
			return T();
		}

		return out;
	}

	bool Read(PVOID pAddress, PVOID pOut, SIZE_T sz) {
		PREAD_DATA readData = nullptr;
		char buffer[sizeof(READ_DATA) * 2] = { 0 };
		if (PAGE_ALIGN(buffer) != PAGE_ALIGN(buffer + sizeof(READ_DATA))) {
			readData = (PREAD_DATA)PAGE_ALIGN(buffer + sizeof(READ_DATA));
		}
		else {
			readData = (PREAD_DATA)buffer;
		}

		readData->length = sz;
		readData->pOutBuf = pOut;
		readData->pTarget = pAddress;

		NTSTATUS ntStatus = CPU::CPUIDVmCall(VMCALL_READ_VIRT, (ULONG64)readData, _cr3, _vmcallKey);
		if (ntStatus != 0) {
			Log("[RW] Failed reading %p: 0x%x", pAddress, ntStatus);
			return false;
		}

		return true;
	}

	template<typename T>
	bool Write(PVOID pAddress, T obj) {
		PWRITE_DATA writeData = nullptr;
		char buffer[sizeof(WRITE_DATA) * 2] = { 0 };
		if (PAGE_ALIGN(buffer) != PAGE_ALIGN(buffer + sizeof(WRITE_DATA))) {
			writeData = (PWRITE_DATA)PAGE_ALIGN(buffer + sizeof(WRITE_DATA));
		}
		else {
			writeData = (PWRITE_DATA)buffer;
		}
		writeData->length = sizeof(T);
		writeData->pInBuf = &obj;
		writeData->pTarget = pAddress;

		NTSTATUS ntStatus = CPU::CPUIDVmCall(VMCALL_WRITE_VIRT, (ULONG64)writeData, _cr3, _vmcallKey);
		if (ntStatus != 0) {
			Log("[RW] Failed writing %p: 0x%x", pAddress, ntStatus);
			return false;
		}
		return true;
	}

	inline bool Write(PVOID pAddress, PVOID pIn, SIZE_T sz) {
		PWRITE_DATA writeData = nullptr;
		char buffer[sizeof(WRITE_DATA) * 2] = { 0 };
		if (PAGE_ALIGN(buffer) != PAGE_ALIGN(buffer + sizeof(WRITE_DATA))) {
			writeData = (PWRITE_DATA)PAGE_ALIGN(buffer + sizeof(WRITE_DATA));
		}
		else {
			writeData = (PWRITE_DATA)buffer;
		}
		writeData->length = sz;
		writeData->pInBuf = pIn;
		writeData->pTarget = pAddress;

		NTSTATUS ntStatus = CPU::CPUIDVmCall(VMCALL_WRITE_VIRT, (ULONG64)writeData, _cr3, _vmcallKey);
		if (ntStatus != 0) {
			Log("[RW] Failed writing %p: 0x%x", pAddress, ntStatus);
			return false;
		}
		return true;
	}
};

std::vector<HANDLE> vHooks;

void ParseCmd(InternalManager& mng, CMD& cmd) {
	switch (cmd.code) {
	case CMD_CODE::Hook:
	{
		if (!cmd.cmd.hook.src || !cmd.cmd.hook.dst)
			break;

		if (bEPTHide) {
			KERNEL_REQUEST kernelRequest;
			kernelRequest.instructionID = INST_SHADOW;
			kernelRequest.procInfo.cr3 = &gameCr3;
			kernelRequest.procInfo.pEprocess = gameEprocess;
			kernelRequest.memoryInfo.opSize = INTERNAL_HOOK_SIZE;
			kernelRequest.memoryInfo.opDstAddr = (ULONG64)cmd.cmd.hook.src;
			if (!vdm.CallbackInvoke(&kernelRequest)) {
				Log("Failed requesting module shadowing: 0x%llx", (ULONG64)cmd.cmd.hook.src);
			}
		}

		HANDLE hHook = mng.Hook(cmd.cmd.hook.src, cmd.cmd.hook.dst, cmd.cmd.hook.jTableOffset);
		if (hHook)
			vHooks.push_back(hHook);
		break;
	}
	default:
	{
		Log("Invalid cmd: 0x%llx", cmd.code);
	}
	}
}

void ParseCmdThread(InternalManager& mng) {
	while (true) {
		Sleep(1);
		if (!mng.cmd.CommandsAvailable()) {
			continue;
		}

		std::vector<CMD> cmds = mng.cmd.PopAll();
		DbgLog("Popped %d cmds", cmds.size());
		for (auto& cmd : cmds) {
			ParseCmd(mng, cmd);
		}
	}
}

constexpr DWORD64 sklibKey = 0xcc717f65b6da49d2;

#pragma optimize("", off)
int main() {
	if (!loader::LoadSKLib(sklibKey, &callbackAddress, true)) {
		Log("Failed loading SKLib driver");
	}
	else {
		Log("Loaded SKLib driver");
	}

	vdm.Init(sklibKey, callbackAddress);

	system("pause");
	KERNEL_REQUEST kernelRequest;
	kernelRequest.instructionID = INST_IDENTITY_MAP;
	if (!vdm.CallbackInvoke(&kernelRequest)) {
		Log("Failed mapping identity");
		system("pause");
		return -1;
	}
	else {
		Log("Mapped identity at: %p", kernelRequest.pIdentityMapping);
		Log("Test read identity map: 0x%llx", ((DWORD64*)kernelRequest.pIdentityMapping)[0]);
		pIdentity = (PVOID)kernelRequest.pIdentityMapping;
	}

	std::ifstream File("TestDll.dll", std::ios::binary | std::ios::ate);
	if (File.fail()) {
		File.close();
		return false;
	}
	auto FileSize = File.tellg();
	auto pSrcData = new BYTE[static_cast<UINT_PTR>(FileSize)];
	File.seekg(0, std::ios::beg);
	File.read(reinterpret_cast<char*>(pSrcData), FileSize);
	File.close();
	
	PVOID pMappedInternal = 0;

	kernelRequest.instructionID = INST_SUBSCRIBE_GAME;
	kernelRequest.procInfo.pImageName = (char*)"RustClient.exe";
	kernelRequest.procInfo.cr3 = &gameCr3;
	kernelRequest.procInfo.mapInfo.pBuffer = pSrcData;
	kernelRequest.procInfo.mapInfo.bMapped = false;
	kernelRequest.procInfo.mapInfo.bEPTHide = bEPTHide;
	kernelRequest.procInfo.mapInfo.sz = FileSize;
	if (!vdm.CallbackInvoke(&kernelRequest)) {
		Log("Failed subscribing game");

		if (GetProcessPid(L"RustClient.exe") != -1) {
			kernelRequest.instructionID = INST_MAP;
			kernelRequest.procInfo.dwPid = (HANDLE)GetProcessPid(L"RustClient.exe");
			kernelRequest.procInfo.mapInfo.pBuffer = pSrcData;
			kernelRequest.procInfo.mapInfo.sz = FileSize;
			kernelRequest.procInfo.cr3 = &gameCr3;
			if (!vdm.CallbackInvoke(&kernelRequest)) {
				Log("Failed injecting internal module");
			}
			gameCr3 = kernelRequest.procInfo.lastTrackedCr3;
			pMappedInternal = kernelRequest.procInfo.mapInfo.pOutBuffer;
			Log("Mapped internal to: %p", pMappedInternal);
		}
	}
	else {
		if (GetProcessPid(L"RustClient.exe") != -1) {
			kernelRequest.instructionID = INST_MAP;
			kernelRequest.procInfo.dwPid = (HANDLE)GetProcessPid(L"RustClient.exe");
			kernelRequest.procInfo.mapInfo.pBuffer = pSrcData;
			kernelRequest.procInfo.mapInfo.sz = FileSize;
			kernelRequest.procInfo.cr3 = &gameCr3;
			if (!vdm.CallbackInvoke(&kernelRequest)) {
				Log("Failed injecting internal module");
			}
			gameCr3 = kernelRequest.procInfo.lastTrackedCr3;
			pMappedInternal = kernelRequest.procInfo.mapInfo.pOutBuffer;
			Log("Mapped internal to: %p", pMappedInternal);
		}
		else {
			kernelRequest.instructionID = INST_LOCK_MODULE;
			kernelRequest.procInfo.pImageName = (char*)"GameAssembly.dll";
			if (!vdm.CallbackInvoke(&kernelRequest)) {
				Log("Failed requesting module shadowing");
			}
			else {
				Log("Locked module: %s", kernelRequest.procInfo.pImageName);
			}
		}
	}
	
	kernelRequest.instructionID = INST_GET_INFO;
	kernelRequest.procInfo.pImageName = (char*)"RustClient.exe";

	while (!gameCr3
		|| kernelRequest.procInfo.dllsQueueShadow
		) {
		//Sleep(1000);
	}

	PROC_INFO* pProcInfo = (PROC_INFO*)_aligned_malloc(sizeof(*pProcInfo), PAGE_SIZE);
	memset(pProcInfo, 0, sizeof(*pProcInfo));
	CPU::CPUIDVmCall(VMCALL_GET_INFO, (ULONG64)pProcInfo, (ULONG64)&gameCr3, sklibKey);
	Log("Process base: %p", pProcInfo->imageBase);

	kernelRequest.procInfo = *pProcInfo;

	pMappedInternal = pMappedInternal ? pMappedInternal : kernelRequest.procInfo.mapInfo.pOutBuffer;
	kernelRequest.procInfo.mapInfo.pOutBuffer = pMappedInternal;
	Log("CR3: 0x%llx", gameCr3);
	gameEprocess = kernelRequest.procInfo.pEprocess;

	PVOID pStartCoroutine = (PVOID)((ULONG64)kernelRequest.procInfo.lastDllBase + 0x282D520);

	if (bEPTHide) {
		kernelRequest.instructionID = INST_SHADOW;
		kernelRequest.memoryInfo.opSize = INTERNAL_HOOK_SIZE;
		kernelRequest.memoryInfo.opDstAddr = (ULONG64)pStartCoroutine;
		if (!vdm.CallbackInvoke(&kernelRequest)) {
			Log("Failed requesting module shadowing: 0x%llx", (ULONG64)pStartCoroutine);
		}
	}

	PE pe(pSrcData);

	DWORD64 startCoroutine = (DWORD64)pe.resolveExportedSymbolRVA(L"StartCoroutine_hk");
	DWORD64 shared = (DWORD64)pe.resolveExportedSymbolRVA(L"sharedData");
	if (!shared) {
		Log("Could not find shared data offset!");
		system("pause");
		return -1;
	}

	Log("DLL mapped at: %p", pMappedInternal);

	PVOID pStartCoroutineHk = (PVOID)((DWORD64)pMappedInternal + startCoroutine);
	PVOID pSharedDataDll = (PVOID)((DWORD64)pMappedInternal + shared);
	Log("StartCoroutine hook: %p", pStartCoroutineHk);
	Log("Shared data: %p", pSharedDataDll);

	Log("GameAssembly.dll base: 0x%llx", (ULONG64)kernelRequest.procInfo.lastDllBase);

	Sleep(2000);
	IdentityMapping identity(pIdentity, &gameCr3);
	InternalManager internalMng(pIdentity, &gameCr3, pSharedDataDll);

	internalMng.FillModuleData(kernelRequest.procInfo);

	HANDLE hStartCoroutine = internalMng.Hook(pStartCoroutine, pStartCoroutineHk, InternalJTableManager::offset(StartCoroutine));
	Log("StartCoroutine trampoline: %p", hStartCoroutine);
	vHooks.push_back(hStartCoroutine);

	std::thread parseThread(ParseCmdThread, std::ref(internalMng));

	auto pModData = internalMng.InternalModData();
	int i = 0;
	while (!pModData->bCRTInit) {
		if (pModData->dwSetupTime) {
			Log("Waiting for CRT to be initialized: %ds", i);
			i++;
		}
		else {
			Log("Waiting for DllMain to be called...");
		}
		Sleep(1000);
	}
	Log("CRT initialized: %ds", i);

	i = 0;
	printf("Press enter to undo hooks\n");
	std::cin >> i;

	internalMng.Eject(true);
_end:
	while (1)
		Sleep(1);
}
