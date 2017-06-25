/******************************************************************************
项目：M2-SDK
描述：NSudo库
文件名：M2.NSudo.h
基于项目：无
许可协议：看顶层目录的 License.txt
建议的Windows SDK版本：10.0.10586及以后

Project: M2-SDK
Description: NSudo Library
Filename: M2.NSudo.h
License: See License.txt in the top level directory
Recommend Minimum Windows SDK Version: 10.0.10586
******************************************************************************/

#pragma once

#ifndef _M2_NSUDO_
#define _M2_NSUDO_

// 为编译通过而禁用的微软.Net Framework SDK存在的警告
#if _MSC_VER >= 1200
#pragma warning(push)
// 字节填充添加在数据成员后(等级 4)
#pragma warning(disable:4820)
// 不带范围的枚举的前向声明必须具有基础类型(假定为 int)(等级 4)
#pragma warning(disable:4471) 
#endif

#include <metahost.h>
#import "mscorlib.tlb" raw_interfaces_only				\
    high_property_prefixes("_get","_put","_putref")		\
    rename("ReportEvent", "InteropServices_ReportEvent")

#if _MSC_VER >= 1200
#pragma warning(pop)
#endif

#ifdef __cplusplus
extern "C" {
	using namespace M2;
#endif

	/*
	SuDuplicateToken函数通过现有的访问令牌创建一个主令牌或模仿令牌。
	The SuDuplicateToken function creates a primary token or an impersonation
	token via an existing access token.

	该函数是DuplicateTokenEx API的一个等价实现。
	This function is an equivalent implementation of DuplicateTokenEx API.
	*/
	static NTSTATUS WINAPI SuDuplicateToken(
		_In_ HANDLE hExistingToken,
		_In_ DWORD dwDesiredAccess,
		_In_opt_ LPSECURITY_ATTRIBUTES lpTokenAttributes,
		_In_ SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
		_In_ TOKEN_TYPE TokenType,
		_Outptr_ PHANDLE phNewToken)
	{
		SECURITY_QUALITY_OF_SERVICE SQOS;
		OBJECT_ATTRIBUTES ObjectAttributes;
		
		M2InitSecurityQuailtyOfService(
			SQOS, ImpersonationLevel, FALSE, FALSE);
		M2InitObjectAttributes(
			ObjectAttributes, nullptr, 0, nullptr, nullptr, &SQOS);
		
		if (lpTokenAttributes &&
			lpTokenAttributes->nLength == sizeof(SECURITY_ATTRIBUTES))
		{
			ObjectAttributes.Attributes =
				(ULONG)(lpTokenAttributes->bInheritHandle ? OBJ_INHERIT : 0);
			ObjectAttributes.SecurityDescriptor =
				lpTokenAttributes->lpSecurityDescriptor;
		}

		return NtDuplicateToken(
			hExistingToken,
			dwDesiredAccess,
			&ObjectAttributes,
			FALSE,
			TokenType,
			phNewToken);
	}

	/*
	SuOpenProcess函数打开一个存在的本机进程对象。
	The SuOpenProcess function opens an existing local process object.

	该函数是OpenProcess API的一个等价实现。
	This function is an equivalent implementation of OpenProcess API.
	*/
	static NTSTATUS WINAPI SuOpenProcess(
		_Out_ PHANDLE phProcess,
		_In_ DWORD dwDesiredAccess,
		_In_ BOOL bInheritHandle,
		_In_ DWORD dwProcessId)
	{
		OBJECT_ATTRIBUTES ObjectAttributes; 
		CLIENT_ID ClientID;
		
		M2InitClientID(ClientID, dwProcessId, 0);
		M2InitObjectAttributes(ObjectAttributes);

		ObjectAttributes.Attributes =
			(ULONG)(bInheritHandle ? OBJ_INHERIT : 0);

		return NtOpenProcess(
			phProcess, dwDesiredAccess, &ObjectAttributes, &ClientID);
	}

	/*
	SuOpenProcessToken函数根据进程ID打开一个进程的关联令牌。
	The SuOpenProcessToken function opens the access token associated with a
	process via ProcessID.
	*/
	static NTSTATUS WINAPI SuOpenProcessToken(
		_In_ DWORD dwProcessId,
		_In_ DWORD DesiredAccess,
		_Outptr_ PHANDLE TokenHandle)
	{
		NTSTATUS status = STATUS_SUCCESS;
		HANDLE hProcess = nullptr;

		status = SuOpenProcess(
			&hProcess, MAXIMUM_ALLOWED, FALSE, dwProcessId);
		if (NT_SUCCESS(status))
		{
			status = NtOpenProcessToken(
				hProcess, DesiredAccess, TokenHandle);
			NtClose(hProcess);
		}

		return status;
	}

	/*
	SuOpenSessionToken函数根据已登陆的用户的会话ID获取主访问令牌。您需要在
	LocalSystem账户且开启SE_TCB_NAME特权的访问令牌上下文下调用该函数。
	The SuOpenSessionToken function obtains the primary access token of the
	logged-on user specified by the session ID. To call this function
	successfully, the calling application must be running within the context
	of the LocalSystem account and have the SE_TCB_NAME privilege.

	该函数是WTSQueryUserToken API的一个等价实现。
	This function is an equivalent implementation of WTSQueryUserToken API.
	*/
	static HRESULT WINAPI SuOpenSessionToken(
		_In_ ULONG SessionId,
		_Out_ PHANDLE phToken)
	{
		WINSTATIONUSERTOKEN WSUT = { 0 };
		DWORD ReturnLength = 0;

		// 初始化 LastError
		M2SetLastError(ERROR_SUCCESS);

		// 获取线程令牌
		if (WinStationQueryInformationW(
			SERVERNAME_CURRENT,
			SessionId,
			WinStationUserToken,
			&WSUT,
			sizeof(WINSTATIONUSERTOKEN),
			&ReturnLength))
		{
			// 如果执行成功则返回令牌句柄
			*phToken = WSUT.UserToken;
		}	

		return __HRESULT_FROM_WIN32(M2GetLastError());
	}

	/*
	SuStartService函数通过服务名启动服务并返回服务状态。
	The SuStartService function starts a service and return service status via
	service name.
	*/
	static HRESULT WINAPI SuStartService(
		_In_ LPCWSTR lpServiceName,
		_Out_ LPSERVICE_STATUS_PROCESS lpServiceStatus)
	{
		SC_HANDLE hSCM = nullptr;
		SC_HANDLE hService = nullptr;
		DWORD nBytesNeeded = 0;
		DWORD nOldCheckPoint = 0;
		ULONGLONG nCurrentTick = 0;
		ULONGLONG nLastTick = 0;
		bool bStartServiceWCalled = false;
		bool bSleepCalled = false;
		bool bFinished = false;
		bool bSucceed = false;

		// 初始化 LastError
		M2SetLastError(ERROR_SUCCESS);

		hSCM = OpenSCManagerW(
			nullptr,
			nullptr,
			SC_MANAGER_CONNECT);
		if (!hSCM) goto FuncEnd;

		hService = OpenServiceW(
			hSCM,
			lpServiceName,
			SERVICE_QUERY_STATUS | SERVICE_START);
		if (!hService) goto FuncEnd;

		while (QueryServiceStatusEx(
			hService,
			SC_STATUS_PROCESS_INFO,
			(LPBYTE)lpServiceStatus,
			sizeof(SERVICE_STATUS_PROCESS),
			&nBytesNeeded))
		{
			switch (lpServiceStatus->dwCurrentState)
			{
			case SERVICE_STOPPED:
				if (!bStartServiceWCalled)
				{
					bStartServiceWCalled = true;
					bFinished = (!StartServiceW(hService, 0, nullptr));
				}
				else bFinished = true;
				break;
			case SERVICE_STOP_PENDING:
			case SERVICE_START_PENDING:
				nCurrentTick = NtGetTickCount64();

				if (!bSleepCalled)
				{
					nLastTick = nCurrentTick;
					nOldCheckPoint = lpServiceStatus->dwCheckPoint;

					bSleepCalled = true;

					// 等待250ms（借鉴.Net服务操作类的实现）
					LARGE_INTEGER Interval;
					Interval.QuadPart = 250LL * -10000LL;
					NtDelayExecution(FALSE, &Interval);
				}
				else
				{
					// 如果校验点增加则继续循环，否则检测是否超时
					if (lpServiceStatus->dwCheckPoint > nOldCheckPoint)
					{
						bSleepCalled = false;
					}
					else
					{
						ULONGLONG nDiff = nCurrentTick - nLastTick;
						if (nDiff > lpServiceStatus->dwWaitHint)
						{
							M2SetLastError(ERROR_TIMEOUT);
							bFinished = true;
						}
						else
						{
							// 未超时则继续循环
							bSleepCalled = false;
						}
					}
				}
				break;
			default:
				bSucceed = true;
				bFinished = true;
				break;
			}

			if (bFinished) break;
		}

		// 如果服务启动失败则清空状态信息
		if (!bSucceed)
			memset(lpServiceStatus, 0, sizeof(SERVICE_STATUS_PROCESS));

	FuncEnd:
		if (hService) CloseServiceHandle(hService);
		if (hSCM) CloseServiceHandle(hSCM);
		return __HRESULT_FROM_WIN32(M2GetLastError());
	}

	/*
	SuOpenServiceProcessToken函数根据服务名打开一个服务进程的关联令牌。
	The SuOpenServiceProcessToken function opens the access token associated
	with a service process via service name.
	*/
	static HRESULT WINAPI SuOpenServiceProcessToken(
		_In_ LPCWSTR lpServiceName,
		_In_ DWORD DesiredAccess,
		_Outptr_ PHANDLE TokenHandle)
	{
		HRESULT hr = S_OK;
		NTSTATUS status = STATUS_SUCCESS;
		SERVICE_STATUS_PROCESS ssStatus;

		hr = SuStartService(lpServiceName, &ssStatus);
		if (SUCCEEDED(hr))
		{
			status = SuOpenProcessToken(
				ssStatus.dwProcessId, DesiredAccess, TokenHandle);
			hr = __HRESULT_FROM_WIN32(RtlNtStatusToDosError(status));
		}

		return hr;
	}

	/*
	SuOpenCurrentProcessToken函数打开当前进程的关联令牌。
	The SuOpenCurrentProcessToken function opens the access token associated
	with current process.
	*/
	static NTSTATUS WINAPI SuOpenCurrentProcessToken(
		_Out_ PHANDLE phProcessToken,
		_In_ DWORD DesiredAccess)
	{
		return NtOpenProcessToken(
			NtCurrentProcess(), DesiredAccess, phProcessToken);
	}


	/*
	SuGetCurrentProcessSessionID获取当前进程的会话ID。
	The SuGetCurrentProcessSessionID function obtains the Session ID of the 
	current process.
	*/
	static NTSTATUS SuGetCurrentProcessSessionID(PDWORD SessionID)
	{
		NTSTATUS status = STATUS_SUCCESS;
		HANDLE hToken = INVALID_HANDLE_VALUE;
		DWORD ReturnLength = 0;

		status = SuOpenCurrentProcessToken(&hToken, MAXIMUM_ALLOWED);
		if (NT_SUCCESS(status))
		{
			status = NtQueryInformationToken(
				hToken,
				TokenSessionId, 
				SessionID, 
				sizeof(DWORD), 
				&ReturnLength);
		}

		return status;
	}

	/*
	SuSetThreadToken函数给线程分配一个模拟令牌。该函数还可以使一个线程停止使用
	模拟令牌。
	The SuSetThreadToken function assigns an impersonation token to a thread.
	The function can also cause a thread to stop using an impersonation token.

	该函数是SetThreadToken API的一个等价实现。
	This function is an equivalent implementation of SetThreadToken API.
	*/
	static NTSTATUS WINAPI SuSetThreadToken(
		_In_opt_ PHANDLE phThread,
		_In_ HANDLE hToken)
	{
		return NtSetInformationThread(
			(phThread != nullptr) ? *phThread : NtCurrentThread(),
			ThreadImpersonationToken,
			&hToken,
			sizeof(HANDLE));
	}

	/*
	SuSetCurrentThreadToken函数给当前线程分配一个模拟令牌。该函数还可以使当前线
	程停止使用模拟令牌。
	The SuSetCurrentThreadToken function assigns an impersonation token to the
	current thread. The function can also cause the current thread to stop
	using an impersonation token.
	*/
	static NTSTATUS WINAPI SuSetCurrentThreadToken(
		_In_ HANDLE hToken)
	{
		return SuSetThreadToken(nullptr, hToken);
	}

	/*
	SuRevertToSelf函数终止客户端应用程序模拟。
	The SuRevertToSelf function terminates the impersonation of a client
	application.

	该函数是RevertToSelf API的一个等价实现。
	This function is an equivalent implementation of RevertToSelf API.
	*/
	static NTSTATUS WINAPI SuRevertToSelf()
	{
		return SuSetCurrentThreadToken(nullptr);
	}

	/*
	SuSetTokenPrivileges函数启用或禁用指定的访问令牌特权。启用或禁用一个访问令
	牌的特权需要TOKEN_ADJUST_PRIVILEGES访问权限。
	The SuSetTokenPrivileges function enables or disables privileges in the
	specified access token. Enabling or disabling privileges in an access
	token requires TOKEN_ADJUST_PRIVILEGES access.
	*/
	static NTSTATUS WINAPI SuSetTokenPrivileges(
		_In_ HANDLE TokenHandle,
		_In_opt_ PTOKEN_PRIVILEGES NewState)
	{
		return NtAdjustPrivilegesToken(
			TokenHandle, FALSE, NewState, 0, nullptr, nullptr);
	}

	/*
	访问令牌特权定义
	The definitions of the Token Privileges
	*/
	typedef enum _TOKEN_PRIVILEGES_LIST
	{
		SeMinWellKnownPrivilege = 2,
		SeCreateTokenPrivilege = 2,
		SeAssignPrimaryTokenPrivilege,
		SeLockMemoryPrivilege,
		SeIncreaseQuotaPrivilege,
		SeMachineAccountPrivilege,
		SeTcbPrivilege,
		SeSecurityPrivilege,
		SeTakeOwnershipPrivilege,
		SeLoadDriverPrivilege,
		SeSystemProfilePrivilege,
		SeSystemtimePrivilege,
		SeProfileSingleProcessPrivilege,
		SeIncreaseBasePriorityPrivilege,
		SeCreatePagefilePrivilege,
		SeCreatePermanentPrivilege,
		SeBackupPrivilege,
		SeRestorePrivilege,
		SeShutdownPrivilege,
		SeDebugPrivilege,
		SeAuditPrivilege,
		SeSystemEnvironmentPrivilege,
		SeChangeNotifyPrivilege,
		SeRemoteShutdownPrivilege,
		SeUndockPrivilege,
		SeSyncAgentPrivilege,
		SeEnableDelegationPrivilege,
		SeManageVolumePrivilege,
		SeImpersonatePrivilege,
		SeCreateGlobalPrivilege,
		SeTrustedCredManAccessPrivilege,
		SeRelabelPrivilege,
		SeIncreaseWorkingSetPrivilege,
		SeTimeZonePrivilege,
		SeCreateSymbolicLinkPrivilege,
		SeMaxWellKnownPrivilege = SeCreateSymbolicLinkPrivilege
	} TOKEN_PRIVILEGES_LIST, *PTOKEN_PRIVILEGES_LIST;

	/*
	访问令牌完整性级别定义
	The definitions of the Token Integrity Levels
	*/
	typedef enum _TOKEN_INTEGRITY_LEVELS_LIST
	{
		// S-1-16-0
		UntrustedLevel = SECURITY_MANDATORY_UNTRUSTED_RID,

		// S-1-16-4096
		LowLevel = SECURITY_MANDATORY_LOW_RID,

		// S-1-16-8192
		MediumLevel = SECURITY_MANDATORY_MEDIUM_RID,

		// S-1-16-8448
		MediumPlusLevel = SECURITY_MANDATORY_MEDIUM_PLUS_RID,

		// S-1-16-12288
		HighLevel = SECURITY_MANDATORY_HIGH_RID,

		// S-1-16-16384
		SystemLevel = SECURITY_MANDATORY_SYSTEM_RID, 

		// S-1-16-20480
		ProtectedLevel = SECURITY_MANDATORY_PROTECTED_PROCESS_RID
	} TOKEN_INTEGRITY_LEVELS_LIST, *PTOKEN_INTEGRITY_LEVELS_LIST;

	/*
	SuSetTokenPrivilege函数启用或禁用指定的访问令牌的指定特权。启用或禁用一个访
	问令牌的特权需要TOKEN_ADJUST_PRIVILEGES访问权限。
	The SuSetTokenPrivilege function enables or disables the specified
	privilege in the specified access token. Enabling or disabling privileges
	in an access token requires TOKEN_ADJUST_PRIVILEGES access.
	*/
	static NTSTATUS WINAPI SuSetTokenPrivilege(
		_In_ HANDLE hExistingToken,
		_In_ TOKEN_PRIVILEGES_LIST Privilege,
		_In_ bool bEnable)
	{
		TOKEN_PRIVILEGES TP;
		TP.PrivilegeCount = 1;
		TP.Privileges[0].Luid.LowPart = Privilege;
		TP.Privileges[0].Attributes = (DWORD)(bEnable ? SE_PRIVILEGE_ENABLED : 0);

		return SuSetTokenPrivileges(hExistingToken, &TP);
	}

	/*
	SuSetTokenAllPrivileges函数启用或禁用指定的访问令牌的所有特权。启用或禁用一
	个访问令牌的特权需要TOKEN_ADJUST_PRIVILEGES访问权限。
	The SuSetTokenAllPrivileges function enables or disables all privileges in
	the specified access token. Enabling or disabling privileges in an access
	token requires TOKEN_ADJUST_PRIVILEGES access.
	*/
	static NTSTATUS WINAPI SuSetTokenAllPrivileges(
		_In_ HANDLE hExistingToken,
		_In_ bool bEnable)
	{
		NTSTATUS status = STATUS_SUCCESS;
		PTOKEN_PRIVILEGES pTPs = nullptr;
		DWORD Length = 0;

		// 获取特权信息大小
		NtQueryInformationToken(
			hExistingToken, TokenPrivileges, nullptr, 0, &Length);

		// 分配内存
		status = M2HeapAlloc(Length, pTPs);
		if (NT_SUCCESS(status))
		{
			// 获取特权信息
			status = NtQueryInformationToken(
				hExistingToken,
				TokenPrivileges,
				pTPs,
				Length,
				&Length);
			if (NT_SUCCESS(status))
			{
				// 设置特权信息
				for (DWORD i = 0; i < pTPs->PrivilegeCount; i++)
					pTPs->Privileges[i].Attributes =
					(DWORD)(bEnable ? SE_PRIVILEGE_ENABLED : 0);

				// 开启全部特权
				status = SuSetTokenPrivileges(hExistingToken, pTPs);
			}

			// 释放内存
			M2HeapFree(pTPs);
		}

		return status;
	}

	// sizeof(SID_IDENTIFIER_AUTHORITY)
	const SIZE_T SIA_Length = sizeof(SID_IDENTIFIER_AUTHORITY);

	// SECURITY_NT_AUTHORITY
	static SID_IDENTIFIER_AUTHORITY SIA_NT = SECURITY_NT_AUTHORITY;

	// SECURITY_WORLD_SID_AUTHORITY
	static SID_IDENTIFIER_AUTHORITY SIA_World = SECURITY_WORLD_SID_AUTHORITY;

	// SECURITY_APP_PACKAGE_AUTHORITY
	static SID_IDENTIFIER_AUTHORITY SIA_App = SECURITY_APP_PACKAGE_AUTHORITY;

	// SECURITY_MANDATORY_LABEL_AUTHORITY
	static SID_IDENTIFIER_AUTHORITY SIA_IL = SECURITY_MANDATORY_LABEL_AUTHORITY;

	/*
	SuSetTokenIntegrityLevel函数为指定的访问令牌设置完整性标签。
	The SuSetTokenIntegrityLevel function sets the integrity level for the
	specified access token.
	*/
	static NTSTATUS WINAPI SuSetTokenIntegrityLevel(
		_In_ HANDLE TokenHandle,
		_In_ TOKEN_INTEGRITY_LEVELS_LIST IL)
	{
		NTSTATUS status = STATUS_SUCCESS;
		TOKEN_MANDATORY_LABEL TML;

		// 初始化SID
		status = RtlAllocateAndInitializeSid(
			&SIA_IL, 1, IL, 0, 0, 0, 0, 0, 0, 0, &TML.Label.Sid);
		if (NT_SUCCESS(status))
		{
			// 初始化TOKEN_MANDATORY_LABEL
			TML.Label.Attributes = SE_GROUP_INTEGRITY;

			// 设置令牌对象
			status = NtSetInformationToken(
				TokenHandle, TokenIntegrityLevel, &TML, sizeof(TML));

			// 释放SID
			RtlFreeSid(TML.Label.Sid);
		}

		return status;
	}

	/*
	SuIsLogonSid函数判断指定的SID是否为登录SID。
	The SuIsLogonSid function determines whether the specified SID is a logon
	SID.
	*/
	static bool WINAPI SuIsLogonSid(
		_In_ PSID pSid)
	{
		// 获取pSid的SID_IDENTIFIER_AUTHORITY结构
		PSID_IDENTIFIER_AUTHORITY pSidAuth = RtlIdentifierAuthoritySid(pSid);

		// 如果不符合SID_IDENTIFIER_AUTHORITY结构长度，则返回false
		if (memcmp(pSidAuth, &SIA_NT, SIA_Length)) return false;

		// 判断SID是否属于Logon SID
		return (*RtlSubAuthorityCountSid(pSid) == SECURITY_LOGON_IDS_RID_COUNT
			&& *RtlSubAuthoritySid(pSid, 0) == SECURITY_LOGON_IDS_RID);
	}

	/*
	SuSetKernelObjectIntegrityLevel函数为指定的内核对象设置完整性标签。
	The SuSetKernelObjectIntegrityLevel function sets the integrity level for
	the specified kernel object.
	*/
	static NTSTATUS WINAPI SuSetKernelObjectIntegrityLevel(
		_In_ HANDLE Object,
		_In_ TOKEN_INTEGRITY_LEVELS_LIST IL)
	{
		const size_t AclLength = 88;
		NTSTATUS status = STATUS_SUCCESS;
		PSID pSID = nullptr;
		PACL pAcl = nullptr;
		SECURITY_DESCRIPTOR SD;
		HANDLE hNewHandle = nullptr;

		// 复制句柄
		status = NtDuplicateObject(
			NtCurrentProcess(),
			Object,
			NtCurrentProcess(),
			&hNewHandle,
			DIRECTORY_ALL_ACCESS,
			0,
			0);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		//初始化SID
		status = RtlAllocateAndInitializeSid(
			&SIA_IL, 1, IL, 0, 0, 0, 0, 0, 0, 0, &pSID);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		//分配ACL结构内存
		status = M2HeapAlloc(AclLength, pAcl);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 创建SD
		status = RtlCreateSecurityDescriptor(
			&SD, SECURITY_DESCRIPTOR_REVISION);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 创建ACL
		status = RtlCreateAcl(pAcl, AclLength, ACL_REVISION);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 添加完整性ACE
		status = RtlAddMandatoryAce(
			pAcl, ACL_REVISION, 0, pSID,
			SYSTEM_MANDATORY_LABEL_ACE_TYPE, OBJECT_TYPE_CREATE);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 设置SACL
		status = RtlSetSaclSecurityDescriptor(&SD, TRUE, pAcl, FALSE);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 设置内核对象
		status = NtSetSecurityObject(
			hNewHandle, LABEL_SECURITY_INFORMATION, &SD);

	FuncEnd:
		M2HeapFree(pAcl);
		RtlFreeSid(pSID);
		NtClose(hNewHandle);

		return status;
	}

	/*
	SuCreateLUAToken函数从一个现有的访问令牌创建一个新的LUA访问令牌。
	The SuCreateLUAToken function creates a new LUA access token from an
	existing access token.
	*/
	static NTSTATUS WINAPI SuCreateLUAToken(
		_Out_ PHANDLE TokenHandle,
		_In_ HANDLE ExistingTokenHandle)
	{
		NTSTATUS status = STATUS_SUCCESS;
		DWORD Length = 0;
		BOOL EnableTokenVirtualization = TRUE;
		TOKEN_OWNER Owner = { 0 };
		TOKEN_DEFAULT_DACL NewTokenDacl = { 0 };
		PTOKEN_USER pTokenUser = nullptr;
		PTOKEN_DEFAULT_DACL pTokenDacl = nullptr;
		PSID pAdminSid = nullptr;
		PACCESS_ALLOWED_ACE pTempAce = nullptr;

		//创建受限令牌
		status = NtFilterToken(
			ExistingTokenHandle, LUA_TOKEN,
			nullptr, nullptr, nullptr, TokenHandle);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 设置令牌完整性
		status = SuSetTokenIntegrityLevel(
			*TokenHandle, TOKEN_INTEGRITY_LEVELS_LIST::MediumLevel);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 获取令牌对应的用户账户SID信息大小
		status = NtQueryInformationToken(
			*TokenHandle, TokenUser, nullptr, 0, &Length);
		if (status != STATUS_BUFFER_TOO_SMALL) goto FuncEnd;

		// 为令牌对应的用户账户SID信息分配内存
		status = M2HeapAlloc(Length, pTokenUser);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 获取令牌对应的用户账户SID信息
		status = NtQueryInformationToken(
			*TokenHandle, TokenUser, pTokenUser, Length, &Length);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 设置令牌Owner为当前用户
		Owner.Owner = pTokenUser->User.Sid;
		status = NtSetInformationToken(
			*TokenHandle, TokenOwner, &Owner, sizeof(TOKEN_OWNER));
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 获取令牌的DACL信息大小
		status = NtQueryInformationToken(
			*TokenHandle, TokenDefaultDacl, nullptr, 0, &Length);
		if (status != STATUS_BUFFER_TOO_SMALL) goto FuncEnd;

		// 为令牌的DACL信息分配内存
		status = M2HeapAlloc(Length, pTokenDacl);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 获取令牌的DACL信息
		status = NtQueryInformationToken(
			*TokenHandle, TokenDefaultDacl, pTokenDacl, Length, &Length);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 获取管理员组SID
		status = RtlAllocateAndInitializeSid(
			&SIA_NT, 2,
			SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
			0, 0, 0, 0, 0, 0, &pAdminSid);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 计算新ACL大小
		Length = pTokenDacl->DefaultDacl->AclSize;
		Length += RtlLengthSid(pTokenUser->User.Sid);
		Length += sizeof(ACCESS_ALLOWED_ACE);

		// 分配ACL结构内存
		status = M2HeapAlloc(Length, NewTokenDacl.DefaultDacl);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 创建ACL
		status = RtlCreateAcl(
			NewTokenDacl.DefaultDacl,
			Length, pTokenDacl->DefaultDacl->AclRevision);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 添加ACE
		status = RtlAddAccessAllowedAce(
			NewTokenDacl.DefaultDacl,
			pTokenDacl->DefaultDacl->AclRevision,
			GENERIC_ALL,
			pTokenUser->User.Sid);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 复制ACE
		for (ULONG i = 0;
			NT_SUCCESS(RtlGetAce(pTokenDacl->DefaultDacl, i, (PVOID*)&pTempAce));
			++i)
		{
			if (RtlEqualSid(pAdminSid, &pTempAce->SidStart)) continue;

			RtlAddAce(
				NewTokenDacl.DefaultDacl,
				pTokenDacl->DefaultDacl->AclRevision, 0,
				pTempAce, pTempAce->Header.AceSize);
		}

		// 设置令牌DACL
		Length += sizeof(TOKEN_DEFAULT_DACL);
		status = NtSetInformationToken(
			*TokenHandle, TokenDefaultDacl, &NewTokenDacl, Length);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 开启LUA虚拟化
		status = NtSetInformationToken(
			*TokenHandle,
			TokenVirtualizationEnabled,
			&EnableTokenVirtualization,
			sizeof(BOOL));
		if (!NT_SUCCESS(status)) goto FuncEnd;

	FuncEnd: // 扫尾

		if (NewTokenDacl.DefaultDacl) M2HeapFree(NewTokenDacl.DefaultDacl);
		if (pAdminSid) RtlFreeSid(pAdminSid);
		if (pTokenDacl) M2HeapFree(pTokenDacl);
		if (pTokenUser) M2HeapFree(pTokenUser);
		if (!NT_SUCCESS(status))
		{
			NtClose(*TokenHandle);
			*TokenHandle = INVALID_HANDLE_VALUE;
		}

		return status;
	}

	/*
	内部使用的AppContainer对象列表
	The list of the AppContainer Objects for Internal use.
	*/
	const enum SuAppContainerHandleList
	{
		RootDirectory, // 主目录对象
		RpcDirectory,  // RPC目录对象
		GlobalSymbolicLink, // Global符号链接
		LocalSymbolicLink, // Local符号链接
		SessionSymbolicLink, // Session符号链接
		NamedPipe //命名管道
	};

	/*
	SuBuildAppContainerSecurityDescriptor函数从为创建一个新的AppContainer访问令
	牌构建一个新的安全标识符结构。
	The SuBuildAppContainerSecurityDescriptor function builds a new Security
	Descriptor struct for creating a new AppContainer access token.
	*/
	NTSTATUS WINAPI SuBuildAppContainerSecurityDescriptor(
		_In_ PSECURITY_DESCRIPTOR ExistingSecurityDescriptor,
		_In_ PSID SandBoxSid,
		_In_ PSID UserSid,
		_In_ bool IsRpcControl,
		_Out_ PSECURITY_DESCRIPTOR *NewSecurityDescriptor)
	{
		NTSTATUS status = STATUS_SUCCESS;
		DWORD ReturnLength = 0;
		BOOLEAN DaclPresent = FALSE;
		BOOLEAN DaclDefaulted = FALSE;
		PACL pAcl = nullptr;
		PACL pNewAcl = nullptr;
		PSID AdminSid = nullptr;
		PSID RestrictedSid = nullptr;
		PSID WorldSid = nullptr;
		bool bUserSidExist = false;
		PACCESS_ALLOWED_ACE pTempAce = nullptr;

		//生成受限组SID结构
		status = RtlAllocateAndInitializeSid(
			&SIA_NT, 1, SECURITY_RESTRICTED_CODE_RID,
			0, 0, 0, 0, 0, 0, 0, &RestrictedSid);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		//生成管理员组SID结构
		status = RtlAllocateAndInitializeSid(
			&SIA_NT, 2, SECURITY_BUILTIN_DOMAIN_RID,
			DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdminSid);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		//生成Everyone组SID结构
		status = RtlAllocateAndInitializeSid(
			&SIA_World, 1, SECURITY_WORLD_RID,
			0, 0, 0, 0, 0, 0, 0, &WorldSid);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		//获取现有对象的ACL
		status = RtlGetDaclSecurityDescriptor(
			ExistingSecurityDescriptor, &DaclPresent, &pAcl, &DaclDefaulted);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		//计算新ACL大小
		ReturnLength = pAcl->AclSize;
		ReturnLength += RtlLengthSid(SandBoxSid) * 2;
		ReturnLength += RtlLengthSid(UserSid) * 2;
		ReturnLength += RtlLengthSid(RestrictedSid);
		ReturnLength += RtlLengthSid(AdminSid);
		ReturnLength += RtlLengthSid(WorldSid);
		ReturnLength += sizeof(ACCESS_ALLOWED_ACE) * 7;

		//分配ACL结构内存
		status = M2HeapAlloc(ReturnLength, pNewAcl);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		//创建ACL
		status = RtlCreateAcl(pNewAcl, ReturnLength, pAcl->AclRevision);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		//复制ACE
		for (ULONG i = 0; NT_SUCCESS(RtlGetAce(pAcl, i, (PVOID*)&pTempAce)); i++)
		{
			//检测登陆SID并对权限做出修改
			if (SuIsLogonSid(&pTempAce->SidStart)
				&& !(pTempAce->Header.AceFlags & INHERIT_ONLY_ACE))
			{
				pTempAce->Mask = DIRECTORY_ALL_ACCESS;
			}

			//如果不是是rpc句柄则跳过管理员和Everyone的SID添加
			if (!IsRpcControl
				&& (RtlEqualSid(&pTempAce->SidStart, AdminSid)
					|| RtlEqualSid(&pTempAce->SidStart, RestrictedSid)
					|| RtlEqualSid(&pTempAce->SidStart, WorldSid))) continue;

			//如果是用户SID存在则标记
			if (RtlEqualSid(&pTempAce->SidStart, UserSid))
				bUserSidExist = true;

			//添加ACE
			RtlAddAce(pNewAcl, pAcl->AclRevision, 0,
				pTempAce, pTempAce->Header.AceSize);
		}

		//添加ACE（特殊） - 沙盒SID
		status = RtlAddAccessAllowedAce(
			pNewAcl,
			pAcl->AclRevision,
			DIRECTORY_ALL_ACCESS,
			SandBoxSid);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		//添加ACE（InheritNone） - 沙盒SID
		status = RtlAddAccessAllowedAceEx(
			pNewAcl,
			pAcl->AclRevision,
			OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE,
			GENERIC_ALL,
			SandBoxSid);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		if (!bUserSidExist)
		{
			//添加ACE（特殊） - 用户SID
			status = RtlAddAccessAllowedAce(
				pNewAcl,
				pAcl->AclRevision,
				DIRECTORY_ALL_ACCESS,
				UserSid);
			if (!NT_SUCCESS(status)) goto FuncEnd;

			//添加ACE（InheritNone） - 用户SID
			status = RtlAddAccessAllowedAceEx(
				pNewAcl,
				pAcl->AclRevision,
				OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE,
				GENERIC_ALL,
				UserSid);
			if (!NT_SUCCESS(status)) goto FuncEnd;
		}

		if (IsRpcControl)
		{
			//添加ACE（InheritNone） - 管理员SID
			status = RtlAddAccessAllowedAceEx(
				pNewAcl,
				pAcl->AclRevision,
				OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE,
				GENERIC_ALL,
				AdminSid);
			if (!NT_SUCCESS(status)) goto FuncEnd;

			//添加ACE（InheritNone） - 受限SID
			status = RtlAddAccessAllowedAceEx(
				pNewAcl,
				pAcl->AclRevision,
				OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE,
				GENERIC_READ | GENERIC_EXECUTE,
				RestrictedSid);
			if (!NT_SUCCESS(status)) goto FuncEnd;

			//添加ACE（InheritNone） - Everyone SID
			status = RtlAddAccessAllowedAceEx(
				pNewAcl,
				pAcl->AclRevision,
				OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE,
				GENERIC_READ | GENERIC_EXECUTE,
				WorldSid);
			if (!NT_SUCCESS(status)) goto FuncEnd;
		}

		//分配SD结构内存
		status = M2HeapAlloc(
			sizeof(SECURITY_DESCRIPTOR), *NewSecurityDescriptor);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		//创建SD
		status = RtlCreateSecurityDescriptor(
			*NewSecurityDescriptor, SECURITY_DESCRIPTOR_REVISION);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		//设置SD
		status = RtlSetDaclSecurityDescriptor(
			*NewSecurityDescriptor, DaclPresent, pNewAcl, DaclDefaulted);
		if (!NT_SUCCESS(status)) goto FuncEnd;

	FuncEnd:
		RtlFreeSid(WorldSid);
		RtlFreeSid(AdminSid);
		RtlFreeSid(RestrictedSid);
		return status;
	}

#define PIPE_ALL_ACCESS (SYNCHRONIZE \
            | STANDARD_RIGHTS_REQUIRED \
            | PIPE_ACCESS_INBOUND \
            | PIPE_ACCESS_OUTBOUND \
            | PIPE_ACCESS_DUPLEX)

	/*
	SuCreateAppContainerToken函数从一个现有的访问令牌创建一个新的AppContainer访
	问令牌。
	The SuCreateAppContainerToken function creates a new AppContainer access
	token from an existing access token.
	*/
	NTSTATUS WINAPI SuCreateAppContainerToken(
		_Out_ PHANDLE TokenHandle,
		_In_ HANDLE ExistingTokenHandle,
		_In_ PSECURITY_CAPABILITIES SecurityCapabilities)
	{
		NTSTATUS status = STATUS_SUCCESS;
		PVOID pNTDLL = nullptr;
		UNICODE_STRING usNTDLL = { 0 };
		ANSI_STRING asFuncName = { 0 };
		decltype(NtCreateLowBoxToken) *pNtCreateLowBoxToken = nullptr;
		decltype(NtCreateDirectoryObjectEx) *pNtCreateDirectoryObjectEx = nullptr;
		DWORD ReturnLength = 0;
		DWORD TokenSessionID = 0;
		wchar_t Buffer[MAX_PATH];
		UNICODE_STRING usBNO = RTL_CONSTANT_STRING(L"\\BaseNamedObjects");
		OBJECT_ATTRIBUTES ObjectAttributes;
		UNICODE_STRING usACNO = { 0 };
		UNICODE_STRING usRpcControl = RTL_CONSTANT_STRING(L"\\RPC Control");
		UNICODE_STRING usRpcControl2 = RTL_CONSTANT_STRING(L"RPC Control");
		UNICODE_STRING usRootDirectory = { 0 };
		UNICODE_STRING usGlobal = RTL_CONSTANT_STRING(L"Global");
		UNICODE_STRING usLocal = RTL_CONSTANT_STRING(L"Local");
		UNICODE_STRING usSession = RTL_CONSTANT_STRING(L"Session");
		UNICODE_STRING usBNO1 = RTL_CONSTANT_STRING(L"\\BaseNamedObjects");
		PACCESS_ALLOWED_ACE pTempAce = nullptr;
		UNICODE_STRING usNamedPipe = { 0 };
		IO_STATUS_BLOCK IoStatusBlock;
		UNICODE_STRING usAppContainerSID = { 0 };
		HANDLE hBaseNamedObjects = nullptr;
		PSECURITY_DESCRIPTOR pSD = nullptr;
		PTOKEN_USER pTokenUser = nullptr;
		PSECURITY_DESCRIPTOR pDirectorySD = nullptr;
		PSECURITY_DESCRIPTOR pRpcControlSD = nullptr;
		HANDLE hAppContainerNamedObjects = nullptr;
		HANDLE hRpcControl = nullptr;
		HANDLE HandleList[6] = { nullptr };

		// 获取ntdll.dll地址
		M2InitUnicodeString(usNTDLL, L"ntdll.dll");
		status = LdrGetDllHandleEx(0, nullptr, nullptr, &usNTDLL, &pNTDLL);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 获取NtCreateLowBoxToken地址
		M2InitString(asFuncName, "NtCreateLowBoxToken");
		status = LdrGetProcedureAddress(
			pNTDLL, &asFuncName, 0,
			reinterpret_cast<PVOID*>(&pNtCreateLowBoxToken));
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 获取NtCreateDirectoryObjectEx地址
		M2InitString(asFuncName, "NtCreateDirectoryObjectEx");
		status = LdrGetProcedureAddress(
			pNTDLL, &asFuncName, 0,
			reinterpret_cast<PVOID*>(&pNtCreateDirectoryObjectEx));
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 获取令牌会话ID
		status = NtQueryInformationToken(
			ExistingTokenHandle,
			TokenSessionId,
			&TokenSessionID,
			sizeof(DWORD),
			&ReturnLength);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 把SID转换为Unicode字符串
		status = RtlConvertSidToUnicodeString(
			&usAppContainerSID, SecurityCapabilities->AppContainerSid, TRUE);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 如果SessionID不为0，则生成对应会话的路径
		if (TokenSessionID)
		{
			StringCbPrintfW(
				Buffer, sizeof(Buffer),
				L"\\Sessions\\%ld\\BaseNamedObjects", TokenSessionID);

			M2InitUnicodeString(usBNO, Buffer);
		}

		// 初始化用于打开BaseNamedObjects目录对象的OBJECT_ATTRIBUTES结构
		M2InitObjectAttributes(ObjectAttributes, &usBNO);

		// 打开BaseNamedObjects目录对象
		status = NtOpenDirectoryObject(
			&hBaseNamedObjects,
			READ_CONTROL | DIRECTORY_QUERY | DIRECTORY_TRAVERSE,
			&ObjectAttributes);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 获取BaseNamedObjects目录安全标识符信息大小
		NtQuerySecurityObject(
			hBaseNamedObjects, DACL_SECURITY_INFORMATION,
			nullptr, 0, &ReturnLength);

		// 为安全标识符分配内存
		status = M2HeapAlloc(ReturnLength, pSD);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 获取BaseNamedObjects目录安全标识符信息
		status = NtQuerySecurityObject(
			hBaseNamedObjects, DACL_SECURITY_INFORMATION,
			pSD, ReturnLength, &ReturnLength);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 获取令牌用户信息大小
		status = NtQueryInformationToken(
			ExistingTokenHandle, TokenUser,
			nullptr, 0, &ReturnLength);
		if (status != STATUS_BUFFER_TOO_SMALL) goto FuncEnd;

		// 为令牌用户信息分配内存
		status = M2HeapAlloc(ReturnLength, pTokenUser);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 获取令牌用户信息
		status = NtQueryInformationToken(
			ExistingTokenHandle, TokenUser,
			pTokenUser, ReturnLength, &ReturnLength);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 创建AppContainer对象目录安全标识符
		status = SuBuildAppContainerSecurityDescriptor(
			pSD,
			SecurityCapabilities->AppContainerSid,
			pTokenUser->User.Sid,
			false,
			&pDirectorySD);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 创建AppContainer RPC对象目录安全标识符
		status = SuBuildAppContainerSecurityDescriptor(
			pSD,
			SecurityCapabilities->AppContainerSid,
			pTokenUser->User.Sid,
			true,
			&pRpcControlSD);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 初始化AppContainerNamedObjects对象目录路径字符串
		StringCbPrintfW(
			Buffer, sizeof(Buffer),
			L"\\Sessions\\%ld\\AppContainerNamedObjects", TokenSessionID);

		// 初始化AppContainerNamedObjects对象目录路径UNICODE_STRING结构
		M2InitUnicodeString(usACNO, Buffer);

		// 初始化用于打开AppContainerNamedObjects目录对象的OBJECT_ATTRIBUTES结构
		M2InitObjectAttributes(ObjectAttributes, &usACNO);

		// 打开AppContainerNamedObjects目录对象
		status = NtOpenDirectoryObject(
			&hAppContainerNamedObjects,
			DIRECTORY_QUERY | DIRECTORY_TRAVERSE |
			DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY,
			&ObjectAttributes);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 初始化用于创建AppContainer目录对象的OBJECT_ATTRIBUTES结构
		M2InitObjectAttributes(
			ObjectAttributes,
			&usAppContainerSID,
			OBJ_INHERIT | OBJ_OPENIF,
			hAppContainerNamedObjects,
			pDirectorySD);

		// 创建AppContainer目录对象
		status = pNtCreateDirectoryObjectEx(
			&HandleList[SuAppContainerHandleList::RootDirectory],
			DIRECTORY_QUERY | DIRECTORY_TRAVERSE |
			DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY,
			&ObjectAttributes,
			hBaseNamedObjects,
			1);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 设置AppContainer目录对象完整性标签为低
		status = SuSetKernelObjectIntegrityLevel(
			HandleList[SuAppContainerHandleList::RootDirectory],
			TOKEN_INTEGRITY_LEVELS_LIST::LowLevel);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 初始化用于打开RPC Control目录对象的OBJECT_ATTRIBUTES结构
		M2InitObjectAttributes(ObjectAttributes, &usRpcControl);

		// 打开RPC Control目录对象
		status = NtOpenDirectoryObject(
			&hRpcControl,
			DIRECTORY_QUERY | DIRECTORY_TRAVERSE,
			&ObjectAttributes);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 初始化用于创建AppContainer RPC Control目录对象的OBJECT_ATTRIBUTES结构
		M2InitObjectAttributes(
			ObjectAttributes,
			&usRpcControl2,
			OBJ_INHERIT | OBJ_OPENIF,
			HandleList[SuAppContainerHandleList::RootDirectory],
			pRpcControlSD);

		// 创建AppContainer RPC Control目录对象
		status = pNtCreateDirectoryObjectEx(
			&HandleList[SuAppContainerHandleList::RpcDirectory],
			DIRECTORY_QUERY | DIRECTORY_TRAVERSE |
			DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY,
			&ObjectAttributes,
			hRpcControl,
			1);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 设置AppContainer RPC Control目录对象完整性标签为低
		status = SuSetKernelObjectIntegrityLevel(
			HandleList[SuAppContainerHandleList::RpcDirectory],
			TOKEN_INTEGRITY_LEVELS_LIST::LowLevel);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 初始化AppContainer目录对象字符串
		StringCbPrintfW(
			Buffer, sizeof(Buffer),
			L"\\Sessions\\%d\\AppContainerNamedObjects\\%ws",
			TokenSessionID,
			usAppContainerSID.Buffer, usAppContainerSID.Length);

		// 初始化AppContainer目录对象的UNICODE_STRING结构
		M2InitUnicodeString(usRootDirectory, Buffer);

		// 初始化用于创建Global符号链接对象的OBJECT_ATTRIBUTES结构
		M2InitObjectAttributes(
			ObjectAttributes,
			&usGlobal,
			OBJ_INHERIT | OBJ_OPENIF,
			HandleList[SuAppContainerHandleList::RootDirectory],
			pDirectorySD);

		// 在AppContainer目录对象下创建Global符号链接对象
		status = NtCreateSymbolicLinkObject(
			&HandleList[SuAppContainerHandleList::GlobalSymbolicLink],
			SYMBOLIC_LINK_ALL_ACCESS,
			&ObjectAttributes,
			&usBNO1);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 初始化用于创建Local符号链接对象的OBJECT_ATTRIBUTES结构
		M2InitObjectAttributes(
			ObjectAttributes,
			&usLocal,
			OBJ_INHERIT | OBJ_OPENIF,
			HandleList[SuAppContainerHandleList::RootDirectory],
			pDirectorySD);

		// 在AppContainer目录对象下创建Local符号链接对象
		status = NtCreateSymbolicLinkObject(
			&HandleList[SuAppContainerHandleList::LocalSymbolicLink],
			SYMBOLIC_LINK_ALL_ACCESS,
			&ObjectAttributes,
			&usRootDirectory);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 初始化用于创建Session符号链接对象的OBJECT_ATTRIBUTES结构
		M2InitObjectAttributes(
			ObjectAttributes,
			&usSession,
			OBJ_INHERIT | OBJ_OPENIF,
			HandleList[SuAppContainerHandleList::RootDirectory],
			pDirectorySD);

		// 在AppContainer目录对象下创建Session符号链接对象
		status = NtCreateSymbolicLinkObject(
			&HandleList[SuAppContainerHandleList::SessionSymbolicLink],
			SYMBOLIC_LINK_ALL_ACCESS,
			&ObjectAttributes,
			&usRootDirectory);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 初始化AppContainer命名管道路径字符串
		StringCbPrintfW(
			Buffer, sizeof(Buffer),
			L"\\Device\\NamedPipe\\Sessions\\%d\\AppContainerNamedObjects\\%ws",
			TokenSessionID,
			usAppContainerSID.Buffer, usAppContainerSID.Length);

		for (ULONG i = 0;
			NT_SUCCESS(RtlGetAce(
			((SECURITY_DESCRIPTOR*)pDirectorySD)->Dacl,
				i,
				(PVOID*)&pTempAce));
			++i)
		{
			DWORD LowMask = LOWORD(pTempAce->Mask);

			// 清零pTempAce->Mask低16位
			pTempAce->Mask &= ~0xFFFF;

			if (FILE_CREATE_PIPE_INSTANCE == (LowMask & FILE_CREATE_PIPE_INSTANCE))
				pTempAce->Mask |= SYNCHRONIZE | FILE_WRITE_DATA;

			if (FILE_READ_EA == (LowMask & FILE_READ_EA))
				pTempAce->Mask |= SYNCHRONIZE | FILE_CREATE_PIPE_INSTANCE;
		}

		// 初始化AppContainer命名管道UNICODE_STRING结构
		M2InitUnicodeString(usNamedPipe, Buffer);

		// 初始化创建AppContainer命名管道的OBJECT_ATTRIBUTES结构
		M2InitObjectAttributes(
			ObjectAttributes,
			&usNamedPipe,
			OBJ_INHERIT | OBJ_CASE_INSENSITIVE,
			nullptr,
			pDirectorySD,
			nullptr);

		// 创建AppContainer命名管道
		status = NtCreateFile(
			&HandleList[SuAppContainerHandleList::NamedPipe],
			PIPE_ALL_ACCESS,
			&ObjectAttributes,
			&IoStatusBlock,
			nullptr,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			FILE_OPEN_IF,
			FILE_DIRECTORY_FILE,
			nullptr,
			0);
		if (!NT_SUCCESS(status)) goto FuncEnd;

		// 初始化用于创建AppContainer令牌对象的OBJECT_ATTRIBUTES结构
		M2InitObjectAttributes(ObjectAttributes);

		// 创建AppContainer令牌
		status = pNtCreateLowBoxToken(
			TokenHandle,
			ExistingTokenHandle,
			MAXIMUM_ALLOWED,
			&ObjectAttributes,
			SecurityCapabilities->AppContainerSid,
			SecurityCapabilities->CapabilityCount,
			SecurityCapabilities->Capabilities,
			6,
			HandleList);

	FuncEnd: // 结束处理

		for (size_t i = 0; i < 6; ++i) NtClose(HandleList[i]);
		NtClose(hRpcControl);
		NtClose(hAppContainerNamedObjects);
		M2HeapFree(pRpcControlSD);
		M2HeapFree(pDirectorySD);
		M2HeapFree(pTokenUser);
		M2HeapFree(pSD);
		NtClose(hBaseNamedObjects);
		RtlFreeUnicodeString(&usAppContainerSID);

		return status;
	}

	/*
	SuGenerateRandomAppContainerSid函数生成一个随机AppContainer SID
	The SuGenerateRandomAppContainerSid function generates a random AppContainer
	SID.
	*/
	void WINAPI SuGenerateRandomAppContainerSid(
		_Out_ PSID *RandomAppContainerSid)
	{
		LARGE_INTEGER PerfCounter, PerfFrequency;

		// 获取性能计数器数值
		NtQueryPerformanceCounter(&PerfCounter, &PerfFrequency);

		//生成种子
		ULONG seed = (ULONG)(PerfCounter.QuadPart - PerfFrequency.QuadPart);

		RtlAllocateAndInitializeSid(
			&SIA_App,
			SECURITY_APP_PACKAGE_RID_COUNT,
			SECURITY_APP_PACKAGE_BASE_RID,
			(DWORD)RtlRandomEx(&seed),
			(DWORD)RtlRandomEx(&seed),
			(DWORD)RtlRandomEx(&seed),
			(DWORD)RtlRandomEx(&seed),
			(DWORD)RtlRandomEx(&seed),
			(DWORD)RtlRandomEx(&seed),
			(DWORD)RtlRandomEx(&seed),
			RandomAppContainerSid);
	}

	/*
	SuGenerateAppContainerCapabilities函数生成一个AppContainer能力列表.你应该调
	用M2HeapFree释放你生成的能力列表。
	The SuGenerateAppContainerCapabilities function generates an AppContainer
	capabilities list. You should call M2HeapFree to free the memory the list
	which you generated.
	*/
	NTSTATUS WINAPI SuGenerateAppContainerCapabilities(
		_Out_ PSID_AND_ATTRIBUTES *Capabilities,
		_In_ DWORD *CapabilitiyRIDs,
		_In_ DWORD CapabilityCount)
	{
		NTSTATUS status = STATUS_SUCCESS;

		//设置参数及分配内存
		status = M2HeapAlloc(
			CapabilityCount * sizeof(SID_AND_ATTRIBUTES), *Capabilities);
		if (!NT_SUCCESS(status)) goto Error;

		//获取能力SID
		for (DWORD i = 0; i < CapabilityCount; i++)
		{
			(*Capabilities)[i].Attributes = SE_GROUP_ENABLED;
			status = RtlAllocateAndInitializeSid(
				&SIA_App,
				SECURITY_BUILTIN_CAPABILITY_RID_COUNT,
				SECURITY_CAPABILITY_BASE_RID, CapabilitiyRIDs[i],
				0, 0, 0, 0, 0, 0,
				&(*Capabilities)[i].Sid);
			if (!NT_SUCCESS(status)) goto Error;
		}

		return status;

	Error: // 错误处理

		if (*Capabilities)
		{
			for (DWORD i = 0; i < CapabilityCount; i++)
				if ((*Capabilities)[i].Sid) RtlFreeSid((*Capabilities)[i].Sid);

			M2HeapFree(*Capabilities);
			*Capabilities = nullptr;
		}

		return status;
	}

	/*
	SuCLRExecuteAssembly函数执行指定的.Net程序集。入口方法格式为:
	The SuCLRExecuteAssembly function executes the specified .Net Assembly.
	The format of the entry method:

	static int pwzMethodName(String pwzArgument);
	*/
	static HRESULT WINAPI SuCLRExecuteAssembly(
		_In_ LPCWSTR pwzVersion,
		_In_ LPCWSTR pwzAssemblyPath,
		_In_ LPCWSTR pwzTypeName,
		_In_ LPCWSTR pwzMethodName,
		_In_ LPCWSTR pwzArgument)
	{
		HRESULT hr = E_NOTIMPL;

		ICLRMetaHost *pMetaHost = nullptr;
		ICLRRuntimeInfo *pRuntimeInfo = nullptr;

		// ICorRuntimeHost和ICLRRuntimeHost是CLR 4.0支持的两个CLR宿主接口
		// 以下是使用.Net v2.0提供的ICLRRuntimeHost接口以支持CLR 2.0新功能的示例
		// ICLRRuntimeHost不支持加载.NET v1.x运行时.
		ICLRRuntimeHost *pClrRuntimeHost = nullptr;

		// The static method in the .NET class to invoke.
		DWORD pReturnValue = 0;

		// 
		// 加载并启动.NET运行时.
		// 

		wprintf(L"Load and start the .NET runtime %s \n", pwzVersion);

		PVOID pDllModule = nullptr;

		NTSTATUS status = STATUS_SUCCESS;
		CLRCreateInstanceFnPtr pCLRCreateInstance = nullptr;

		status = M2LoadModule(pDllModule, L"mscoree.dll");
		if (!NT_SUCCESS(status))
		{
			hr = __HRESULT_FROM_WIN32(RtlNtStatusToDosError(status));
			goto Cleanup;
		}

		status = M2GetProcedureAddress(
			pCLRCreateInstance, pDllModule, "CLRCreateInstance");
		if (!NT_SUCCESS(status))
		{
			hr = __HRESULT_FROM_WIN32(RtlNtStatusToDosError(status));
			goto Cleanup;
		}

		hr = pCLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&pMetaHost));
		if (FAILED(hr))
		{
			wprintf(L"CLRCreateInstance failed w/hr 0x%08lx\n", hr);
			goto Cleanup;
		}

		// 获取对应CLR版本的ICLRRuntimeInfo接口
		hr = pMetaHost->GetRuntime(pwzVersion, IID_PPV_ARGS(&pRuntimeInfo));
		if (FAILED(hr))
		{
			wprintf(L"ICLRMetaHost::GetRuntime failed w/hr 0x%08lx\n", hr);
			goto Cleanup;
		}

		// 检测特定版本的运行时是否可以加载入当前进程
		BOOL fLoadable = FALSE;
		hr = pRuntimeInfo->IsLoadable(&fLoadable);
		if (FAILED(hr))
		{
			wprintf(L"ICLRRuntimeInfo::IsLoadable failed w/hr 0x%08lx\n", hr);
			goto Cleanup;
		}

		if (!fLoadable)
		{
			wprintf(L".NET runtime %s cannot be loaded\n", pwzVersion);
			goto Cleanup;
		}

		// 加载特定版本CLR到当前进程，并获取ICLRRuntimeHost接口
		hr = pRuntimeInfo->GetInterface(CLSID_CLRRuntimeHost,
			IID_PPV_ARGS(&pClrRuntimeHost));
		if (FAILED(hr))
		{
			wprintf(L"ICLRRuntimeInfo::GetInterface failed w/hr 0x%08lx\n", hr);
			goto Cleanup;
		}

		// 启动CLR.
		hr = pClrRuntimeHost->Start();
		if (FAILED(hr))
		{
			wprintf(L"CLR failed to start w/hr 0x%08lx\n", hr);
			goto Cleanup;
		}

		wprintf(L"Load the assembly %s\n", pwzAssemblyPath);

		// 调用pwzAssemblyPath程序集pwzTypeName类的方法并在pReturnValue返回运行结果
		// 方法格式为 static int pwzMethodName(String pwzArgument)
		hr = pClrRuntimeHost->ExecuteInDefaultAppDomain(
			pwzAssemblyPath,
			pwzTypeName,
			pwzMethodName,
			pwzArgument,
			&pReturnValue);
		if (FAILED(hr))
		{
			wprintf(L"Failed to call %s w/hr 0x%08lx\n", pwzMethodName, hr);
			goto Cleanup;
		}

		// Print the call result of the static method.
		wprintf(L"Call %s.%s(\"%s\") => %d\n", pwzTypeName, pwzMethodName,
			pwzArgument, (int)pReturnValue);

	Cleanup:

		if (pMetaHost)
		{
			pMetaHost->Release();
			pMetaHost = nullptr;
		}
		if (pRuntimeInfo)
		{
			pRuntimeInfo->Release();
			pRuntimeInfo = nullptr;
		}
		if (pClrRuntimeHost)
		{
			pClrRuntimeHost->Release();
			pClrRuntimeHost = nullptr;
		}

		if (pDllModule)
		{
			M2FreeModule(pDllModule);
			pDllModule = nullptr;
		}

		return hr;
	}

	/*
	SuCreateProcess函数创建一个新进程和对应的主线程
	The SuCreateProcess function creates a new process and its primary thread.
	*/
	static HRESULT WINAPI SuCreateProcess(
		_In_opt_ HANDLE hToken,
		_In_opt_ LPCWSTR lpApplicationName,
		_Inout_opt_ LPWSTR lpCommandLine,
		_In_ DWORD dwCreationFlags,
		_In_opt_ LPVOID lpEnvironment,
		_In_opt_ LPCWSTR lpCurrentDirectory,
		_In_ LPSTARTUPINFOW lpStartupInfo,
		_Out_ LPPROCESS_INFORMATION lpProcessInformation)
	{
		HRESULT hr = S_OK;
		
		if (!CreateProcessAsUserW(
			hToken,
			lpApplicationName,
			lpCommandLine,
			nullptr,
			nullptr,
			FALSE,
			dwCreationFlags,
			lpEnvironment,
			lpCurrentDirectory,
			lpStartupInfo,
			lpProcessInformation))
		{
			if (!CreateProcessWithTokenW(
				hToken,
				LOGON_WITH_PROFILE,
				lpApplicationName,
				lpCommandLine,
				dwCreationFlags,
				lpEnvironment,
				lpCurrentDirectory,
				lpStartupInfo,
				lpProcessInformation))
			{
				hr = __HRESULT_FROM_WIN32(M2GetLastError());
			}
		}
		
		return hr;
	}

	class CSuProcessSnapshot
	{
	public:
		/*
		初始化进程快照
		Initialize the Process Snapshot
		*/
		CSuProcessSnapshot(
			_Out_ PNTSTATUS Status) 
		{
			*Status = this->Refresh();
		}

		/*
		反初始化进程快照
		Uninitialize the Process Snapshot
		*/
		~CSuProcessSnapshot()
		{
			if (lpBuffer) M2HeapFree(lpBuffer);
		}

		/*
		刷新进程快照
		Refresh the Process Snapshot
		*/
		NTSTATUS Refresh()
		{
			NTSTATUS status = STATUS_SUCCESS;
			DWORD dwLength = 0;

			do
			{
				// 获取进程信息大小
				status = NtQuerySystemInformation(
					SystemProcessInformation,
					nullptr,
					0,
					&dwLength);
				if (status != STATUS_INFO_LENGTH_MISMATCH) break;

				// 为令牌信息分配内存，如果失败则返回
				status = M2HeapAlloc(
					dwLength,
					lpBuffer);
				if (!NT_SUCCESS(status)) break;

				// 获取进程信息
				status = NtQuerySystemInformation(
					SystemProcessInformation,
					lpBuffer,
					dwLength,
					&dwLength);

				// 设置遍历开始地址
				pTemp = (ULONG_PTR)(PVOID)lpBuffer;

			} while (false);

			return status;
		}

		/*
		遍历进程快照
		Enumerate the Process Snapshot
		*/
		bool Next(
			_Out_ PSYSTEM_PROCESS_INFORMATION *pSPI)
		{
			*pSPI = (PSYSTEM_PROCESS_INFORMATION)pTemp;

			// 如果*pSPI=0或下个结构偏移=0时则pTemp=0，否则pTemp=下个结构地址
			if (!*pSPI || !(*pSPI)->NextEntryOffset) pTemp = 0;
			else pTemp += (*pSPI)->NextEntryOffset;

			// 返回执行结果
			return (*pSPI != nullptr);
		}

	private:
		PVOID lpBuffer;
		ULONG_PTR pTemp = 0;
	};


#if _MSC_VER >= 1200
#pragma warning(push)
#pragma warning(disable:4355) // "this": 用于基成员初始值设定项列表
#endif

	/*
	进程列表遍历迭代器
	Iterator for enumerate the process list

	用法 Usage
	for (auto pSPI : CM2EnumProcess(status)) { }

	status 是初始化遍历返回值（可选）
	status is the return value for initialization (Optional)
	*/
	class CM2EnumProcess
	{
	public:
		class CM2EnumProcessIterator
		{
		private:
			CM2EnumProcess* m_EnumProcess;

		public:
			FORCEINLINE CM2EnumProcessIterator(
				_In_ CM2EnumProcess* FindFile) :
				m_EnumProcess(FindFile)
			{

			}

			FORCEINLINE ~CM2EnumProcessIterator()
			{

			}

			FORCEINLINE void operator++()
			{
				// 如果pSPI和下个结构偏移都存在，则继续循环，否则清零
				if (m_EnumProcess->pSPI && m_EnumProcess->pSPI->NextEntryOffset)
				{
					ULONG_PTR NextSPI = reinterpret_cast<ULONG_PTR>(m_EnumProcess->pSPI);
					NextSPI += m_EnumProcess->pSPI->NextEntryOffset;
					m_EnumProcess->pSPI = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(NextSPI);
				}
				else
				{
					m_EnumProcess->pSPI = nullptr;
				}
			}

			// 根据迭代器循环特性，使用不等于操作符遍历目录
			FORCEINLINE bool operator!=(const CM2EnumProcessIterator& Item)
			{
				UNREFERENCED_PARAMETER(Item);
				return (m_EnumProcess->pSPI != nullptr);
			}

			FORCEINLINE PSYSTEM_PROCESS_INFORMATION operator*()
			{
				return m_EnumProcess->pSPI;
			}
		};

	private:
		CM2EnumProcessIterator Iterator;
		PVOID lpBuffer;
		PSYSTEM_PROCESS_INFORMATION pSPI;

	public:
		// 初始化文件遍历, 不内联考虑到大量使用本迭代器时实现函数复用以节约空间
		DECLSPEC_NOINLINE CM2EnumProcess(
			_Out_ NTSTATUS* InitStatus = nullptr) :
			Iterator(this),
			lpBuffer(nullptr),
			pSPI(nullptr)

		{
			NTSTATUS status = STATUS_SUCCESS;
			DWORD dwLength = 0;

			do
			{
				// 获取进程信息大小
				status = NtQuerySystemInformation(
					SystemProcessInformation,
					nullptr,
					0,
					&dwLength);
				if (status != STATUS_INFO_LENGTH_MISMATCH) break;

				// 为令牌信息分配内存，如果失败则返回
				status = M2HeapAlloc(
					dwLength,
					lpBuffer);
				if (!NT_SUCCESS(status)) break;

				// 获取进程信息
				status = NtQuerySystemInformation(
					SystemProcessInformation,
					lpBuffer,
					dwLength,
					&dwLength);
				if (!NT_SUCCESS(status)) break;

				// 设置遍历开始地址
				pSPI = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(lpBuffer);

			} while (false);

			if (InitStatus) *InitStatus = status;
		}

		FORCEINLINE ~CM2EnumProcess()
		{
			if (lpBuffer) M2HeapFree(lpBuffer);
		}

		FORCEINLINE CM2EnumProcessIterator& begin()
		{
			return Iterator;
		}

		FORCEINLINE CM2EnumProcessIterator& end()
		{
			return Iterator;
		}
	};

#if _MSC_VER >= 1200
#pragma warning(pop)
#endif
	
	/*
	SuGetSystemTokenCopy函数获取一个当前会话SYSTEM用户令牌的副本。
	The SuGetSystemTokenCopy function obtains a copy of current session SYSTEM 
	user token.
	*/
	static NTSTATUS WINAPI SuGetSystemTokenCopy(
		_In_ DWORD dwDesiredAccess,
		_In_opt_ LPSECURITY_ATTRIBUTES lpTokenAttributes,
		_In_ SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
		_In_ TOKEN_TYPE TokenType,
		_Outptr_ PHANDLE phToken)
	{
		NTSTATUS status = STATUS_SUCCESS;
		DWORD dwWinLogonPID = (DWORD)-1;
		DWORD dwSessionID = (DWORD)-1;
		HANDLE hProcessToken = nullptr;

		do
		{
			// 获取当前进程令牌会话ID
			status = SuGetCurrentProcessSessionID(&dwSessionID);
			if (!NT_SUCCESS(status)) break;

			// 遍历进程寻找winlogon进程并获取PID
			for (auto pSPI : CM2EnumProcess(&status))
			{
				if (pSPI->SessionId != dwSessionID) continue;
				if (pSPI->ImageName.Buffer == nullptr) continue;

				if (wcscmp(L"winlogon.exe", pSPI->ImageName.Buffer) == 0)
				{
					dwWinLogonPID = HandleToUlong(pSPI->UniqueProcessId);
					break;
				}
			}

			// 如果初始化进程遍历失败，则返回错误
			if (!NT_SUCCESS(status)) break;

			// 如果没找到进程，则返回错误
			if (dwWinLogonPID == -1)
			{
				status = STATUS_NOT_FOUND;
				break;
			}

			// 获取当前会话winlogon进程令牌
			status = SuOpenProcessToken(
				dwWinLogonPID, MAXIMUM_ALLOWED, &hProcessToken);
			if (!NT_SUCCESS(status)) break;

			// 复制令牌
			status = SuDuplicateToken(
				hProcessToken,
				dwDesiredAccess,
				lpTokenAttributes,
				ImpersonationLevel,
				TokenType,
				phToken);
			if (!NT_SUCCESS(status)) break;

		} while (false);

		NtClose(hProcessToken);

		return status;
	}

	/*
	SuGetServiceProcessTokenCopy函数根据服务名获取一个服务进程令牌的副本。
	The SuGetServiceProcessTokenCopy function obtains a copy of service process
	token via service name.
	*/
	static HRESULT WINAPI SuGetServiceProcessTokenCopy(
		_In_ LPCWSTR lpServiceName,
		_In_ DWORD dwDesiredAccess,
		_In_opt_ LPSECURITY_ATTRIBUTES lpTokenAttributes,
		_In_ SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
		_In_ TOKEN_TYPE TokenType,
		_Outptr_ PHANDLE phToken)
	{
		HRESULT hr = S_OK;
		NTSTATUS status = STATUS_SUCCESS;
		HANDLE hToken = nullptr;

		// 打开服务进程令牌
		hr = SuOpenServiceProcessToken(
			lpServiceName, MAXIMUM_ALLOWED, &hToken);
		if (SUCCEEDED(hr))
		{
			// 复制令牌
			status = SuDuplicateToken(
				hToken,
				dwDesiredAccess,
				lpTokenAttributes,
				ImpersonationLevel,
				TokenType,
				phToken);
			hr = __HRESULT_FROM_WIN32(RtlNtStatusToDosError(status));

			NtClose(hToken);
		}

		return hr;
	}

	/*
	SuGetSessionTokenCopy函数根据服务名获取一个服务进程令牌的副本。
	The SuGetSessionTokenCopy function obtains a copy of Session token via
	Session ID.
	*/
	static HRESULT WINAPI SuGetSessionTokenCopy(
		_In_ DWORD dwSessionID,
		_In_ DWORD dwDesiredAccess,
		_In_opt_ LPSECURITY_ATTRIBUTES lpTokenAttributes,
		_In_ SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
		_In_ TOKEN_TYPE TokenType,
		_Outptr_ PHANDLE phToken)
	{
		HRESULT hr = S_OK;
		NTSTATUS status = STATUS_SUCCESS;
		HANDLE hToken = nullptr;

		// 打开会话令牌
		hr = SuOpenSessionToken(dwSessionID, &hToken);
		if (SUCCEEDED(hr))
		{
			// 复制令牌
			status = SuDuplicateToken(
				hToken,
				dwDesiredAccess,
				lpTokenAttributes,
				ImpersonationLevel,
				TokenType,
				phToken);
			hr = __HRESULT_FROM_WIN32(RtlNtStatusToDosError(status));

			NtClose(hToken);
		}

		return hr;
	}

	/*
	SuGetProcessTokenCopy函数根据进程ID获取一个进程令牌的副本。
	The SuGetProcessTokenCopy function obtains a copy of process token via
	Process ID.
	*/
	static NTSTATUS WINAPI SuGetProcessTokenCopy(
		_In_ DWORD dwProcessID,
		_In_ DWORD dwDesiredAccess,
		_In_opt_ LPSECURITY_ATTRIBUTES lpTokenAttributes,
		_In_ SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
		_In_ TOKEN_TYPE TokenType,
		_Outptr_ PHANDLE phToken)
	{
		NTSTATUS status = STATUS_SUCCESS;
		HANDLE hToken = nullptr;

		// 打开进程令牌
		status = SuOpenProcessToken(dwProcessID, MAXIMUM_ALLOWED, &hToken);
		if (NT_SUCCESS(status))
		{
			// 复制令牌
			status = SuDuplicateToken(
				hToken,
				dwDesiredAccess,
				lpTokenAttributes,
				ImpersonationLevel,
				TokenType,
				phToken);

			NtClose(hToken);
		}

		return status;
	}

	/*
	SuImpersonateAsSystem函数给当前线程分配一个SYSTEM用户模拟令牌。该函数还可以
	使当前线程停止使用模拟令牌。
	The SuImpersonateAsSystem function assigns an SYSTEM user impersonation
	token to the current thread. The function can also cause the current thread
	to stop using an impersonation token.
	*/
	static NTSTATUS WINAPI SuImpersonateAsSystem()
	{
		NTSTATUS status = STATUS_SUCCESS;
		HANDLE hToken = nullptr;

		// 获取当前会话SYSTEM用户令牌副本
		status = SuGetSystemTokenCopy(
			MAXIMUM_ALLOWED,
			nullptr,
			SecurityImpersonation,
			TokenImpersonation,
			&hToken);
		if (NT_SUCCESS(status))
		{
			// 启用令牌全部特权
			status = SuSetTokenAllPrivileges(hToken, true);
			if (NT_SUCCESS(status))
			{
				// 模拟令牌
				status = SuSetCurrentThreadToken(hToken);
			}

			NtClose(hToken);
		}

		return status;
	}

#ifdef __cplusplus
}
#endif

#endif // !_M2_NSUDO_
