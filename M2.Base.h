/******************************************************************************
项目：M2-SDK
描述：M2-SDK 基本定义
文件名：M2.Base.h
许可协议：看顶层目录的 License.txt
建议的最低 Windows SDK 版本：10.0.10586
提示：无

Project: M2-SDK
Description: Base M2-SDK Definitions
Filename: M2.Base.h
License: See License.txt in the top level directory
Recommend Minimum Windows SDK Version: 10.0.10586
Tips: N/A
******************************************************************************/

#pragma once

#ifndef _M2_BASE_
#define _M2_BASE_

// 初始化UNICODE_STRING结构
#define M2InitUnicodeString(Destination, Source) \
{ \
	Destination.Length = \
		(USHORT)(Source ? (wcslen(Source) * sizeof(WCHAR)) : 0); \
	Destination.MaximumLength = \
		(USHORT)(Source ? ((wcslen(Source) + 1) * sizeof(WCHAR)) : 0); \
	Destination.Buffer = \
		Source ? Source : nullptr; \
}

// 初始化STRING结构
#define M2InitString(Destination, Source) \
{ \
	Destination.Length = \
		(USHORT)(Source ? (strlen(Source) * sizeof(CHAR)) : 0); \
	Destination.MaximumLength = \
		(USHORT)(Source ? ((strlen(Source) + 1) * sizeof(CHAR)) : 0); \
	Destination.Buffer = \
		Source ? Source : nullptr; \
}

// 初始化常量NT字符串结构
#define M2InitNtConstantString(Destination, Source) \
{ \
	Destination.Length = (USHORT)(sizeof(Source) - sizeof(Source[0])); \
	Destination.MaximumLength = (USHORT)(sizeof(Source) : 0); \
	Destination.Buffer Source; \
}

#ifdef __cplusplus

// 初始化OBJECT_ATTRIBUTES结构
FORCEINLINE void M2InitObjectAttributes(
	_Out_ OBJECT_ATTRIBUTES& ObjectAttributes,
	_In_ PUNICODE_STRING ObjectName = nullptr,
	_In_ ULONG Attributes = 0,
	_In_ HANDLE RootDirectory = nullptr,
	_In_ PVOID SecurityDescriptor = nullptr,
	_In_ PVOID SecurityQualityOfService = nullptr)
{
	ObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
	ObjectAttributes.RootDirectory = RootDirectory;
	ObjectAttributes.ObjectName = ObjectName;
	ObjectAttributes.Attributes = Attributes;
	ObjectAttributes.SecurityDescriptor = SecurityDescriptor;
	ObjectAttributes.SecurityQualityOfService = SecurityQualityOfService;
}

// 初始化SECURITY_QUALITY_OF_SERVICE结构
FORCEINLINE void M2InitSecurityQuailtyOfService(
	_Out_ SECURITY_QUALITY_OF_SERVICE& SecurityQuailtyOfService,
	_In_ SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
	_In_ SECURITY_CONTEXT_TRACKING_MODE ContextTrackingMode,
	_In_ BOOLEAN EffectiveOnly)
{
	SecurityQuailtyOfService.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
	SecurityQuailtyOfService.ImpersonationLevel = ImpersonationLevel;
	SecurityQuailtyOfService.ContextTrackingMode = ContextTrackingMode;
	SecurityQuailtyOfService.EffectiveOnly = EffectiveOnly;
}

// 初始化CLIENT_ID结构
FORCEINLINE void M2InitClientID(
	_Out_ CLIENT_ID& ClientID,
	_In_opt_ DWORD ProcessID,
	_In_opt_ DWORD ThreadID)
{
	ClientID.UniqueProcess = UlongToHandle(ProcessID);
	ClientID.UniqueThread = UlongToHandle(ThreadID);
}

// 获取KUSER_SHARED_DATA结构
FORCEINLINE PKUSER_SHARED_DATA M2GetKUserSharedData()
{
	return ((PKUSER_SHARED_DATA const)0x7ffe0000);
}

// 获取当前系统会话号
FORCEINLINE DWORD M2GetCurrentSessionID()
{
	return M2GetKUserSharedData()->ActiveConsoleId;
}

// GetLastError()的未公开内联实现
FORCEINLINE DWORD M2GetLastError()
{	
	return NtCurrentTeb()->LastErrorValue;
}

// SetLastError()的未公开内联实现
FORCEINLINE VOID M2SetLastError(_In_ DWORD dwErrCode)
{
	if (NtCurrentTeb()->LastErrorValue != dwErrCode)
		NtCurrentTeb()->LastErrorValue = dwErrCode;
}

// 在默认堆上分配内存
FORCEINLINE PVOID M2HeapAlloc(
	_In_ SIZE_T Size)
{
	return RtlAllocateHeap(RtlProcessHeap(), 0, Size);
}

// 在默认堆上释放内存
FORCEINLINE VOID M2HeapFree(
	_In_ PVOID BaseAddress)
{
	RtlFreeHeap(RtlProcessHeap(), 0, BaseAddress);
}

// 分配初始化为零的内存
FORCEINLINE PVOID M2AllocZeroedMemory(
	_In_ size_t Size)
{
	return RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, Size);
}

// 通过直接访问PEB结构获取当前进程模块,以替代GetModuleHandleW(NULL)
FORCEINLINE HMODULE M2GetCurrentModuleHandle()
{
	return reinterpret_cast<HMODULE>(NtCurrentPeb()->ImageBaseAddress);
}

// 加载特定DLL
FORCEINLINE NTSTATUS M2LoadDll(
	_In_ PUNICODE_STRING DllName,
	_Out_ PVOID *DllHandle)
{
	return LdrLoadDll(nullptr, nullptr, DllName, DllHandle);
}

// 获取已加载的特定DLL的句柄
FORCEINLINE NTSTATUS M2GetDllHandle(
	_In_ PUNICODE_STRING DllName,
	_Out_ PVOID *DllHandle)
{
	return LdrGetDllHandleEx(0, nullptr, nullptr, DllName, DllHandle);
}

// 加载dll
inline NTSTATUS M2LoadDll(
	_In_ LPCWSTR lpDllName,
	_Out_ PVOID &pDllModule)
{
	UNICODE_STRING usDllName;
	
	M2InitUnicodeString(usDllName, const_cast<PWSTR>(lpDllName));

	return LdrLoadDll(
		nullptr, nullptr, &usDllName, &pDllModule);
}

// 卸载dll
inline NTSTATUS M2UnloadDll(
	_In_ PVOID pDllModule)
{
	return (pDllModule ? LdrUnloadDll(pDllModule) : 0);
}

// 创建事件对象, 不内联考虑到大量使用本函数时实现函数复用以节约空间
NTSTATUS WINAPI M2CreateEvent(
	_Out_ PHANDLE phEvent,
	_In_opt_ LPSECURITY_ATTRIBUTES lpEventAttributes,
	_In_ BOOL bManualReset,
	_In_ BOOL bInitialState,
	_In_opt_ LPCWSTR lpName);

namespace M2
{
	// 按范围取值
	template<typename T>
	inline T M2GetValueByRange(T Value, T Min, T Max)
	{
		return ((Value > Min) ? ((Value > Max) ? Max : Value) : Min);
	}

	// 在默认堆上分配内存
	template<typename PtrType>
	FORCEINLINE NTSTATUS M2HeapAlloc(
		_In_ SIZE_T Size,
		_Out_ PtrType &BaseAddress)
	{
		BaseAddress = (PtrType)RtlAllocateHeap(RtlProcessHeap(), 0, Size);
		return (BaseAddress ? STATUS_SUCCESS : STATUS_NO_MEMORY);
	}

	// 内存指针模板类
	template<typename PtrType> class CPtr
	{
	public:
		// 分配内存
		bool Alloc(_In_ size_t Size)
		{
			if (m_Ptr) this->Free();
			m_Ptr = malloc(Size);
			return (m_Ptr != nullptr);
		}

		// 释放内存
		void Free()
		{
			free(m_Ptr);
			m_Ptr = nullptr;
		}

		// 获取内存指针
		operator PtrType() const
		{
			return (PtrType)m_Ptr;
		}

		// 获取内存指针(->运算符)
		PtrType operator->() const
		{
			return (PtrType)m_Ptr;
		}

		// 设置内存指针
		CPtr& operator=(_In_ PtrType Ptr)
		{
			if (Ptr != m_Ptr) // 如果值相同返回自身,否则赋新值
			{
				if (m_Ptr) this->Free(); // 如果内存已分配则释放			
				m_Ptr = Ptr; // 设置内存指针
			}
			return *this; // 返回自身
		}

		// 退出时释放内存
		~CPtr()
		{
			if (m_Ptr) this->Free();
		}

	private:
		//指针内部变量
		void *m_Ptr = nullptr;
	};

	// 忽略未调用参数警告
	template<typename T> void UnReferencedParameter(const T&) {}

	// 获取dll函数入口
	template<typename FuncType> FORCEINLINE NTSTATUS M2GetFunc(
		_In_ PVOID lpDllModule,
		_In_ LPSTR lpFuncName,
		_Out_ FuncType &pFuncAddress)
	{
		ANSI_STRING asFuncName;

		M2InitString(asFuncName, lpFuncName);

		return LdrGetProcedureAddress(
			lpDllModule, &asFuncName, 0,
			reinterpret_cast<PVOID*>(&pFuncAddress));
	}
}

#endif


#endif


//*****************************************************************************
// Windows 10未文档化DPI支持相关定义
// Windows 10 DPI Support Definations
//*****************************************************************************
#ifndef _M2_WINDOWS_INTERNAL_WINDOWS10DPISUPPORT_
#define _M2_WINDOWS_INTERNAL_WINDOWS10DPISUPPORT_

#if _MSC_VER >= 1200
#pragma warning(push)
// 从“type of expression”到“type required”的不安全转换(等级 3)
#pragma warning(disable:4191) 
#endif

#ifdef __cplusplus
extern "C" {
#endif

	typedef INT(WINAPI *PFN_EnablePerMonitorDialogScaling)();
	typedef BOOL(WINAPI *PFN_EnableChildWindowDpiMessage)(HWND, BOOL);
	typedef BOOL(WINAPI *PFN_NtUserEnableChildWindowDpiMessage)(HWND, BOOL);

	/*
	EnablePerMonitorDialogScaling函数为指定对话框启用Per-Monitor DPI Aware支
	持。
	The EnablePerMonitorDialogScaling function enables the Per-Monitor DPI
	Aware for the specified dialog.

	你需要在Windows 10 Threshold 1 及以后的版本使用该函数。
	You need to use this function in Windows 10 Threshold 1 or later.
	*/
	FORCEINLINE INT EnablePerMonitorDialogScaling()
	{
		UNICODE_STRING usDllName;
		PVOID pDllHandle = nullptr;
		PFN_EnablePerMonitorDialogScaling pFunc = nullptr;

		M2InitUnicodeString(usDllName, const_cast<PWSTR>(L"user32.dll"));

		if (!NT_SUCCESS(LdrGetDllHandleEx(
			0, nullptr, nullptr, &usDllName, &pDllHandle)))
			return -1;
		if (!NT_SUCCESS(LdrGetProcedureAddress(
			pDllHandle, nullptr, 2577, reinterpret_cast<PVOID*>(&pFunc))))
			return -1;

		return pFunc();
	}

	/*
	EnableChildWindowDpiMessage函数启用指定子窗口的DPI消息。
	The EnableChildWindowDpiMessage function enables the dpi messages from the
	specified child window.

	你需要在Windows 10 Threshold 1 和 Windows Threshold 2使用该函数。Windows
	10 Redstone 1 及以后的版本需要使用NtUserEnableChildWindowDpiMessage。
	You need to use this function in Windows 10 Threshold 1 and Windows 10
	Threshold 2. You need to use NtUserEnableChildWindowDpiMessage in Windows
	10 Redstone 1 or later.
	*/
	FORCEINLINE BOOL EnableChildWindowDpiMessage(
		_In_ HWND hWnd,
		_In_ BOOL bEnable)
	{
		UNICODE_STRING usDllName;	
		ANSI_STRING asFuncName;
		PVOID pDllHandle = nullptr;
		PFN_EnableChildWindowDpiMessage pFunc = nullptr;

		M2InitUnicodeString(usDllName, const_cast<PWSTR>(L"user32.dll"));
		M2InitString(asFuncName, "EnableChildWindowDpiMessage");

		if (!NT_SUCCESS(LdrGetDllHandleEx(
			0, nullptr, nullptr, &usDllName, &pDllHandle)))
			return -1;
		if (!NT_SUCCESS(LdrGetProcedureAddress(
			pDllHandle, &asFuncName, 0, reinterpret_cast<PVOID*>(&pFunc))))
			return -1;

		return pFunc(hWnd, bEnable);
	}

	/*
	NtUserEnableChildWindowDpiMessage函数启用指定子窗口的DPI消息。
	The NtUserEnableChildWindowDpiMessage function enables the dpi messages
	from the specified child window.

	你需要在Windows 10 Redstone 1 及以后的版本使用该函数。
	You need to use this function in Windows 10 Redstone 1 or later.
	*/
	FORCEINLINE BOOL NtUserEnableChildWindowDpiMessage(
		_In_ HWND hWnd,
		_In_ BOOL bEnable)
	{
		UNICODE_STRING usDllName;
		ANSI_STRING asFuncName;	
		PVOID pDllHandle = nullptr;
		PFN_NtUserEnableChildWindowDpiMessage pFunc = nullptr;

		M2InitUnicodeString(usDllName, const_cast<PWSTR>(L"win32u.dll"));
		M2InitString(asFuncName, "NtUserEnableChildWindowDpiMessage");

		if (!NT_SUCCESS(LdrGetDllHandleEx(
			0, nullptr, nullptr, &usDllName, &pDllHandle)))
			return -1;
		if (!NT_SUCCESS(LdrGetProcedureAddress(
			pDllHandle, &asFuncName, 0, reinterpret_cast<PVOID*>(&pFunc))))
			return -1;

		return (pFunc ? pFunc(hWnd, bEnable) : -1);
	}

#ifdef __cplusplus
}
#endif

#if _MSC_VER >= 1200
#pragma warning(pop)
#endif

#endif

#ifndef _COM_HELPER_
#define _COM_HELPER_

// 为编译通过而禁用的警告
#if _MSC_VER >= 1200
#pragma warning(push)
#pragma warning(disable:4820) // 字节填充添加在数据成员后(等级 4)
#endif

namespace M2
{

#define COM_INTERFACE_ENTRY(Interface) \
	if (__uuidof(Interface) == riid) \
	{ \
		*ppvObject = (Interface*)this; \
		AddRef(); \
		return S_OK; \
	}

#define COM_INTERFACE_MAP_BEGIN \
	__forceinline HRESULT InternalQueryInterface( \
		REFIID riid, \
		void __RPC_FAR *__RPC_FAR *ppvObject) \
	{

#define COM_INTERFACE_MAP_END \
	COM_INTERFACE_ENTRY(IUnknown); \
	return E_NOINTERFACE; \
	}

	// 单线程COM对象模板类
	template <class BaseClass, class Interface>
	class CComObject : public Interface
	{
	private:
		ULONG m_ulRef;

	public:
		// 构造函数
		CComObject() :m_ulRef(1)
		{
		}

		// 析构函数
		virtual ~CComObject()
		{
		}

		// 查询接口
		virtual HRESULT STDMETHODCALLTYPE QueryInterface(
			REFIID riid,
			void __RPC_FAR *__RPC_FAR *ppvObject)
		{
			return ((BaseClass*)this)->InternalQueryInterface(riid, ppvObject);
		}

		// 增加引用计数
		virtual ULONG STDMETHODCALLTYPE AddRef()
		{
			return InterlockedIncrement(&m_ulRef);
		}

		// 释放引用计数
		virtual ULONG STDMETHODCALLTYPE Release()
		{
			ULONG dwRet = InterlockedDecrement(&m_ulRef);

			// 如果释放计数后等于0释放自身
			if (dwRet == 0) delete (BaseClass*)this;

			// 否则返回当前计数
			return dwRet;
		}
	};
}

#if _MSC_VER >= 1200
#pragma warning(pop)
#endif

#endif