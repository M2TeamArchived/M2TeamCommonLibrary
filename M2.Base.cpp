/******************************************************************************
项目：M2-SDK
描述：M2-SDK 基本定义实现
文件名：M2.Base.cpp
许可协议：看顶层目录的 License.txt
建议的最低 Windows SDK 版本：10.0.10586
提示：无

Project: M2-SDK
Description: Implemention of Base M2-SDK Definitions
Filename: M2.Base.cpp
License: See License.txt in the top level directory
Recommend Minimum Windows SDK Version: 10.0.10586
Tips: N/A
******************************************************************************/

#include "M2.Windows.h" // Windows API 基本定义
#include "M2.Base.h" // M2-SDK 基本定义

namespace M2
{
	// 创建事件对象, 不内联考虑到大量使用本函数时实现函数复用以节约空间
	NTSTATUS WINAPI M2CreateEvent(
		_Out_ PHANDLE phEvent,
		_In_opt_ LPSECURITY_ATTRIBUTES lpEventAttributes,
		_In_ BOOL bManualReset,
		_In_ BOOL bInitialState,
		_In_opt_ LPCWSTR lpName)
	{
		OBJECT_ATTRIBUTES ObjectAttributes;
		UNICODE_STRING NtFileName;

		M2InitObjectAttributes(ObjectAttributes);

		if (lpEventAttributes &&
			lpEventAttributes->nLength == sizeof(SECURITY_ATTRIBUTES))
		{
			if (lpEventAttributes->bInheritHandle)
				ObjectAttributes.Attributes = OBJ_INHERIT;
			ObjectAttributes.SecurityDescriptor =
				lpEventAttributes->lpSecurityDescriptor;
		}

		if (lpName)
		{
			M2InitUnicodeString(NtFileName, (PWSTR)lpName);
			ObjectAttributes.ObjectName = &NtFileName;
		}

		return NtCreateEvent(
			phEvent,
			EVENT_ALL_ACCESS,
			&ObjectAttributes,
			bManualReset ? NotificationEvent : SynchronizationEvent,
			(BOOLEAN)bInitialState);
	}
}
