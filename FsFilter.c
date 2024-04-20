#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#define MAX_PATH 260
enum role
{
	breaker,//никакакого доступа
	reader,
	writer,
	admin//полный доступ
};
enum operation
{
	reading,
	writing
};
struct oneItem
{
	CHAR proccess[30];
	enum role rl;
};

struct oneItem processItems[20];
INT count_processItems = 0;
PFLT_FILTER FilterHandle = NULL;
extern UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process);
WCHAR targetDirectory[MAX_PATH] = { 0 };

CHAR* GetProcessNameFromPid(HANDLE pid)
{
	PEPROCESS Process;
	if (PsLookupProcessByProcessId(pid, &Process) == STATUS_INVALID_PARAMETER)
		return NULL;
	return (CHAR*)PsGetProcessImageFileName(Process);
}

NTSTATUS checkItem(enum operation oper)
{
	HANDLE proccess_handle = PsGetCurrentProcessId();
	char* proccessName = GetProcessNameFromPid(proccess_handle);
	DbgPrint("Proccess name: %s\n", proccessName);
	for (int i = 0; i < count_processItems; i++) {
		if (strcmp(processItems[i].proccess, proccessName) == 0) {
			if (processItems[i].rl == admin || (processItems[i].rl == reader && oper == reading) || (processItems[i].rl == writer && oper == writing))
				return STATUS_SUCCESS;
			else
				return STATUS_ACCESS_DENIED;
		}
	}
	return STATUS_ACCESS_DENIED;
}

FLT_PREOP_CALLBACK_STATUS BeforeIO(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletetionContext)
{
	PFLT_FILE_NAME_INFORMATION FileNameInfo;
	NTSTATUS status;
	wchar_t parentDirectory[MAX_PATH] = { 0 };
	
	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInfo);
	if (NT_SUCCESS(status))
	{
		status = FltParseFileNameInformation(FileNameInfo);
		if (NT_SUCCESS(status)) 
		{
			RtlCopyMemory(parentDirectory, FileNameInfo->ParentDir.Buffer, FileNameInfo->ParentDir.MaximumLength);
			if (wcscmp(parentDirectory, targetDirectory) == 0) {
				enum operation currentOperation = -1;
				if (Data->Iopb->IrpFlags & IRP_WRITE_OPERATION) {//проверяем какая операция чтение или запись
					currentOperation = writing;
					DbgPrint("Write operation in %ws\n", parentDirectory);
				}
				else if (Data->Iopb->IrpFlags & IRP_READ_OPERATION) {
					currentOperation = reading;
					DbgPrint("Read operation in %ws\n", parentDirectory);
				}
				if (checkItem(currentOperation) != STATUS_SUCCESS)
				{
					DbgPrint("Access denied!\n");
					Data->IoStatus.Status = STATUS_ACCESS_DENIED;
					FltReleaseFileNameInformation(FileNameInfo);
					return FLT_PREOP_COMPLETE;
				}
				else
					DbgPrint("Access allowed!\n");
			}
		}
		FltReleaseFileNameInformation(FileNameInfo);
	}
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

const FLT_OPERATION_REGISTRATION Callbacks[] = {//регистрация колбэков, которые вызываются при любой операции чтения и записи
	{IRP_MJ_CREATE,0,BeforeIO,NULL},
	{IRP_MJ_WRITE,0,BeforeIO,NULL},
	{IRP_MJ_READ,0,BeforeIO,NULL},
	{IRP_MJ_OPERATION_END}
};

NTSTATUS driverUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
	DbgPrint("Driver unload\n");
	FltUnregisterFilter(FilterHandle);
	return STATUS_SUCCESS;
}

const FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION),
	FLT_REGISTRATION_VERSION,
	0,
	NULL,
	Callbacks,
	driverUnload,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
};

NTSTATUS readConfig()//чтение конфиг файла 
{
	UNICODE_STRING     uniName;
	OBJECT_ATTRIBUTES  objAttr;

	RtlInitUnicodeString(&uniName, L"\\??\\C:\\Users\\karam\\Desktop\\conf.txt");//ввести свой путь на виртуалке
	InitializeObjectAttributes(&objAttr, &uniName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);

	HANDLE   handle;
	NTSTATUS ntstatus;
	IO_STATUS_BLOCK    ioStatusBlock;

	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
		return STATUS_INVALID_DEVICE_STATE;

	PCHAR next_str, context;
	LARGE_INTEGER      byteOffset;
	//открытие файла на чтение
	ntstatus = ZwCreateFile(&handle, GENERIC_READ, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (NT_SUCCESS(ntstatus))
		DbgPrint("Openning config file: Success\n");
	else {
		DbgPrint("Openning config file: Error %d \n", RtlNtStatusToDosError(ntstatus));
		return ntstatus;
	}

	if (NT_SUCCESS(ntstatus))
	{
		byteOffset.LowPart = byteOffset.HighPart = 0;
		CHAR confBuffer[1024] = { 0 };
		ntstatus = ZwReadFile(handle, NULL, NULL, NULL, &ioStatusBlock,//читаем из файла в confBuffer
			confBuffer, 1024, &byteOffset, NULL);
		confBuffer[strlen(confBuffer)] = '\0';

		if (NT_SUCCESS(ntstatus))
		{
			INT i = 2, j = 0;
			for (i = 2, j = 0; confBuffer[i] != '\n' && confBuffer[i] != 13; i++, j++)//13 - спец символ из ascii (скорее всего завершение строки или что то подобное) 
				targetDirectory[j] = confBuffer[i];
			targetDirectory[j] = '\0';//прочитали отслеживаемую директорию
			i+=2;
			
			INT size = strlen(confBuffer);
			while (i < size) //читаем оставшиеся строки файла, заполняем массив с правилами
			{
				CHAR rule_str[50];
				j = 0;
				while (confBuffer[i] != '\n')//читаем до переноса строки
				{
					rule_str[j] = confBuffer[i];
					j++;
					i++;
				}
				rule_str[j] = '\0';

				INT k = 0;
				while (rule_str[k] != ':') {
					processItems[count_processItems].proccess[k] = rule_str[k];//получаем имя процесса
					k++;
				}
				processItems[count_processItems].proccess[k] = '\0';
				k++;
				
				for (int y = k; y < strlen(rule_str); y++) {
					if (rule_str[y] == 13)
						rule_str[y] = '\0';
				}
				if (strcmp((rule_str + k), "reader") == 0)//получаем роль процесса
					processItems[count_processItems].rl = reader;
				else if (strcmp((rule_str + k), "writer") == 0)
					processItems[count_processItems].rl = writer;
				else if (strcmp((rule_str + k), "admin") == 0)
					processItems[count_processItems].rl = admin;
				else
					processItems[count_processItems].rl = breaker;
				DbgPrint("Process: %s Role: %d\n", processItems[count_processItems].proccess, processItems[count_processItems].rl);
				count_processItems++;
				i++;
			}
		}
		ZwClose(handle);
	}
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RehistryPath)
{
	NTSTATUS status;
	status = FltRegisterFilter(DriverObject, &FilterRegistration, &FilterHandle);

	if (NT_SUCCESS(status)) {

		status = readConfig();
		if (status != STATUS_SUCCESS) {
			DbgPrint("Reading config file: Error %d\n", status);
			return status;
		}
		else
			DbgPrint("Reading config file: Success\n");


		status = FltStartFiltering(FilterHandle);
		if (!NT_SUCCESS(status))
			FltUnregisterFilter(FilterHandle);
	}
	return status;
}