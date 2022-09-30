#include <windows.h>
#include <stdio.h>

unsigned short gerioprint(unsigned char *impressora, unsigned char *dados, unsigned short dados_len){
	
	HANDLE hPrinter;
	int r = OpenPrinter(impressora, &hPrinter, NULL);
	if(!r){
		
		printf("erro\n");
		return 1;
	}
	DWORD sSize = 16;
	BYTE printData[16];
	r = AddJob(hPrinter, 1, printData, 16, &sSize);
	BYTE fPrintData[sSize];
	r = AddJob(hPrinter, 1, fPrintData, sSize, &sSize);
	if(!r){
		
		ClosePrinter(hPrinter);
		printf("erro:%d\n", GetLastError());
		return 1;
	}
	ADDJOB_INFO_1 *jobInfo = (ADDJOB_INFO_1*)fPrintData;
	
	HANDLE hFile = CreateFile(jobInfo->Path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile == INVALID_HANDLE_VALUE){
		
		ClosePrinter(hPrinter);
		printf("erro:%d\n", GetLastError());
		return 1;
	}
	WriteFile(hFile, dados, dados_len, NULL, NULL);
	CloseHandle(hFile);
	ScheduleJob(hPrinter, jobInfo->JobId);
	
	ClosePrinter(hPrinter);
	return 0;
}