# Code/API Specification

## Chapter 1: API Overview

### 1.1 Overview

This document provides the API specifications for the **Distributed Log Parsing Library** (hereinafter referred to as "log parsing library").

### 1.2 API Composition

The library provides APIs for various functionalities.

| Functionality | Function Name | Parameter | Return Value | Etc. |
| --- | --- | --- | --- | --- |
| File Operation | analyze_File | char* fileDirectory, F_info* attribute | void |  |
|  | getLine_Count | FILE* fp | unsigned int |  |
|  | getFile_Size | FILE* fp | unsigned int |  |
|  | fileSpliter | char* inputDir, char* baseDir, int line | int |  |
| Data Structure - List | List_create | void | parsingResult* |  |
|  | List_insert | parsingResult** target, parsingResult* newNode | void |  |
|  | List_delete | parsingResult* target | void |  |
|  | List_count | parsingResult* target | int |  |
| Read File Thread | readThread | char* path, FILE_SEARCH file_search, char* search_point, int index | file_parsing* |  |
|  | GetfileList | char* path, char* search_point | parsingResult* |  |
|  | Thread_R | void* lpParam | unsigned int | Calling convention: __stdcall |
| Searching Pattern | logScaner | char* getLine, pcapInfo* output | void |  |
|  | landAttack | pcapInfo* checker | int |  |
|  | suspicious_syn_Flood | pcapInfo* checker | int |  |
|  | suspicious_Smurf | char* broadcastAddr, pcapInfo* checker | int |  |

### 1.3 Dependencies

The parsing library does not use any third-party libraries and relies solely on C language and libraries available on Windows.

The following is the list of libraries used:

```c
<direct.h>, <io.h>, <process.h>, <stdio.h>, <stdlib.h>, <string.h>, <time.h>, <Windows.h>, <sys/types.h>
```

### 1.4 Library Internal Code Management Structure

- `all.h` : Contains definitions for thread-based list and search functions, as well as standard C libraries.
- `all.cpp` : Source file where the function implementations of the library are stored.
- `testcode.cpp` : Test code file used to verify the normal operation of the library.

---

## Chapter 2: API Specification

### 2.1 Structures and Global Variables

```c
extern HANDLE hthread[1000];
extern CRITICAL_SECTION cs;
extern parsingResult* firstNode;
```

- **hthread** : A global array storing thread handles, used for managing processing response time and termination.
- **cs** : Used for critical section setting to prevent errors caused by concurrent access to internal links in multi-threaded list operations.
- **firstNode** : A pointer variable holding the starting address of the list, used for node insertion operations by threads.

```c
typedef struct pcapText_Line {
	char seqNum[10];
	char time[20];
	char sendAddr[20];
	char recvAddr[20];
	char protocol[20];
	char option[200];
} pcapInfo;

typedef struct _parsingResult {
	pcapInfo data;
	struct _parsingResult* next;
} parsingResult;

typedef struct File_information {
	unsigned int fileSize;
	unsigned int fileRow;
} F_info;

typedef struct arg {
	char fullDirectory[200];
	char search_type[100];
	char broadcast_Addr[16];
	parsingResult* Node;
} file_parsing;

typedef struct _finddata_t FILE_SEARCH;
```

- **pcapText_Line** : Structure for storing parsed results from tshark logs.
- **parsingResult** : Node structure for storing parsed log results in a list format.
- **arg** : Structure for passing arguments to threads.

### 2.2 File Management

```c
void analyze_File(char* fileDirectory, F_info* attribute);
unsigned int getLine_Count(FILE* fp);
unsigned int getFile_Size(FILE* fp);
int fileSpliter(char* inputDir, char* baseDir, int line);
```

- *void analyze_File(char fileDirectory, F_info* attribute);**
    - Parameters: `char* fileDirectory`, `F_info* attribute`
    - Function: Parses the number of lines and size information of the file and stores it in the `attribute` pointer.
    - Return Value: void
- *unsigned int getLine_Count(FILE fp);*
    - Parameters: `FILE* fp`
    - Function: Returns the number of lines in the file.
    - Return Value: Line count (unsigned int)
- *unsigned int getFile_Size(FILE fp);*
    - Parameters: `FILE* fp`
    - Function: Measures the size of the file.
    - Return Value: File size (unsigned int)
- *int fileSpliter(char inputDir, char* baseDir, int line);**
    - Parameters: `char* inputDir`, `char* baseDir`, `int line`
    - Function: Splits the input file into the specified number of lines and saves them in the `baseDir` path.
    - Return Value:
        - Success: 1
        - Error Codes:
            - 1 (Input path error)
            - 2 (Output path error)
            - 3 (Unknown error)
            - 0 (Insufficient arguments)

### 2.3 List Operations

```c
parsingResult* List_create();
void List_insert(parsingResult** target, parsingResult* newNode);
void List_delete(parsingResult* target);
int List_count(parsingResult* target);
```

- *parsingResult List_create();*
    - Parameters: void
    - Function: Allocates memory dynamically for a `parsingResult` structure and returns a pointer.
    - Return Value: `parsingResult*`
- **void List_insert(parsingResult** target, parsingResult* newNode);**
    - Parameters: `parsingResult** target`, `parsingResult* newNode`
    - Function: Inserts `newNode` into the list.
    - Return Value: void
- *void List_delete(parsingResult target);*
    - Parameters: `parsingResult* target`
    - Function: Deallocates all dynamically allocated nodes in the list.
    - Return Value: void
- *int List_count(parsingResult target);*
    - Parameters: `parsingResult* target`
    - Function: Counts and returns the number of nodes in the list.
    - Return Value: Number of nodes (int)

### 2.4 Threads

```c
void readThread(char* path, FILE_SEARCH file_search, char* search_point, int index);
parsingResult* GetfileList(char* path, char* search_point);
unsigned int __stdcall Thread_R(void* lpParam);
```

- *void readThread(char path, FILE_SEARCH file_search, char* search_point, int index);**
    - Parameters: `char* path`, `FILE_SEARCH file_search`, `char* search_point`, `int index`
    - Function: Calls a thread to process split files based on the provided search options.
    - Return Value: void
- *parsingResult GetfileList(char* path, char* search_point);**
    - Parameters: `char* path`, `char* search_point`
    - Function: Sequentially calls threads to search for DOS attack patterns in the split files.
    - Return Value: Pointer to the start of the list containing search results (`parsingResult*`)
- *unsigned int __stdcall Thread_R(void lpParam);*
    - Parameters: `void* lpParam`
    - Function: Searches for patterns based on specified search options and inserts them into the list.
    - Return Value: void

### 2.5 Pattern Search

```c
void logScaner(char* getLine, pcapInfo* output);
int landAttack(pcapInfo* checker);
int suspicious_syn_Flood(pcapInfo* checker);
int suspicious_Smurf(char* broadcastAddr, pcapInfo* checker);
```

- *void logScaner(char getLine, pcapInfo* output);**
    - Parameters: `char* getLine`, `pcapInfo* output`
    - Function: Parses the input log string and stores it in the `pcapInfo` structure.
    - Return Value: void
- *int landAttack(pcapInfo checker);*
    - Parameters: `pcapInfo* checker`
    - Function: Checks if the parsed log indicates a LAND attack pattern.
    - Return Value:
        - Success: 1 (LAND attack pattern)
        - Failure: 0 (Other pattern)
- *int suspicious_syn_Flood(pcapInfo checker);*
    - Parameters: `pcapInfo* checker`
    - Function: Checks if the parsed log indicates a SYN Flood attack pattern.
    - Return Value:
        - Success: 1 (SYN Flood pattern)
        - Failure: 0 (Other pattern)
- *int suspicious_Smurf(char broadcastAddr, pcapInfo* checker);**


## Chapter 3: Test Code

### 3.1 Test Code Source

```c
#include "all.h"
#include <time.h>

void Analyzing(char* analysisFile, char* temp, char* dosSignature);

int main() {
	// File path
	// Save path
	// Analysis item
	// Retrieve list
	clock_t start1, end1;
	float res1;

	char analysisFile[300] = "C:/Users/kimse/Desktop/text.txt";
	char temp[300] = "C:/Users/kimse/Desktop/temp/";
	char dosSignature[300] = "suspicious_syn_Flood";

	//InitializeCriticalSection(&cs);
	start1 = clock();
	Analyzing(analysisFile, temp, dosSignature);
	end1 = clock();
	res1 = (float)(end1 - start1) / CLOCKS_PER_SEC;
	printf(" Time taken for multi-threaded operation: %.3f seconds \n", res1);
	//DeleteCriticalSection(&cs);

	return 0;
}

void Analyzing(char* analysisFile, char* temp, char* dosSignature) {	
	// File splitting

	//int line = getLine_Count()
	if (fileSpliter(analysisFile, temp, 5) != 1) {
		printf("Failed to split the file.");
		return;
	}
	parsingResult* test = GetfileList(temp, dosSignature);
	parsingResult* temps = test;
	temps = temps->next;

	printf("Final results ---------------\n");
	while (1) {
		printf("%s %s\n", temps->data.seqNum, temps->data.recvAddr);
		temps = temps->next;
		if (temps == NULL)
			break;
	}
	
}

```

### 3.2 Test Results

```c
    1   0.000000 64.233.189.188 172.30.1.26  TCP 66 443 58964 [ACK] Seq=1 Ack=1 Win=265 Len=0 SLE=0 SRE=1
    2   0.266836  172.30.1.26 34.64.4.10   UDP 75 53615 443 Len=33
    3   0.300480   34.64.4.10 172.30.1.26  UDP 67 443 53615 Len=25
    4   5.836485  172.30.1.26 13.225.125.157 TCP 54 58935 80 [FIN, ACK] Seq=1 Ack=1 Win=517 Len=0
    5   5.844743 13.225.125.157 172.30.1.26  TCP 54 80 58935 [FIN, ACK] Seq=1 Ack=2 Win=131 Len=0
    6   5.844818  172.30.1.26 13.225.125.157 TCP 54 58935 80 [ACK] Seq=2 Ack=2 Win=517 Len=0
    4   5.836485  172.30.1.26 13.225.125.157 TCP 54 58935 80 [FIN, ACK] Seq=1 Ack=1 Win=517 Len=0
    5   5.844743 13.225.125.157 172.30.1.26  TCP 54 80 58935 [FIN, ACK] Seq=1 Ack=2 Win=131 Len=0
    6   5.844818  172.30.1.26 13.225.125.157 TCP 54 58935 80 [ACK] Seq=2 Ack=2 Win=517 Len=0
    6   5.844818  172.30.1.26 13.225.125.157 TCP 54 58935 80 [ACK] Seq=2 Ack=2 Win=517 Len=0
```

### (Left - Thread-based operation, Right - Single-process operation)

![https://www.notion.soTshark%20log%20parser%20(based%20in%20thread%20list!!!)%201092382dbb9e45d5bbc4723b45164897/Untitled%201.png](https://www.notion.soTshark%20log%20parser%20(based%20in%20thread%20list!!!)%201092382dbb9e45d5bbc4723b45164897/Untitled%201.png)

![https://www.notion.soTshark%20log%20parser%20(based%20in%20thread%20list!!!)%201092382dbb9e45d5bbc4723b45164897/Untitled%202.png](https://www.notion.soTshark%20log%20parser%20(based%20in%20thread%20list!!!)%201092382dbb9e45d5bbc4723b45164897/Untitled%202.png)

![https://www.notion.soTshark%20log%20parser%20(based%20in%20thread%20list!!!)%201092382dbb9e45d5bbc4723b45164897/Untitled%203.png](https://www.notion.soTshark%20log%20parser%20(based%20in%20thread%20list!!!)%201092382dbb9e45d5bbc4723b45164897/Untitled%203.png)

From the test results, it is evident that thread-based operations provide faster search results compared to single-process operations.

### 3.3 Precautions

1. **List Results**
    - Results from the list operations are based on thread-based search and insertion; therefore, no additional sorting is performed.
2. **List Operations**
    - The library does not provide thread support for operations other than list insertion.
3. **Tshark Log Format Issues**
    - The original text log is read as ASCII, which may not correctly interpret the ‘→’ character.
    - If using this library, please ensure that the ‘→’ character is removed from the log files before processing.
4. **Threads and File Splitting**
    - Due to the design of the code, a separate thread is created for parsing each split file.
    - Performance degradation may occur if the number of threads exceeds 3, so consider the number of lines for file splitting accordingly.
    - Parameters: `char* broadcastAddr`, `pcapInfo* checker`
    - Function: Checks if the parsed log indicates a Smurf attack pattern.
    - Return Value:
        - Success: 1 (Smurf pattern)
        - Failure: 0 (Other pattern)
