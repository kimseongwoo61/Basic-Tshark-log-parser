# Tshark Log Parser (based on thread list)

### Overview

The **Distributed Log Parsing Library** is designed to analyze Tshark log files efficiently and rapidly using multithreading. This library, implemented in C and using Windows libraries exclusively, provides comprehensive functionality for file management, list management, threading, and pattern detection.

### Key Features

- **File Management**: Analyze files, count lines, calculate file sizes, and split files.
- **List Management**: Create, insert, delete, and count list items.
- **Thread Management**: Read files using threads, retrieve file lists, and execute threads.
- **Pattern Detection**: Log scanner, Land attack detection, suspicious SYN Flood detection, and suspicious Smurf attack detection.

### Usage Example

```c
#include "all.h"
#include <time.h>
void Analyzing(char* analysisFile, char* temp, char* dosSignature);

int main() {
    clock_t start1, end1;
    float res1;

    char analysisFile[300] = "C:/Users/kimse/Desktop/text.txt";
    char temp[300] = "C:/Users/kimse/Desktop/temp/";
    char dosSignature[300] = "suspicious_syn_Flood";

    start1 = clock();
    Analyzing(analysisFile, temp, dosSignature);
    end1 = clock();
    res1 = (float)(end1 - start1) / CLOCKS_PER_SEC;
    printf("Multithreaded execution time: %.3f seconds\n", res1);

    return 0;
}

void Analyzing(char* analysisFile, char* temp, char* dosSignature) {
    if (fileSpliter(analysisFile, temp, 5) != 1) {
        printf("Failed to split the file.");
        return;
    }
    parsingResult* test = GetfileList(temp, dosSignature);
    parsingResult* temps = test;
    temps = temps->next;

    printf("Results:\n");
    while (temps != NULL) {
        printf("%s %s\n", temps->data.seqNum, temps->data.recvAddr);
        temps = temps->next;
    }
}

```

### Additional Information

- **Environment**: This program is written using Visual Studio and supports only Windows environments.
- **Usage Instructions**: Download the files from the GitHub repository, open the solution file in Visual Studio, and run the program.

### For more information

- **Code/Feature Specification**:  [Link](https://github.com/kimseongwoo61/Basic-Tshark-log-parser/blob/main/specification.MD)

