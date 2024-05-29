#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "dirent.h"

#define FILE_NAME "AntiVirusLog.txt"

typedef struct file {
    char* fileName;
    char* filePath;
} fileStruct;

bool isInfected(char* filePath, char* virusPath, int kind);
fileStruct* sortFiles(char* directoryPath, int* size);
void sort(fileStruct* arr, int size);
void putValueInStruct(fileStruct* arr, int arrSize, char* dirPath);
int showMenu(char* filesPath, char* signPath);
void printResult(fileStruct* arr, int size, char* signPath, char* folder, FILE* logFile);
void printQuickResult(fileStruct* arr, int size, char* signPath, char* folder, FILE* logFile);
char* folderToFile(char* folderPath);

int main(int argc, char** argv)
{
    int choice = 0;  // Initialize choice variable
    if (argc != 3)  // Check if the correct number of arguments is provided
    {
        printf("Usage %s <folder> <virus_signature>\n", argv[0]);  // Print usage message
        return 0;  // Exit program
    }

    choice = showMenu(argv[1], argv[2]);  // Display menu and get user choice
    int filesAmount = 0;  // Initialize files amount
    fileStruct* fileArr = sortFiles(argv[1], &filesAmount);  // Sort files in the folder

    if (fileArr == NULL)
    {  // Check if file array is NULL
        printf("No files to scan or an error occurred.\n");  // Print error message
        return 1;  // Exit program with error
    }

    putValueInStruct(fileArr, filesAmount, argv[1]);  // Populate file array with values

    char* logFilePath = folderToFile(argv[1]);  // Generate log file path from folder
    FILE* logFile = fopen(logFilePath, "w");  // Open log file for writing
    if (logFile == NULL)
    {  // Check if log file opening failed
        perror("Failed to open log file");  // Print error message
        free(logFilePath);  // Free allocated memory for log file path
        return 1;  // Exit program with error
    }

    if (choice == 0)  // Check if the choice is 0
    {
        printResult(fileArr, filesAmount, argv[2], argv[1], logFile);  // Print detailed results
    }
    else
    {
        printQuickResult(fileArr, filesAmount, argv[2], argv[1], logFile);  // Print quick results
    }

    for (int i = 0; i < filesAmount; i++)
    {  // Loop through each file in file array
        free(fileArr[i].fileName);  // Free allocated memory for file name
        free(fileArr[i].filePath);  // Free allocated memory for file path
    }
    free(fileArr);  // Free allocated memory for file array
    free(logFilePath);  // Free allocated memory for log file path
    fclose(logFile);  // Close log file
    getchar();
    return 0;  // Exit program successfully
}
/*
* this function will check if the virus signature is in the file
* input: file path, the signature path, the kind(first 20% )
* output: true if the signatur is in the file false else
*/
bool isInfected(char* filePath, char* virusPath, int kind)
{
    FILE* file = fopen(filePath, "rb");  // Open the file to scan in binary mode
    FILE* virus = fopen(virusPath, "rb");  // Open the virus signature file in binary mode
    long i = 0;  // Initialize loop variable
    int addToLast = 0;  // Initialize variable for additional offset
    if (file == NULL || virus == NULL)
    {  // Check if either file failed to open
        if (file != NULL) fclose(file);  // Close the file if it was opened
        if (virus != NULL) fclose(virus);  // Close the virus file if it was opened
        return false;  // Return false indicating no infection check could be performed
    }

    fseek(file, 0, SEEK_END);  // Move to the end of the file
    long fileSize = ftell(file);  // Get the size of the file
    fseek(file, 0, SEEK_SET);  // Move back to the beginning of the file


    fseek(virus, 0, SEEK_END);  // Move to the end of the virus file
    long virusSize = ftell(virus);  // Get the size of the virus file
    fseek(virus, 0, SEEK_SET);  // Move back to the beginning of the virus file

    if (virusSize > fileSize)
    {  // Check if virus size is greater than file size
        fclose(file);  // Close the file
        fclose(virus);  // Close the virus file
        return false;  // Return false indicating no infection
    }

    bool found = false;  // Initialize infection found flag
    char* fileBuffer = (char*)malloc(virusSize);  // Allocate buffer for file data
    char* virusBuffer = (char*)malloc(virusSize);  // Allocate buffer for virus data

    if (fileBuffer == NULL || virusBuffer == NULL)
    {  // Check if memory allocation failed
        if (fileBuffer != NULL) free(fileBuffer);  // Free file buffer if allocated
        if (virusBuffer != NULL) free(virusBuffer);  // Free virus buffer if allocated
        fclose(file);  // Close the file
        fclose(virus);  // Close the virus file
        return false;  // Return false indicating no infection check could be performed
    }

    fread(virusBuffer, 1, virusSize, virus);  // Read virus signature into buffer
    if (kind == 1)  // Check if kind is 1
    {
        for (i = 0; i <= fileSize - virusSize; i++)
        {  // Loop through file data
            fseek(file, i, SEEK_SET);  // Move to current position in file
            fread(fileBuffer, 1, virusSize, file);  // Read file data into buffer

            if (memcmp(fileBuffer, virusBuffer, virusSize) == 0)
            {  // Compare buffers
                found = true;  // Set infection found flag
                break;  // Exit loop
            }
        }
    }
    else if (kind == 3)  // Check if kind is 3
    {

        for (i = 0; i <= fileSize - virusSize; i++)
        {  // Loop through file data

            addToLast = i + ((fileSize / 5) * 4);  // Calculate additional offset
            
            fseek(file, i + addToLast, SEEK_SET);  // Move to current position in file
            fread(fileBuffer, 1, virusSize, file);  // Read file data into buffer

            if (memcmp(fileBuffer, virusBuffer, virusSize) == 0)
            {  // Compare buffers
                found = true;  // Set infection found flag
                break;  // Exit loop
            }
        }
    }
    else if (kind == 2)  // Check if kind is 2
    {
        fileSize = fileSize / 5;  // Adjust file size for partial scan
        for (i = 0; i <= fileSize - virusSize; i++)
        {  // Loop through file data
            fseek(file, i, SEEK_SET);  // Move to current position in file
            fread(fileBuffer, 1, virusSize, file);  // Read file data into buffer

            if (memcmp(fileBuffer, virusBuffer, virusSize) == 0)
            {  // Compare buffers
                found = true;  // Set infection found flag
                break;  // Exit loop
            }
        }
    }

    free(fileBuffer);  // Free file buffer
    free(virusBuffer);  // Free virus buffer
    fclose(file);  // Close the file
    fclose(virus);  // Close the virus file

    return found;  // Return whether infection was found
}
/*
* this function will put the fils names from the dir to the big array
* input: the directory path and the amount of files
* output: a struct kind array with the sorted names
*/
fileStruct* sortFiles(char* directoryPath, int* size)
{
    int i = 0;  // Initialize index for file array
    int j = 0;  // Initialize index for cleanup in case of error
    DIR* directory = NULL;  // Initialize directory pointer
    struct dirent* entry;  // Initialize directory entry pointer
    int count = 0;  // Initialize file count

    directory = opendir(directoryPath);  // Open the directory
    if (directory == NULL)
    {  // Check if directory failed to open
        printf("Error opening directory\n");  // Print error message
        return NULL;  // Return NULL indicating failure
    }

    while ((entry = readdir(directory)) != NULL)
    {  // Read directory entries
        if (entry->d_type == DT_REG)
        {  // Check if entry is a regular file
            count++;  // Increment file count
        }
    }

    rewinddir(directory);  // Reset directory stream to beginning

    fileStruct* array = malloc(count * sizeof(fileStruct));  // Allocate memory for file array
    if (array == NULL)
    {  // Check if memory allocation failed
        printf("Memory allocation failed\n");  // Print error message
        closedir(directory);  // Close the directory
        return NULL;  // Return NULL indicating failure
    }

    while ((entry = readdir(directory)) != NULL)
    {  // Read directory entries again
        if (entry->d_type == DT_REG)
        {  // Check if entry is a regular file
            array[i].filePath = malloc(strlen(directoryPath) + strlen(entry->d_name) + 2);  // Allocate memory for file path
            if (array[i].filePath == NULL)
            {  // Check if memory allocation failed
                printf("Memory allocation failed\n");  // Print error message
                for (j = 0; j < i; j++)
                {  // Loop to free allocated memory
                    free(array[j].filePath);  // Free file path memory
                }
                free(array);  // Free file array memory
                closedir(directory);  // Close the directory
                return NULL;  // Return NULL indicating failure
            }
            sprintf(array[i].filePath, "%s/%s", directoryPath, entry->d_name);  // Concatenate directory path and file name to form file path
            array[i].fileName = malloc(strlen(entry->d_name) + 1);  // Allocate memory for file name
            if (array[i].fileName == NULL)
            {  // Check if memory allocation failed
                printf("Memory allocation failed\n");  // Print error message
                for (j = 0; j < i; j++)
                {  // Loop to free allocated memory
                    free(array[j].filePath);  // Free file path memory
                    free(array[j].fileName);  // Free file name memory
                }
                free(array);  // Free file array memory
                closedir(directory);  // Close the directory
                return NULL;  // Return NULL indicating failure
            }
            strcpy(array[i].fileName, entry->d_name);  // Copy file name to array
            i++;  // Increment file array index
        }
    }

    closedir(directory);  // Close the directory

    sort(array, count);  // Sort the file array
    *size = count;  // Set the size output parameter

    return array;  // Return the file array
}


/*
* this function will sort the files name
* input: the big array and its size
* output: none
*/
void sort(fileStruct* arr, int size)
{
    int i, j;  // Initialize loop variables
    fileStruct temp;  // Temporary variable for swapping

    for (i = 0; i < size - 1; i++) {  // Outer loop for passes
        for (j = 0; j < size - i - 1; j++) {  // Inner loop for comparisons
            if (strcmp(arr[j].fileName, arr[j + 1].fileName) > 0) {  // Compare file names
                temp = arr[j];  // Swap elements
                arr[j] = arr[j + 1];
                arr[j + 1] = temp;
            }
        }
    }
}

/*
* this function will put the file path from the dir to the struct
* input: the big array, its size, the dir path
* output: none
*/

void putValueInStruct(fileStruct* arr, int arrSize, char* dirPath)
{
    for (int i = 0; i < arrSize; i++) {  // Loop through the array
        char filePath[500];  // Buffer to hold file path
        snprintf(filePath, sizeof(filePath), "%s/%s", dirPath, arr[i].fileName);  // Construct file path
        arr[i].filePath = malloc(strlen(filePath) + 1);  // Allocate memory for file path
        if (arr[i].filePath != NULL) {  // Check if memory allocation was successful
            strcpy(arr[i].filePath, filePath);  // Copy file path to structure
        }
    }
}

/*
* this function will show the menu
* input: the folderpath and the virus path
* output: the choice
*/
int showMenu(char* filesPath, char* signPath)
{
    int choice = 0;  // Initialize choice variable
    printf("Welcome to my Virus Scan!\n\n");  // Print welcome message
    printf("Folder to scan: %s\n", filesPath);  // Print folder to scan
    printf("Virus signature: %s\n\n", signPath);  // Print virus signature path
    printf("Press 0 for a normal scan or any other key for a quick scan: \n");  // Prompt user for choice
    scanf("%d", &choice);  // Read user choice
    getchar();  // Consume newline character
    printf("Scanning began...\n");  // Print scanning message
    printf("This process may take several minutes...\n\n");  // Inform user about scanning duration
    return choice;  // Return user choice
}

/*
* function will print the result
* input: the big array, its size, the virus path, the filder path and the file
* output: none
*/
void printResult(fileStruct* arr, int size, char* signPath, char* folder, FILE* logFile)
{
    char* name;  // Variable to hold file name
    printf("Scanning:\n");  // Print scanning message
    for (int i = 0; i < size; i++) {  // Loop through the array of files
        name = arr[i].filePath;  // Get file name
        printf("%s - ", name);  // Print file name
        fprintf(logFile, "%s - ", name);  // Write file name to log file

        if (isInfected(arr[i].filePath, signPath, 1))
        {  // Check if file is infected
            printf("Infected!\n");  // Print infected message
            fprintf(logFile, "Infected!\n");  // Write infected message to log file
        }
        else
        {
            printf("Clean\n");  // Print clean message
            fprintf(logFile, "Clean\n");  // Write clean message to log file
        }
    }
    printf("Scan Completed\n");  // Print scan completed message
    
    printf("See log path for results: %s\n", folderToFile(folder));  // Print log path
}

/*
* function will print the quich result
* input: the big array, its size, the virus path, the filder path and the file
* output: none
*/
void printQuickResult(fileStruct* arr, int size, char* signPath, char* folder, FILE* logFile)
{
    char* name;  // Variable to hold file path
    printf("Scanning:\n");  // Print scanning message
    for (int i = 0; i < size; i++)
    {  // Loop through the array of files
        name = arr[i].filePath;  // Get file path
        printf("%s - ", name);  // Print file path
        fprintf(logFile, "%s - ", name);  // Write file path to log file

        // Check if file is infected (first 20%)
        if (isInfected(arr[i].filePath, signPath, 2))
        {
            printf("Infected! (first 20%)\n");  // Print infected message
            fprintf(logFile, "Infected! (first 20%)\n");  // Write infected message to log file
        }
        // Check if file is infected (last 20%)
        else if (isInfected(arr[i].filePath, signPath, 3))
        {
            printf("Infected! (last 20%)\n");  // Print infected message
            fprintf(logFile, "Infected! (last 20%)\n");  // Write infected message to log file
        }
        // Check if file is infected (full scan)
        else if (isInfected(arr[i].filePath, signPath, 1))
        {
            printf("Infected!\n");  // Print infected message
            fprintf(logFile, "Infected!\n");  // Write infected message to log file
        }
        else
        {
            printf("Clean\n");  // Print clean message
            fprintf(logFile, "Clean\n");  // Write clean message to log file
        }
    }
    printf("Scan Completed\n");  // Print scan completed message
    fprintf(logFile, "Scan Completed!\n");  // Write scan completed message to log file
    printf("See log path for results: %s\n", folderToFile(folder));  // Print log path
}

/*
* function will add the file name to the folder
* input: the folder path
* output: the file path
*/
char* folderToFile(const char* folderPath)
{
    // Calculate the required buffer size
    size_t folderPathLen = strlen(folderPath);
    size_t filePathLen = folderPathLen + strlen(FILE_NAME) + 2; // +1 for possible '/' and +1 for '\0'

    // Allocate memory for the new file path
    char* filePath = malloc(filePathLen);
    if (filePath == NULL) {
        printf("Memory allocation failed\n");
        return NULL;
    }

    // Check if folderPath ends with a '/' and construct the file path accordingly
    if (folderPath[folderPathLen - 1] == '/' || folderPath[folderPathLen - 1] == '\\') {
        snprintf(filePath, filePathLen, "%s%s", folderPath, FILE_NAME);
    }
    else {
        snprintf(filePath, filePathLen, "%s/%s", folderPath, FILE_NAME);
    }

    return filePath;
}

