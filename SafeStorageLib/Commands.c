#include "Commands.h"

typedef struct _GLOBAL_STATE
{
    CRITICAL_SECTION Lock;
    BOOLEAN IsInitialized;
    BOOLEAN IsUserLoggedIn;
    char CurrentUsername[11]; 
    char AppDir[MAX_PATH];
    DWORD LoginAttempts;
    ULONGLONG LastAttemptTime;
} GLOBAL_STATE, *PGLOBAL_STATE;

static GLOBAL_STATE gState = { 0 };

#define MAX_LOGIN_ATTEMPTS 5
#define LOCKOUT_DURATION_MS 60000  
#define MIN_USERNAME_LENGTH 5
#define MAX_USERNAME_LENGTH 10
#define MIN_PASSWORD_LENGTH 5
#define HASH_STRING_LENGTH 65  
#define CHUNK_SIZE 4096 


static NTSTATUS ValidateUsername(const char* Username, uint16_t UsernameLength);
static NTSTATUS ValidatePassword(const char* Password, uint16_t PasswordLength);
static NTSTATUS ValidateSubmissionName(const char* SubmissionName, uint16_t SubmissionNameLength);
static NTSTATUS ValidateFilePath(const char* FilePath, uint16_t FilePathLength);
static NTSTATUS ComputePasswordHash(const char* Password, uint16_t PasswordLength, char* HashBuffer, size_t HashBufferSize);
static NTSTATUS UserExists(const char* Username, uint16_t UsernameLength, BOOLEAN* Exists);
static NTSTATUS CreateUserEntry(const char* Username, uint16_t UsernameLength, const char* PasswordHash);
static NTSTATUS VerifyUserCredentials(const char* Username, uint16_t UsernameLength, const char* Password, uint16_t PasswordLength);
static NTSTATUS CopyFileWithThreadPool(const char* SourcePath, const char* DestPath);


NTSTATUS WINAPI
SafeStorageInit(
    VOID
)
{
    HRESULT hr = S_OK;
    DWORD result = 0;
    char usersDir[MAX_PATH] = { 0 };

    if (gState.IsInitialized)
    {
        return STATUS_SUCCESS;
    }

    InitializeCriticalSection(&gState.Lock);
    
    result = GetCurrentDirectoryA(MAX_PATH, gState.AppDir);
    if (result == 0 || result >= MAX_PATH)
    {
        DeleteCriticalSection(&gState.Lock);
        return STATUS_UNSUCCESSFUL;
    }

    hr = StringCchPrintfA(usersDir, MAX_PATH, "%s\\users", gState.AppDir);
    if (FAILED(hr))
    {
        DeleteCriticalSection(&gState.Lock);
        return STATUS_UNSUCCESSFUL;
    }

    if (!CreateDirectoryA(usersDir, NULL))
    {
        if (GetLastError() != ERROR_ALREADY_EXISTS)
        {
            DeleteCriticalSection(&gState.Lock);
            return STATUS_UNSUCCESSFUL;
        }
    }

    gState.IsInitialized = TRUE;
    gState.IsUserLoggedIn = FALSE;
    gState.LoginAttempts = 0;
    gState.LastAttemptTime = 0;
    memset(gState.CurrentUsername, 0, sizeof(gState.CurrentUsername));

    return STATUS_SUCCESS;
}


VOID WINAPI
SafeStorageDeinit(
    VOID
)
{
    if (!gState.IsInitialized)
    {
        return;
    }

    EnterCriticalSection(&gState.Lock);
    gState.IsUserLoggedIn = FALSE;
    memset(gState.CurrentUsername, 0, sizeof(gState.CurrentUsername));
    gState.IsInitialized = FALSE;
    LeaveCriticalSection(&gState.Lock);
    
    DeleteCriticalSection(&gState.Lock);
}


NTSTATUS WINAPI
SafeStorageHandleRegister(
    const char* Username,
    uint16_t UsernameLength,
    const char* Password,
    uint16_t PasswordLength
)
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN userExists = FALSE;
    char passwordHash[HASH_STRING_LENGTH] = { 0 };
    char userDir[MAX_PATH] = { 0 };
    HRESULT hr = S_OK;

    if (!gState.IsInitialized)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    EnterCriticalSection(&gState.Lock);

    if (gState.IsUserLoggedIn)
    {
        LeaveCriticalSection(&gState.Lock);
        printf("Error: Cannot register while a user is logged in.\r\n");
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = ValidateUsername(Username, UsernameLength);
    if (!NT_SUCCESS(status))
    {
        LeaveCriticalSection(&gState.Lock);
        return status;
    }
    status = ValidatePassword(Password, PasswordLength);
    if (!NT_SUCCESS(status))
    {
        LeaveCriticalSection(&gState.Lock);
        return status;
    }

    status = UserExists(Username, UsernameLength, &userExists);
    if (!NT_SUCCESS(status))
    {
        LeaveCriticalSection(&gState.Lock);
        return status;
    }

    if (userExists)
    {
        LeaveCriticalSection(&gState.Lock);
        printf("Error: User already exists.\r\n");
        return STATUS_USER_EXISTS;
    }

    status = ComputePasswordHash(Password, PasswordLength, passwordHash, sizeof(passwordHash));
    if (!NT_SUCCESS(status))
    {
        LeaveCriticalSection(&gState.Lock);
        return status;
    }

    status = CreateUserEntry(Username, UsernameLength, passwordHash);
    if (!NT_SUCCESS(status))
    {
        LeaveCriticalSection(&gState.Lock);
        return status;
    }

    hr = StringCchPrintfA(userDir, MAX_PATH, "%s\\users\\%.*s", gState.AppDir, UsernameLength, Username);
    if (FAILED(hr))
    {
        LeaveCriticalSection(&gState.Lock);
        return STATUS_UNSUCCESSFUL;
    }

    if (!CreateDirectoryA(userDir, NULL))
    {
        LeaveCriticalSection(&gState.Lock);
        printf("Error: Failed to create user directory.\r\n");
        return STATUS_UNSUCCESSFUL;
    }

    LeaveCriticalSection(&gState.Lock);
    printf("User registered successfully.\r\n");
    return STATUS_SUCCESS;
}


NTSTATUS WINAPI
SafeStorageHandleLogin(
    const char* Username,
    uint16_t UsernameLength,
    const char* Password,
    uint16_t PasswordLength
)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONGLONG currentTime = 0;

    if (!gState.IsInitialized)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    EnterCriticalSection(&gState.Lock);

    if (gState.IsUserLoggedIn)
    {
        LeaveCriticalSection(&gState.Lock);
        printf("Error: A user is already logged in.\r\n");
        return STATUS_INVALID_DEVICE_STATE;
    }

    currentTime = GetTickCount64();
    if (gState.LoginAttempts >= MAX_LOGIN_ATTEMPTS)
    {
        if ((currentTime - gState.LastAttemptTime) < LOCKOUT_DURATION_MS)
        {
            LeaveCriticalSection(&gState.Lock);
            printf("Error: Too many failed login attempts. Please wait.\r\n");
            return STATUS_ACCOUNT_LOCKED_OUT;
        }
        else
        {
            gState.LoginAttempts = 0;
        }
    }

    status = VerifyUserCredentials(Username, UsernameLength, Password, PasswordLength);
    if (!NT_SUCCESS(status))
    {
        gState.LoginAttempts++;
        gState.LastAttemptTime = currentTime;
        LeaveCriticalSection(&gState.Lock);
        printf("Error: Invalid username or password.\r\n");
        return STATUS_LOGON_FAILURE;
    }

    gState.IsUserLoggedIn = TRUE;
    gState.LoginAttempts = 0;
    memcpy_s(gState.CurrentUsername, sizeof(gState.CurrentUsername), Username, UsernameLength);
    gState.CurrentUsername[UsernameLength] = '\0';

    LeaveCriticalSection(&gState.Lock);
    printf("Login successful.\r\n");
    return STATUS_SUCCESS;
}


NTSTATUS WINAPI
SafeStorageHandleLogout(
    VOID
)
{
    if (!gState.IsInitialized)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    EnterCriticalSection(&gState.Lock);

    if (!gState.IsUserLoggedIn)
    {
        LeaveCriticalSection(&gState.Lock);
        printf("Error: No user is currently logged in.\r\n");
        return STATUS_INVALID_DEVICE_STATE;
    }

    gState.IsUserLoggedIn = FALSE;
    memset(gState.CurrentUsername, 0, sizeof(gState.CurrentUsername));

    LeaveCriticalSection(&gState.Lock);
    printf("Logout successful.\r\n");
    return STATUS_SUCCESS;
}


NTSTATUS WINAPI
SafeStorageHandleStore(
    const char* SubmissionName,
    uint16_t SubmissionNameLength,
    const char* SourceFilePath,
    uint16_t SourceFilePathLength
)
{
    NTSTATUS status = STATUS_SUCCESS;
    char destPath[MAX_PATH] = { 0 };
    HRESULT hr = S_OK;

    if (!gState.IsInitialized)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    EnterCriticalSection(&gState.Lock);

    if (!gState.IsUserLoggedIn)
    {
        LeaveCriticalSection(&gState.Lock);
        printf("Error: No user is logged in.\r\n");
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = ValidateSubmissionName(SubmissionName, SubmissionNameLength);
    if (!NT_SUCCESS(status))
    {
        LeaveCriticalSection(&gState.Lock);
        return status;
    }

    status = ValidateFilePath(SourceFilePath, SourceFilePathLength);
    if (!NT_SUCCESS(status))
    {
        LeaveCriticalSection(&gState.Lock);
        return status;
    }

    if (GetFileAttributesA(SourceFilePath) == INVALID_FILE_ATTRIBUTES)
    {
        LeaveCriticalSection(&gState.Lock);
        printf("Error: Source file does not exist.\r\n");
        return STATUS_NO_SUCH_FILE;
    }

    hr = StringCchPrintfA(destPath, MAX_PATH, "%s\\users\\%s\\%.*s", 
                          gState.AppDir, gState.CurrentUsername, 
                          SubmissionNameLength, SubmissionName);
    if (FAILED(hr))
    {
        LeaveCriticalSection(&gState.Lock);
        return STATUS_UNSUCCESSFUL;
    }

    LeaveCriticalSection(&gState.Lock);

    status = CopyFileWithThreadPool(SourceFilePath, destPath);
    if (!NT_SUCCESS(status))
    {
        printf("Error: Failed to store file.\r\n");
        return status;
    }

    printf("File stored successfully.\r\n");
    return STATUS_SUCCESS;
}


NTSTATUS WINAPI
SafeStorageHandleRetrieve(
    const char* SubmissionName,
    uint16_t SubmissionNameLength,
    const char* DestinationFilePath,
    uint16_t DestinationFilePathLength
)
{
    NTSTATUS status = STATUS_SUCCESS;
    char sourcePath[MAX_PATH] = { 0 };
    HRESULT hr = S_OK;

    if (!gState.IsInitialized)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    EnterCriticalSection(&gState.Lock);

    if (!gState.IsUserLoggedIn)
    {
        LeaveCriticalSection(&gState.Lock);
        printf("Error: No user is logged in.\r\n");
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = ValidateSubmissionName(SubmissionName, SubmissionNameLength);
    if (!NT_SUCCESS(status))
    {
        LeaveCriticalSection(&gState.Lock);
        return status;
    }

    status = ValidateFilePath(DestinationFilePath, DestinationFilePathLength);
    if (!NT_SUCCESS(status))
    {
        LeaveCriticalSection(&gState.Lock);
        return status;
    }

    hr = StringCchPrintfA(sourcePath, MAX_PATH, "%s\\users\\%s\\%.*s", 
                          gState.AppDir, gState.CurrentUsername, 
                          SubmissionNameLength, SubmissionName);
    if (FAILED(hr))
    {
        LeaveCriticalSection(&gState.Lock);
        return STATUS_UNSUCCESSFUL;
    }

    if (GetFileAttributesA(sourcePath) == INVALID_FILE_ATTRIBUTES)
    {
        LeaveCriticalSection(&gState.Lock);
        printf("Error: Submission file does not exist.\r\n");
        return STATUS_NO_SUCH_FILE;
    }

    LeaveCriticalSection(&gState.Lock);

    status = CopyFileWithThreadPool(sourcePath, DestinationFilePath);
    if (!NT_SUCCESS(status))
    {
        printf("Error: Failed to retrieve file.\r\n");
        return status;
    }

    printf("File retrieved successfully.\r\n");
    return STATUS_SUCCESS;
}


static NTSTATUS
ValidateUsername(
    const char* Username,
    uint16_t UsernameLength
)
{
    uint16_t i = 0;

    if (Username == NULL)
    {
        printf("Error: Username is NULL.\r\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (UsernameLength < MIN_USERNAME_LENGTH || UsernameLength > MAX_USERNAME_LENGTH)
    {
        printf("Error: Username must be between %d and %d characters.\r\n", 
               MIN_USERNAME_LENGTH, MAX_USERNAME_LENGTH);
        return STATUS_INVALID_PARAMETER;
    }

    for (i = 0; i < UsernameLength; i++)
    {
        if (!((Username[i] >= 'a' && Username[i] <= 'z') || 
              (Username[i] >= 'A' && Username[i] <= 'Z')))
        {
            printf("Error: Username must contain only English alphabet letters (a-zA-Z).\r\n");
            return STATUS_INVALID_PARAMETER;
        }
    }

    return STATUS_SUCCESS;
}


static NTSTATUS
ValidatePassword(
    const char* Password,
    uint16_t PasswordLength
)
{
    uint16_t i = 0;
    BOOLEAN hasDigit = FALSE;
    BOOLEAN hasLower = FALSE;
    BOOLEAN hasUpper = FALSE;
    BOOLEAN hasSpecial = FALSE;
    const char specialChars[] = "!@#$%^&";

    if (Password == NULL)
    {
        printf("Error: Password is NULL.\r\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (PasswordLength < MIN_PASSWORD_LENGTH)
    {
        printf("Error: Password must be at least %d characters long.\r\n", MIN_PASSWORD_LENGTH);
        return STATUS_INVALID_PARAMETER;
    }

    for (i = 0; i < PasswordLength; i++)
    {
        if (Password[i] >= '0' && Password[i] <= '9')
        {
            hasDigit = TRUE;
        }
        else if (Password[i] >= 'a' && Password[i] <= 'z')
        {
            hasLower = TRUE;
        }
        else if (Password[i] >= 'A' && Password[i] <= 'Z')
        {
            hasUpper = TRUE;
        }
        else if (strchr(specialChars, Password[i]) != NULL)
        {
            hasSpecial = TRUE;
        }
    }

    if (!hasDigit)
    {
        printf("Error: Password must contain at least one digit.\r\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (!hasLower)
    {
        printf("Error: Password must contain at least one lowercase letter.\r\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (!hasUpper)
    {
        printf("Error: Password must contain at least one uppercase letter.\r\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (!hasSpecial)
    {
        printf("Error: Password must contain at least one special character (!@#$%%^&).\r\n");
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}


static NTSTATUS
ValidateSubmissionName(
    const char* SubmissionName,
    uint16_t SubmissionNameLength
)
{
    uint16_t i = 0;

    if (SubmissionName == NULL)
    {
        printf("Error: Submission name is NULL.\r\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (SubmissionNameLength == 0 || SubmissionNameLength >= MAX_PATH)
    {
        printf("Error: Submission name length is invalid.\r\n");
        return STATUS_INVALID_PARAMETER;
    }

    for (i = 0; i < SubmissionNameLength; i++)
    {
        char c = SubmissionName[i];

        if (c == '\\' || c == '/' || c == ':' || c == '*' || 
            c == '?' || c == '"' || c == '<' || c == '>' || 
            c == '|' || c == '\0')
        {
            printf("Error: Submission name contains invalid characters (\\/:*?\"<>|).\r\n");
            return STATUS_INVALID_PARAMETER;
        }

        if (c < 32 || c == 127)
        {
            printf("Error: Submission name contains control characters.\r\n");
            return STATUS_INVALID_PARAMETER;
        }
    }

    if (SubmissionNameLength >= 2)
    {
        if (SubmissionName[0] == '.' && SubmissionName[1] == '.')
        {
            printf("Error: Submission name cannot start with '..'.\r\n");
            return STATUS_INVALID_PARAMETER;
        }
    }

    if (SubmissionName[0] == '.')
    {
        printf("Error: Submission name cannot start with '.'.\r\n");
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}


static NTSTATUS
ValidateFilePath(
    const char* FilePath,
    uint16_t FilePathLength
)
{
    uint16_t i = 0;
    BOOLEAN hasNullTerminator = FALSE;

    if (FilePath == NULL)
    {
        printf("Error: File path is NULL.\r\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (FilePathLength == 0 || FilePathLength >= MAX_PATH)
    {
        printf("Error: File path length is invalid.\r\n");
        return STATUS_INVALID_PARAMETER;
    }

    for (i = 0; i < FilePathLength; i++)
    {
        if (FilePath[i] == '\0')
        {
            hasNullTerminator = TRUE;
            break;
        }
    }

    if (!hasNullTerminator && FilePathLength < MAX_PATH)
    {
        if (FilePath[FilePathLength] != '\0')
        {
            printf("Error: File path is not null-terminated.\r\n");
            return STATUS_INVALID_PARAMETER;
        }
    }

    for (i = 0; i < FilePathLength && FilePath[i] != '\0'; i++)
    {
        char c = FilePath[i];

        if (c < 32 && c != '\0')
        {
            printf("Error: File path contains control characters.\r\n");
            return STATUS_INVALID_PARAMETER;
        }
    }

    return STATUS_SUCCESS;
}


static NTSTATUS
ComputePasswordHash(
    const char* Password,
    uint16_t PasswordLength,
    char* HashBuffer,
    size_t HashBufferSize
)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    DWORD hashLength = 0;
    DWORD resultLength = 0;
    BYTE hash[32] = { 0 }; 
    DWORD i = 0;

    if (HashBuffer == NULL || HashBufferSize < HASH_STRING_LENGTH)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&hashLength, sizeof(hashLength), &resultLength, 0);
    if (!NT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return status;
    }

    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return status;
    }

    status = BCryptHashData(hHash, (PBYTE)Password, PasswordLength, 0);
    if (!NT_SUCCESS(status))
    {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return status;
    }

    status = BCryptFinishHash(hHash, hash, hashLength, 0);
    if (!NT_SUCCESS(status))
    {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return status;
    }

    for (i = 0; i < hashLength; i++)
    {
        sprintf_s(&HashBuffer[i * 2], HashBufferSize - (i * 2), "%02x", hash[i]);
    }
    HashBuffer[hashLength * 2] = '\0';

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return STATUS_SUCCESS;
}


static NTSTATUS
UserExists(
    const char* Username,
    uint16_t UsernameLength,
    BOOLEAN* Exists
)
{
    char usersFile[MAX_PATH] = { 0 };
    FILE* file = NULL;
    char line[512] = { 0 };
    HRESULT hr = S_OK;
    errno_t err = 0;

    if (Exists == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    *Exists = FALSE;

    hr = StringCchPrintfA(usersFile, MAX_PATH, "%s\\users.txt", gState.AppDir);
    if (FAILED(hr))
    {
        return STATUS_UNSUCCESSFUL;
    }

    err = fopen_s(&file, usersFile, "r");
    if (err != 0 || file == NULL)
    {
        return STATUS_SUCCESS;
    }

    while (fgets(line, sizeof(line), file) != NULL)
    {
        char* separator = strchr(line, ':');
        if (separator != NULL)
        {
            size_t usernameInFileLength = (size_t)(separator - line);
            if (usernameInFileLength == UsernameLength &&
                memcmp(line, Username, UsernameLength) == 0)
            {
                *Exists = TRUE;
                break;
            }
        }
    }

    fclose(file);
    return STATUS_SUCCESS;
}


static NTSTATUS
CreateUserEntry(
    const char* Username,
    uint16_t UsernameLength,
    const char* PasswordHash
)
{
    char usersFile[MAX_PATH] = { 0 };
    FILE* file = NULL;
    HRESULT hr = S_OK;
    errno_t err = 0;

    hr = StringCchPrintfA(usersFile, MAX_PATH, "%s\\users.txt", gState.AppDir);
    if (FAILED(hr))
    {
        return STATUS_UNSUCCESSFUL;
    }

    err = fopen_s(&file, usersFile, "a");
    if (err != 0 || file == NULL)
    {
        printf("Error: Failed to open users.txt file.\r\n");
        return STATUS_UNSUCCESSFUL;
    }

    fprintf(file, "%.*s:%s\n", UsernameLength, Username, PasswordHash);
    fclose(file);

    return STATUS_SUCCESS;
}


static NTSTATUS
VerifyUserCredentials(
    const char* Username,
    uint16_t UsernameLength,
    const char* Password,
    uint16_t PasswordLength
)
{
    char usersFile[MAX_PATH] = { 0 };
    FILE* file = NULL;
    char line[512] = { 0 };
    char computedHash[HASH_STRING_LENGTH] = { 0 };
    NTSTATUS status = STATUS_SUCCESS;
    HRESULT hr = S_OK;
    errno_t err = 0;
    BOOLEAN found = FALSE;

    hr = StringCchPrintfA(usersFile, MAX_PATH, "%s\\users.txt", gState.AppDir);
    if (FAILED(hr))
    {
        return STATUS_UNSUCCESSFUL;
    }

    err = fopen_s(&file, usersFile, "r");
    if (err != 0 || file == NULL)
    {
        return STATUS_NO_SUCH_USER;
    }

    status = ComputePasswordHash(Password, PasswordLength, computedHash, sizeof(computedHash));
    if (!NT_SUCCESS(status))
    {
        fclose(file);
        return status;
    }

    while (fgets(line, sizeof(line), file) != NULL)
    {
        char* separator = strchr(line, ':');
        if (separator != NULL)
        {
            size_t usernameInFileLength = (size_t)(separator - line);
            if (usernameInFileLength == UsernameLength &&
                memcmp(line, Username, UsernameLength) == 0)
            {
                char* storedHash = separator + 1;
                size_t storedHashLen = strlen(storedHash);
         
                if (storedHashLen > 0 && storedHash[storedHashLen - 1] == '\n')
                {
                    storedHash[storedHashLen - 1] = '\0';
                    storedHashLen--;
                }

                if (strcmp(computedHash, storedHash) == 0)
                {
                    found = TRUE;
                }
                break;
            }
        }
    }

    fclose(file);

    return found ? STATUS_SUCCESS : STATUS_LOGON_FAILURE;
}


typedef struct _FILE_COPY_CONTEXT
{
    HANDLE SourceHandle;
    HANDLE DestHandle;
    LARGE_INTEGER FileSize;
    LARGE_INTEGER BytesCopied;
    CRITICAL_SECTION Lock;
    NTSTATUS Status;
} FILE_COPY_CONTEXT, *PFILE_COPY_CONTEXT;


static DWORD WINAPI
CopyChunkWorker(
    LPVOID Parameter
)
{
    PFILE_COPY_CONTEXT context = (PFILE_COPY_CONTEXT)Parameter;
    BYTE buffer[CHUNK_SIZE] = { 0 };
    DWORD bytesRead = 0;
    DWORD bytesWritten = 0;
    LARGE_INTEGER offset = { 0 };
    OVERLAPPED readOverlapped = { 0 };
    OVERLAPPED writeOverlapped = { 0 };
    HANDLE readEvent = NULL;
    HANDLE writeEvent = NULL;

    readEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    writeEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    
    if (readEvent == NULL || writeEvent == NULL)
    {
        if (readEvent != NULL) CloseHandle(readEvent);
        if (writeEvent != NULL) CloseHandle(writeEvent);
        EnterCriticalSection(&context->Lock);
        context->Status = STATUS_UNSUCCESSFUL;
        LeaveCriticalSection(&context->Lock);
        return 1;
    }

    while (TRUE)
    {
        EnterCriticalSection(&context->Lock);
        
        if (context->BytesCopied.QuadPart >= context->FileSize.QuadPart)
        {
            LeaveCriticalSection(&context->Lock);
            break;
        }

        offset.QuadPart = context->BytesCopied.QuadPart;
        context->BytesCopied.QuadPart += CHUNK_SIZE;
        
        LeaveCriticalSection(&context->Lock);

        memset(&readOverlapped, 0, sizeof(readOverlapped));
        readOverlapped.Offset = offset.LowPart;
        readOverlapped.OffsetHigh = offset.HighPart;
        readOverlapped.hEvent = readEvent;
        ResetEvent(readEvent);

        if (!ReadFile(context->SourceHandle, buffer, CHUNK_SIZE, &bytesRead, &readOverlapped))
        {
            DWORD error = GetLastError();
            if (error == ERROR_IO_PENDING)
            {
                if (!GetOverlappedResult(context->SourceHandle, &readOverlapped, &bytesRead, TRUE))
                {
                    error = GetLastError();
                    if (error != ERROR_HANDLE_EOF)
                    {
                        EnterCriticalSection(&context->Lock);
                        context->Status = STATUS_UNSUCCESSFUL;
                        LeaveCriticalSection(&context->Lock);
                        break;
                    }
                }
            }
            else if (error != ERROR_HANDLE_EOF)
            {
                EnterCriticalSection(&context->Lock);
                context->Status = STATUS_UNSUCCESSFUL;
                LeaveCriticalSection(&context->Lock);
                break;
            }
        }

        if (bytesRead == 0)
        {
            break;
        }

        memset(&writeOverlapped, 0, sizeof(writeOverlapped));
        writeOverlapped.Offset = offset.LowPart;
        writeOverlapped.OffsetHigh = offset.HighPart;
        writeOverlapped.hEvent = writeEvent;
        ResetEvent(writeEvent);

        if (!WriteFile(context->DestHandle, buffer, bytesRead, &bytesWritten, &writeOverlapped))
        {
            DWORD error = GetLastError();
            if (error == ERROR_IO_PENDING)
            {
                if (!GetOverlappedResult(context->DestHandle, &writeOverlapped, &bytesWritten, TRUE))
                {
                    EnterCriticalSection(&context->Lock);
                    context->Status = STATUS_UNSUCCESSFUL;
                    LeaveCriticalSection(&context->Lock);
                    break;
                }
            }
            else
            {
                EnterCriticalSection(&context->Lock);
                context->Status = STATUS_UNSUCCESSFUL;
                LeaveCriticalSection(&context->Lock);
                break;
            }
        }
    }

    CloseHandle(readEvent);
    CloseHandle(writeEvent);
    return 0;
}


static NTSTATUS
CopyFileWithThreadPool(
    const char* SourcePath,
    const char* DestPath
)
{
    FILE_COPY_CONTEXT context = { 0 };
    HANDLE threads[4] = { 0 };
    DWORD threadIds[4] = { 0 };
    DWORD threadCount = 0;
    DWORD i = 0;
    NTSTATUS status = STATUS_SUCCESS;

    context.SourceHandle = CreateFileA(SourcePath, GENERIC_READ, FILE_SHARE_READ, NULL,
                                       OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if (context.SourceHandle == INVALID_HANDLE_VALUE)
    {
        return STATUS_NO_SUCH_FILE;
    }

    if (!GetFileSizeEx(context.SourceHandle, &context.FileSize))
    {
        CloseHandle(context.SourceHandle);
        return STATUS_UNSUCCESSFUL;
    }

    context.DestHandle = CreateFileA(DestPath, GENERIC_WRITE, 0, NULL,
                                     CREATE_ALWAYS, FILE_FLAG_OVERLAPPED, NULL);
    if (context.DestHandle == INVALID_HANDLE_VALUE)
    {
        CloseHandle(context.SourceHandle);
        return STATUS_UNSUCCESSFUL;
    }

    InitializeCriticalSection(&context.Lock);
    context.BytesCopied.QuadPart = 0;
    context.Status = STATUS_SUCCESS;

    if (context.FileSize.QuadPart < (64 * 1024))  
    {
        threadCount = 1;
    }
    else if (context.FileSize.QuadPart < (1024 * 1024)) 
    {
        threadCount = 2;
    }
    else
    {
        threadCount = 4;
    }

    for (i = 0; i < threadCount; i++)
    {
        threads[i] = CreateThread(NULL, 0, CopyChunkWorker, &context, 0, &threadIds[i]);
        if (threads[i] == NULL)
        {
            threadCount = i;
            break;
        }
    }

    if (threadCount > 0)
    {
        WaitForMultipleObjects(threadCount, threads, TRUE, INFINITE);
    }

    for (i = 0; i < threadCount; i++)
    {
        if (threads[i] != NULL)
        {
            CloseHandle(threads[i]);
        }
    }

    status = context.Status;

    if (NT_SUCCESS(status))
    {
        if (SetFilePointerEx(context.DestHandle, context.FileSize, NULL, FILE_BEGIN))
        {
            SetEndOfFile(context.DestHandle);
        }
    }

    DeleteCriticalSection(&context.Lock);
    CloseHandle(context.DestHandle);
    CloseHandle(context.SourceHandle);

    return status;
}
