#undef UNICODE
#include <Windows.h>
#include <cstdio>
#include <cstdint>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>

#define DEBUGGER "windbgx" // DEBUGGER PATH

#define log(msg, ...)       fprintf(stderr, msg "\n", ##__VA_ARGS__)

#define logOK(msg, ...)     fprintf(stderr,"[+] " msg "\n", ##__VA_ARGS__)

#define logInfo(msg, ...)   fprintf(stderr,"[*] " msg "\n", ##__VA_ARGS__)

#define logWarn(msg, ...)   fprintf(stderr,"[!] " msg "\n", ##__VA_ARGS__)

#define logErr(msg, ...)    fprintf(stderr,"[-] " msg "\n", ##__VA_ARGS__)

// Pack 16-bit integer to 2-byte std::string
std::string p16(uint16_t x) {
    std::string ret;
    for (uint32_t i = 0; i < sizeof(x); ++i)
        ret += ((char*)&x)[i];
    return ret;
}

// Pack 32-bit integer to 4-byte std::string
std::string p32(uint32_t x) {
    std::string ret;
    for (uint32_t i = 0; i < sizeof(x); ++i)
        ret += ((char*)&x)[i];
    return ret;
}

// Pack 64-bit integer to 8-byte std::string
std::string p64(uint64_t x) {
    std::string ret;
    for (uint32_t i = 0; i < sizeof(x); ++i)
        ret += ((char*)&x)[i];
    return ret;
}


// Hexdump: dump hex to a stringstream.
std::stringstream do_hexdump(const char* data, const size_t sz)
{
    std::stringstream os;
    char ascii[17] = { 0 };
    const uint32_t size = sz & 0xffffffff;

    for (uint32_t i = 0; i < size; ++i)
    {
        auto const c = data[i];

        if (ascii[0] == 0u)
        {
            os << "[HEXDUMP] " << std::setfill('0') << std::setw(4) << std::noshowbase << std::hex << (int)i << "   ";
        }

        os << std::setfill('0') << std::setw(2) << std::uppercase << std::noshowbase << std::hex << (int)c
            << " ";
        ascii[i % 16] = (c >= 0x20 && c <= 0x7e) ? c : '.';

        if ((i + 1) % 8 == 0 || i + 1 == size)
        {
            os << " ";
            if ((i + 1) % 16 == 0)
            {
                os << "|  " << ascii << std::endl;
                ::memset(ascii, 0, sizeof(ascii));
            }
            else if (i + 1 == size)
            {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8)
                {
                    os << " ";
                }
                for (uint32_t j = (i + 1) % 16; j < 16; ++j)
                {
                    os << "   ";
                }
                os << "|  " << ascii << std::endl;
            }
        }
    }

    return os;
}


class Process {
private:
    char* CommandLine;
    HANDLE hRead_inPipe, hWrite_inPipe; // Handle child's stdin
    HANDLE hRead_outPipe, hWrite_outPipe; // Handle child's stdout
    DWORD dwRead, dwWritten; // number of bytes for read/write
    SECURITY_ATTRIBUTES sa;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
public:
    // Create new process via command-line cmd
    Process(const char* cmd) {
        CommandLine = _strdup(cmd);

        if (CommandLine == NULL) {
            logErr("Can't allocate memory!");
            exit(-1);
        }

        dwRead = -1; // init value
        dwWritten = -1; // init value

        // Set up security attributes for the pipes
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.bInheritHandle = TRUE;
        sa.lpSecurityDescriptor = NULL;

        // Create the pipes
        if (!CreatePipe(&hRead_inPipe, &hWrite_inPipe, &sa, 0)) {
            fprintf(stderr, "Error creating inPipe\n");
            exit(-1);
        }

        if (!CreatePipe(&hRead_outPipe, &hWrite_outPipe, &sa, 0)) {
            fprintf(stderr, "Error creating outPipe\n");
            exit(-1);
        }
        // Set up STARTUPINFO for the child process
        ZeroMemory(&si, sizeof(STARTUPINFO));
        si.cb = sizeof(STARTUPINFO);
        si.hStdInput = hRead_inPipe;
        si.hStdOutput = hWrite_outPipe;
        si.dwFlags |= STARTF_USESTDHANDLES;

        // Create the child process
        if (!CreateProcess(NULL, CommandLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
            fprintf(stderr, "Error creating child process\n");
            exit(-1);
        }
        logOK("Process started! PID: %ld with Handle: %p", pi.dwProcessId, pi.hProcess);
#ifdef DEBUG
        logInfo("TID: %ld with Handle %p", pi.dwThreadId, pi.hThread);
#endif
    }
    ~Process() {
        free(CommandLine);
        CommandLine = NULL;
        CloseHandle(hRead_inPipe);
        CloseHandle(hWrite_inPipe);
        CloseHandle(hRead_outPipe);
        CloseHandle(hWrite_outPipe);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
#ifdef DEBUG
        logInfo("Closed process %ld.", pi.dwProcessId);
#endif
    }

    // PID of the process
    DWORD PID() {
        return pi.dwProcessId;
    }
    // TID of the process
    DWORD TID() {
        return pi.dwThreadId;
    }

    //This method does not send the NULL byte. Use std::vector<char> or std::string if you want to do that.
    void send(const char* buf) {

        if (strlen(buf) > 0xffffffff) {
            logErr("Buffer too long!");
            exit(-1);
        }

        if (!WriteFile(hWrite_inPipe, buf, (DWORD)strlen(buf) , &dwWritten, NULL)) {
            fprintf(stderr, "Error writing to pipe\n");
            exit(-1);
        }
#ifdef DEBUG
        logInfo("Sent %u byte(s)", dwWritten);
        log("%s", do_hexdump(buf, strlen(buf)).str().c_str());
#endif
    }
    // Send any bytes you want.
    void send(const std::vector<char>& buf) {

        if (buf.size() > 0xffffffff) {
            logErr("Buffer too long!");
            exit(-1);
        }

        if (!WriteFile(hWrite_inPipe, buf.data(), (DWORD)buf.size(), &dwWritten, NULL)) {
            fprintf(stderr, "Error writing to pipe\n");
            exit(-1);
        }
#ifdef DEBUG
        logInfo("Sent %u byte(s)", dwWritten);
        log("%s", do_hexdump(buf.data(), buf.size()).str().c_str() );
#endif
    }
    // Send any bytes you want.
    void send(const std::string& buf) {

        if (buf.length() > 0xffffffff) {
            logWarn("Buffer too long! Sending first 4294967295 bytes of the buffer.");
        }


        if (!WriteFile(hWrite_inPipe, buf.c_str(), (DWORD)buf.length(), &dwWritten, NULL)) {
            fprintf(stderr, "Error writing to pipe\n");
            exit(-1);
        }
#ifdef DEBUG
        logInfo("Sent %u byte(s)", dwWritten);
        log("%s", do_hexdump(buf.c_str(), buf.length()).str().c_str());
#endif      
    }

    //This method does not send the NULL byte. Use std::vector<char> or std::string if you want to do that.
    void sendline(const char* buf) {
        
        char* buf2send = (char*)malloc(strlen(buf) + 2); // buf + newline + null

        if (buf2send == NULL) {
            logErr("Can't allocate memory!");
            exit(-1);
        }

        sprintf_s(buf2send, strlen(buf) + 2, "%s\n", buf);

        send(buf2send);

        free(buf2send);
    }
    // Send any bytes you want.
    void sendline(const std::vector<char>& buf) {
        std::vector<char> buf2send = buf;
        buf2send.push_back('\n');

        if (buf2send.size() > 0xffffffff) {
            logWarn("Buffer too long! Sending first 4294967295 bytes of the buffer.");
        }

        if (!WriteFile(hWrite_inPipe, buf2send.data(), (DWORD)buf2send.size(), &dwWritten, NULL)) {
            fprintf(stderr, "Error writing to pipe\n");
            exit(-1);
        }
#ifdef DEBUG
        logInfo("Sent %u byte(s)", dwWritten);
        log("%s", do_hexdump(buf2send.data(), buf2send.size()).str().c_str());

#endif
    }
    // Send any bytes you want.
    void sendline(const std::string& buf) {
        std::string buf2send = buf;
        buf2send += '\n';

        if (buf2send.length() > 0xffffffff) {
            logWarn("Buffer too long! Sending first 4294967295 bytes of the buffer.");
        }

        if (!WriteFile(hWrite_inPipe, buf2send.c_str(), (DWORD)buf2send.length(), &dwWritten, NULL)) {
            fprintf(stderr, "Error writing to pipe\n");
            exit(-1);
        }
#ifdef DEBUG
        logInfo("Sent %u byte(s)", dwWritten);
        log("%s", do_hexdump(buf2send.c_str(), buf2send.length()).str().c_str());
#endif    
    }

    std::string recv(size_t size = 0x1000) {

        char* buf = (char*)malloc(size);

        if (buf == NULL) {
            logErr("Can't allocate memory!");
            exit(-1);
        }

        ZeroMemory(buf, size);

        if (size > 0xffffffff) {
            logWarn("Buffer too long! Sending first 4294967295 bytes of the buffer.");
        }

        if (!ReadFile(hRead_outPipe, buf, (DWORD)size , &dwRead, NULL)) {
            fprintf(stderr, "Error reading from pipe\n");
            exit(-1);
        }
        std::string ret(buf, dwRead);
        free(buf);
#ifdef DEBUG
        logInfo("Read %zu byte(s).", ret.length());
        log("%s", do_hexdump(ret.c_str(), ret.length()).str().c_str());
#endif
        return ret;
    }

    std::string recvuntil(const char* pattern, size_t size = 0x1000) {
        if (strlen(pattern) > size)
            size = strlen(pattern) + 0x1000;

        char* buf = (char*)malloc(size);
        char* pTmp = NULL; // Temp variable for realloc

        if (buf == NULL) {
            logErr("Can't allocate memory!");
            exit(-1);
        }

        uint64_t offset = 0;
        ZeroMemory(buf, size);
        
        while ((strstr(buf, pattern) == NULL)) {

            if (offset >= size) {
                size += 0x1000;

                pTmp = (char *)realloc(buf, size);

                if (pTmp == NULL) {
                    logErr("Can't allocate memory!");
                    exit(-1);
                }
                buf = pTmp;
                ZeroMemory(buf + offset, 0x1000);
            }
            if (!ReadFile(hRead_outPipe, buf + offset, 1, &dwRead, NULL)) {
                fprintf(stderr, "Error reading from pipe.\n");
                exit(-1);
            }
            ++offset;
        }
        std::string ret(buf, offset);
        free(buf);
#ifdef DEBUG
        logInfo("Read %zu byte(s).", ret.length());
        log("%s", do_hexdump(ret.c_str(), ret.length()).str().c_str());
#endif
        return ret;
    }

    void sendafter(const char* pattern, const char* buf2send) {
        std::string recv_buf = recvuntil(pattern);
        send(buf2send);
    }

    void sendlineafter(const char* pattern, const char* buf2send) {
        std::string recv_buf = recvuntil(pattern);
        sendline(buf2send);
    }

    void sendafter(const char* pattern, const std::vector<char>& buf2send) {
        std::string recv_buf = recvuntil(pattern);
        send(buf2send);
    }

    void sendlineafter(const char* pattern, const std::vector<char>& buf2send) {
        std::string recv_buf = recvuntil(pattern);
        sendline(buf2send);
    }

    void sendafter(const char* pattern, const std::string& buf2send) {
        std::string recv_buf = recvuntil(pattern);
        send(buf2send);
    }

    void sendlineafter(const char* pattern, const std::string& buf2send) {
        std::string recv_buf = recvuntil(pattern);
        sendline(buf2send);
    }

    //Todo: interactive()
    void interactive() {
        return;
    }

};

// Attach a process to debugger
void debugAttach(Process* p, const char* windbg_script = "") {
    const size_t MAX_LEN = sizeof(DEBUGGER) + strlen(windbg_script) + 0x30;
    char* cmd = (char*)calloc(1, MAX_LEN);

    if (cmd == NULL) {
        logErr("Can't allocate memory!");
        exit(-1);
    }

    sprintf_s(cmd, MAX_LEN, "%s -p %u -c \"%s\"", DEBUGGER, p->PID(), windbg_script);

    logInfo("Attaching %u process to debugger!", p->PID());

    system(cmd);

    free(cmd);
}