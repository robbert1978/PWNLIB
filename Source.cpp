#undef UNICODE
#include <iostream>
#define DEBUG
#include "pwn.h"
#define DEBUG
int main(int argc, char** argv, char** envp) {

	Process* p = new Process("cmd.exe");

	std::string bufRecv = p->recvuntil("reserved.",strlen("reserved."));

	std::cout << bufRecv << std::endl;

	p->sendline("DIR C:\\Users");

	Sleep(2);

	std::cout << p->recv() << std::endl;

	delete p;

}