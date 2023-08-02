#undef UNICODE
#include <iostream>
#define DEBUG
#include "pwn.h"
#define DEBUG
int main(int argc, char** argv, char** envp) {

	Process* p = new Process("cmd.exe");

	std::string bufRecv = p->recvuntil(">");

	p->interactive();

	delete p;

}