#undef UNICODE
#undef DEBUG
#include <iostream>
#include "pwn.h"
#undef DEBUG
int main(int argc, char** argv, char** envp) {

	Process* p = new Process("cmd.exe");

	std::string bufRecv = p->recvuntil(">");

	p->interactive();

	delete p;

}