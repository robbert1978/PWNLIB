#undef UNICODE
#include <iostream>
#define DEBUG
#include "pwn.h"

int main(int argc, char** argv, char** envp) {

	Process* p = new Process("python.exe -i");

	p->sendline("print('A'*0x10)");

	p->recvuntil("A\r\n");

	p->interactive();

	delete p;

}