#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>

char flag[128];
char *stack;

void win()
{
	int f = open("/flag", O_RDONLY);
	read(f, flag, 128);
	puts(flag);
}

int main(int argc, char **argv)
{
    	setvbuf(stdin, NULL, _IONBF, 0);
    	setvbuf(stdout, NULL, _IONBF, 1);
	int x;
	stack = (char *)((unsigned long long)&x & ~0xfff);
	puts("You don't need a stack, do you???");
	while (munmap(stack, 0x1000) == 0) stack += 0x1000;

	win();
}
