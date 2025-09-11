#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <signal.h>

#include <seccomp.h>

#include <capstone/capstone.h>

#define CAPSTONE_ARCH CS_ARCH_X86
#define CAPSTONE_MODE CS_MODE_64

void print_disassembly(void *shellcode_addr, size_t shellcode_size)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CAPSTONE_ARCH, CAPSTONE_MODE, &handle) != CS_ERR_OK)
    {
        printf("ERROR: disassembler failed to initialize.\n");
        return;
    }

    count = cs_disasm(handle, shellcode_addr, shellcode_size, (uint64_t)shellcode_addr, 0, &insn);
    if (count > 0)
    {
        size_t j;
        printf("      Address      |                      Bytes                    |          Instructions\n");
        printf("------------------------------------------------------------------------------------------\n");

        for (j = 0; j < count; j++)
        {
            printf("0x%016lx | ", (unsigned long)insn[j].address);
            for (int k = 0; k < insn[j].size; k++) printf("%02hhx ", insn[j].bytes[k]);
            for (int k = insn[j].size; k < 15; k++) printf("   ");
            printf(" | %s %s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble shellcode! Bytes are:\n\n");
        printf("      Address      |                      Bytes\n");
        printf("--------------------------------------------------------------------\n");
        for (unsigned int i = 0; i <= shellcode_size; i += 16)
        {
            printf("0x%016lx | ", (unsigned long)shellcode_addr+i);
            for (int k = 0; k < 16; k++) printf("%02hhx ", ((uint8_t*)shellcode_addr)[i+k]);
            printf("\n");
        }
    }

    cs_close(&handle);
}

int main(int argc, char **argv, char **envp)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);
    assert(argc > 1);

    int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);
    if (fd < 0)
        printf("Failed to open the file located at `%s`.\n", argv[1]);
    else
        printf("Successfully opened the file located at `%s`.\n", argv[1]);
    void *fdmap = mmap((void *)0xf146000, 0x1000, PROT_READ, MAP_PRIVATE, fd, 0);
    printf("Mapped 0x1000 bytes of your file at %p!\n", fdmap);
    assert(fdmap);


    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x1337000);
    printf("Mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

    puts("Reading 0x1000 bytes of shellcode from stdin.\n");
    int shellcode_size = read(0, shellcode, 0x1000);

    puts("This challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode, shellcode_size);
    puts("");


    stack_t ss;
    ss.ss_sp = malloc(SIGSTKSZ);
    assert(ss.ss_sp);
    ss.ss_size = SIGSTKSZ;
    ss.ss_flags = 0;
    assert(sigaltstack(&ss, NULL) == 0);

    char *handler = mmap((void *)0x1000000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    handler[0] = '\xeb';
    handler[1] = '\xfe';

    assert(mprotect(handler, 0x1000, PROT_READ|PROT_EXEC) == 0);
    struct sigaction sa;
    sa.sa_flags = SA_ONSTACK;
    sa.sa_handler = (void *)handler;
    sigemptyset(&sa.sa_mask);

    for (int sig = 1; sig < 0x1000; sig++) {
        if (sig != SIGKILL && sig != SIGSTOP) {
            sigaction(sig, &sa, NULL);
        }
    }

    puts("Goodbye, Mr. Anderson.");
    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_ERRNO(ENOSYS));
    assert(seccomp_load(ctx) == 0);
    ((void(*)())shellcode)();
}
