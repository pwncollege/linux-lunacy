#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

int main()
{
	int fd = open("/flag", O_TRUNC|O_WRONLY);
	write(fd, "NO FLAG FOR YOU", 15);
	chmod("/flag", 0644);
}
