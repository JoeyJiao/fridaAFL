#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <dirent.h>

int write2stdin(char* buf, ssize_t len) {
	int fd;
  char* path = NULL;

  if (asprintf(&path, "%s/tmp.XXXXXXXXXX", "/data/local/tmp") == -1) {
    return -1;
  }
  fd = mkstemp(path);
  if (fd == -1) {
    free(path);
 	  return -1;
  }

	close(0);
	int newFd = dup(fd);
	if (newFd) {
		printf("error %d: %s\n", errno, strerror(errno));
		return -2;
	}

//	printf("%s: write %ld bytes\n", __func__, len);
	write(0, buf, len);
	fflush(0);

  lseek(0, 0, SEEK_SET);

	return 0;
}

void quit_write2stdin(void) {
  DIR *d = opendir("/data/local/tmp");
  if (d) {
    struct dirent *p;
    while ((p=readdir(d))) {
      if (!strncmp(p->d_name, "tmp.", 4)) {
        char* path = NULL;
        if (asprintf(&path, "/data/local/tmp/%s", p->d_name) == -1) {
          return;
        }
        struct stat statbuf;
        if (!stat(path, &statbuf)) {
          if (S_ISREG(statbuf.st_mode)) {
            unlink(path);
            free(path);
          }
        }
      }
    }
  }
}
