#include <limits.h>
#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  /* Create the file */
  create("test-seek.txt", 0);

  /* Open the file descriptor */
  int fd = open("test-seek.txt");
  if (fd <= 0) {
    fail("error: open() returned output %d", fd);
  }

  /* Seek to the 3rd byte in the file, no error */
  seek(fd, 3);
}