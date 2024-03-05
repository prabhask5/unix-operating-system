#include <limits.h>
#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  /* Create file */
  create("test-tell.txt", 0);

  /* Open the file and gets file descriptor */
  int fd = open("test-tell.txt");
  if (fd <= 0) {
    fail("error: open() returned output %d", fd);
  }

  /* Tell what is the current byte: 0 */
  int byte = tell(fd);
  if (byte != 0) {
    fail("error: tell() gave wrong output %d, should be 0", byte);
  }
  msg("tell(fd) = %d", byte);

  /* Seek to the 3rd byte in the file*/
  seek(fd, 3);

  /* Tell what is the current byte: 3 */
  byte = tell(fd);
  if (byte != 3) {
    fail("error: tell() gave wrong output %d, should be 3", byte);
  }
  msg("tell(fd) = %d", byte);
}