#include <limits.h>
#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  /* Create file */
  create("remove.txt", 0);

  /* Open the file and gets file descriptor */
  int fd = open("remove.txt");
  if (fd <= 0) {
    fail("error: open() returned output %d", fd);
  }

  /* Remove the opened file (without error) */
  bool is_removed = remove("remove.txt");
  if (!is_removed) {
    fail("remove() failed on an open file");
  } else {
    msg("remove() correctly returned TRUE");
  }

  /* Check that the opened file cannot be reopened after being removed */
  fd = open("remove.txt");
  if (fd != -1) {
    fail("error: file could be opened after being removed %d", fd);
  } else {
    msg("fd is %d, should be -1", fd);
  }

  /* Second remove should fail */
  bool is_removed_twice = remove("remove.txt");
  if (is_removed_twice) {
    fail("remove() incorrectly succeeded on an already removed file");
  } else {
    msg("remove() correctly returned FALSE");
  }
}