/* Grows two files in parallel and checks that their contents are
   correct. */

#include <random.h>
#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

#define FILE_SIZE 512 * 128

const char* file_name = "cache_test";
static char buf[1];

void test_main(void) {
  int read1;
  int read2;
  int write1;
  int write2;
  int fd;
  random_init(10);
  random_bytes(buf, sizeof buf);

  /* Create 64KB file */
  CHECK(create(file_name, FILE_SIZE), "create \"%s\"", file_name);
  CHECK((fd = open(file_name)) > 1, "open \"%s\"", file_name);
  random_bytes(buf, sizeof buf);

  read1 = get_cache_info(2);
  write1 = get_cache_info(3);

  /* Write file */
  for (size_t i = 0; i < FILE_SIZE; i++) {
    write(fd, buf, sizeof buf) > 0, "write \"%s\"", file_name;
  }
  // write(fd, buf, sizeof buf) > 0, "write \"%s\"", file_name;
  msg("close \"%s\"", file_name);
  close(fd);

  read2 = get_cache_info(2);
  write2 = get_cache_info(3);

  /* Read the file byte by byte */
  CHECK((fd = open(file_name)) > 1, "open \"%s\"", file_name);
  for (size_t i = 0; i < FILE_SIZE; i++) {
    char c;
    read(fd, &c, 1);
  }
  close(fd);
  msg("close \"%s\"", file_name);

  CHECK(write2 - write1 <= 128, "coalesces write acceptably");
  close(fd);
  remove(file_name);
}