/* Test the buffer cache by checking if its hit rate improves */

#include <random.h>
#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

const char* file_name = "cache_test";
char buf[2048];

void test_main(void) {
  int fd;
  random_init(10);
  random_bytes(buf, sizeof buf);

  /* Create file and fill it */
  CHECK(create(file_name, sizeof buf), "create \"%s\"", file_name);
  CHECK((fd = open(file_name)) > 1, "open \"%s\"", file_name);
  random_bytes(buf, sizeof buf);
  CHECK(write(fd, buf, sizeof buf) > 0, "write \"%s\"", file_name);
  msg("close \"%s\"", file_name);
  close(fd);

  /* Reset cache */
  reset_cache();

  /* Read the file with cold cache */
  CHECK((fd = open(file_name)) > 1, "open \"%s\"", file_name);
  for (size_t i = 0; i < sizeof buf; i++) {
    char c;
    read(fd, &c, 1);
    compare_bytes(&c, buf + i, 1, i, file_name);
  }
  close(fd);
  msg("close \"%s\"", file_name);

  /* Calc hit rate for cold read */
  int cold_hits = get_cache_info(0);
  int cold_misses = get_cache_info(1);
  int cold_total = cold_hits + cold_misses;
  int cold_hit_rate = (cold_hits / cold_total) * 100;
  msg("cold hit rate is \"%d\"", cold_hit_rate);

  /* Read the file with hot cache */
  CHECK((fd = open(file_name)) > 1, "open \"%s\"", file_name);
  for (size_t i = 0; i < sizeof buf; i++) {
    char c;
    read(fd, &c, 1);
    compare_bytes(&c, buf + i, 1, i, file_name);
  }
  close(fd);
  msg("close \"%s\"", file_name);

  /* Calc hit rate for hot read */
  int hot_hits = get_cache_info(0);
  int hot_misses = get_cache_info(1);
  int hot_total = hot_hits + hot_misses;
  int hot_hit_rate = ((hot_hits - cold_hits) / (hot_total - cold_total)) * 100;
  msg("hot hit rate is \"%d\"", hot_hit_rate);

  remove(file_name);

  CHECK(hot_hit_rate > cold_hit_rate, "Hot cache hit rate is higher than cold cache hit rate");
}