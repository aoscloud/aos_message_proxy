#include <stdlib.h>
#include <string.h>

#include "vchanapi.h"

#ifndef MOCKED
#include "vchan.h"
#else
#include "vchan_mock.h"
#endif

int libxenvchan_read_all(struct libxenvchan *ctrl, void *buf, size_t size) {
  int read = 0;

  while (read < size) {
    int ret = libxenvchan_read(ctrl, buf + read, size - read);
    if (ret <= 0) {
      return ret;
    }

    read += ret;
  }

  return size;
}

int libxenvchan_write_all(struct libxenvchan *ctrl, void *buf, size_t size) {
  int written = 0;

  while (written < size) {
    int ret = libxenvchan_write(ctrl, buf + written, size - written);
    if (ret <= 0) {
      return ret;
    }

    written += ret;
  }

  return size;
}
