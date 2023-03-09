#include <libxenvchan.h>

struct libxenvchan *server_init(int domain, char *xs_path) {
  struct libxenvchan *ctrl = libxenvchan_server_init(NULL, domain, xs_path, 0, 0);
  if (ctrl == NULL) {
    return NULL;
  }

  ctrl->blocking = 1;

  return ctrl;
}
