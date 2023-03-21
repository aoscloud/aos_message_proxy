#include <openssl/sha.h>

struct libxenvchan {};

static volatile int close_vchan = 0;
static volatile int read_data_ready = 0;

struct {
  uint32_t buff_size;
  void *data;
} buffer;

struct libxenvchan *server_init(int domain, char *xs_path) {
  struct libxenvchan *ctrl = malloc(sizeof(*ctrl));
  if (!ctrl) {
    return NULL;
  }

  buffer.data = NULL;
  close_vchan = 0;
  read_data_ready = 0;

  return ctrl;
}

void libxenvchan_close(struct libxenvchan *ctrl) {
  close_vchan = 1;

  if (buffer.data != NULL) {
    free(buffer.data);
  }

  free(ctrl);
}

int libxenvchan_read(struct libxenvchan *ctrl, void *data, size_t size) {
  static int i = 0;

  while (!close_vchan && !read_data_ready) {
    // busy wait
  }

  if (close_vchan) {
    return -1;
  }

  if (i == 0) {
    i = 1;
    struct VchanMessageHeader header;
    header.dataSize = buffer.buff_size;

    memset(header.sha256, 0, sizeof(header.sha256));

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, buffer.data, buffer.buff_size);
    SHA256_Final(header.sha256, &ctx);

    memcpy(data, &header, sizeof(header));

    return sizeof(header);
  }

  i = 0;

  memcpy(data, buffer.data, buffer.buff_size);

  read_data_ready = 0;

  return buffer.buff_size;
}

int libxenvchan_write(struct libxenvchan *ctrl, void *data, size_t size) {
  static int i = 0;
  static struct VchanMessageHeader header;

  while (!close_vchan && read_data_ready) {
    // busy wait
  }

  if (close_vchan) {
    return -1;
  }

  if (i == 0) {
    i = 1;

    memcpy(&header, data, sizeof(header));
    buffer.data = malloc(header.dataSize);
    buffer.buff_size = header.dataSize;

    return sizeof(struct VchanMessageHeader);
  }

  i = 0;

  uint8_t sha256[32];
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, data, buffer.buff_size);
  SHA256_Final(sha256, &ctx);

  if (memcmp(header.sha256, sha256, sizeof(header.sha256)) != 0) {
    return -1;
  }

  memcpy(buffer.data, data, header.dataSize);

  read_data_ready = 1;

  return header.dataSize;
}
