# aos_message_proxy

Perform core messages redirection form vchan to gRPC

To run tests on vchan, you need to use the following command:

```bash
CGO_ENABLED=1 CGO_CFLAGS="-DMOCKED=1" go test -v -run .
```

The `MOCKED` macro is used to call mocked functions instead of the `libvchan` library. If changes have been made to `.c` or `.h` files, you may need to run `go clean -cache` before building or running the tests.
