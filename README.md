[![CI](https://github.com/aosedge/aos_message_proxy/workflows/CI/badge.svg)](https://github.com/aosedge/aos_message_proxy/actions?query=workflow%3ACI)
[![codecov](https://codecov.io/gh/aosedge/aos_message_proxy/branch/main/graph/badge.svg?token=mZKEdNf2fx)](https://codecov.io/gh/aosedge/aos_message_proxy)

# aos_message_proxy

Perform core messages redirection form vchan to gRPC

To run tests on vchan, or build locally, CI, you need to use the next build tag `-tags=test`

For build, you need to run next following command:

```bash
go build -tags=test .
```

For test, you need to run next following command:

```bash
go test -tags=test -run .
```

For another test or build on yocto you can skip build tag.
