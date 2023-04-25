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
