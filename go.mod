module github.com/aoscloud/aos_messageproxy

go 1.19

replace github.com/ThalesIgnite/crypto11 => github.com/aoscloud/crypto11 v1.0.3-0.20220217163524-ddd0ace39e6f

require (
	github.com/aoscloud/aos_common v0.0.0-20230309143149-2a708eb7732b
	github.com/cavaliergopher/grab/v3 v3.0.1
	github.com/coreos/go-systemd v0.0.0-20190321100706-95778dfbb74e
	github.com/golang/protobuf v1.5.2
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.0.2
	github.com/sirupsen/logrus v1.9.0
	golang.org/x/mod v0.6.0-dev.0.20220419223038-86c51ed26bb4
	google.golang.org/grpc v1.53.0
	google.golang.org/protobuf v1.28.1
)

require (
	github.com/ThalesIgnite/crypto11 v0.0.0-00010101000000-000000000000 // indirect
	github.com/anexia-it/fsquota v0.1.3 // indirect
	github.com/docker/docker v17.12.1-ce+incompatible // indirect
	github.com/google/go-tpm v0.3.3 // indirect
	github.com/hashicorp/go-version v1.6.0 // indirect
	github.com/miekg/pkcs11 v1.0.3 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/speijnik/go-errortree v1.0.1 // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
	golang.org/x/crypto v0.5.0 // indirect
	golang.org/x/net v0.5.0 // indirect
	golang.org/x/sys v0.4.0 // indirect
	golang.org/x/text v0.6.0 // indirect
	google.golang.org/genproto v0.0.0-20230110181048-76db0878b65f // indirect
)
