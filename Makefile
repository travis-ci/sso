.PHONY:
build:
	go build -o sso github.com/travis-ci/sso/cmd/sso

.PHONY: crossbuild
crossbuild:
	GOARCH=amd64 GOOS=darwin go build -o build/darwin/amd64/sso github.com/travis-ci/sso/cmd/sso
	GOARCH=amd64 GOOS=linux go build -o build/linux/amd64/sso github.com/travis-ci/sso/cmd/sso
