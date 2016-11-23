.PHONY:
build: bindata.go
	go build -o sso github.com/travis-ci/sso/cmd/sso

.PHONY: crossbuild
crossbuild: bindata.go
	GOARCH=amd64 GOOS=darwin go build -o build/darwin/amd64/sso github.com/travis-ci/sso/cmd/sso
	GOARCH=amd64 GOOS=linux go build -o build/linux/amd64/sso github.com/travis-ci/sso/cmd/sso

.PHONY: bindata.go
bindata.go:
	go get -u github.com/jteeuwen/go-bindata/...
	go-bindata -pkg sso static template

.PHONY: github-release
github-release: crossbuild
	bundle install
	bundle exec ruby github-release.rb
