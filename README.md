# sso

This project is a port of [travis-sso](https://github.com/travis-ci/travis-sso) from ruby to go.

When we deploy stuff to heroku, we want to make sure it is not accessible to the whole world. With ruby apps we can use `travis-sso` as a rack middleware. This is not as easy for non-ruby stuff though.

This project aims to make that easier by implementing an HTTP reverse proxy server that sits in front of the application and requires users to authenticate.

Session information is stored in an encrypted cookie (authenticated encryption), and a `Travis-State` header is provided to the application with JSON-encoded information about the authenticated user.

## Installation

    $ go get -u github.com/FiloSottile/gvt
    $ gvt restore

## Run

    $ go run cmd/sso/main.go -upstream 'https://gif.industries' -app 'http://localhost:8080' -encryption-key $(pwgen 32 1) -csrf-key $(pwgen 32 1) -authorized-users 'igorwwwwwwwwwwwwwwwwwwww,svenfuchs'

## Release

    $ make github-release
