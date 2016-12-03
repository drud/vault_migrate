TAG = $(shell git rev-parse HEAD | tr -d '\n')
PREFIX = drud/drud

build:
	CGO_ENABLED=0 GOOS=darwin go build -a -installsuffix cgo -ldflags '-w'   ./main.go
	@mkdir -p ./bin
	@cp -p $(GOPATH)/bin/drud ./bin

