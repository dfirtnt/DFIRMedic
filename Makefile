LDFLAGS ?=
export CGO_ENABLED=0

.PHONY: test vet check build-windows build-darwin generate clean

test:
	go test ./...

vet:
	go vet ./...

generate:
	cd cmd/dfirmedic && go generate

build-windows: generate
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/dfirmedic.exe ./cmd/dfirmedic

build-darwin:
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/dfirmedic ./cmd/dfirmedic

check: vet test
	GOOS=windows GOARCH=amd64 go build -o /dev/null ./cmd/dfirmedic

clean:
	rm -rf dist cmd/dfirmedic/rsrc_windows_*.syso
