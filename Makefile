MOD=ricketyspace.net/cryptopals
PKGS=${MOD} ${MOD}/challenge ${MOD}/lib

build: fmt vet
	go build
.PHONY: build

fmt:
	go fmt ${PKGS}
.PHONY: fmt

vet:
	go vet ./...
.PHONY: vet

test:
	go test ${ARGS} ${MOD}/lib
.PHONY: test

clean:
	go clean
	rm -f *~ ./*/*~
.PHONY: clean
