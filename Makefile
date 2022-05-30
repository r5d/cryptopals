MOD=ricketyspace.net/cryptopals
PKGS=${MOD} ${MOD}/challenge ${MOD}/lib

build: fmt
	go build
.PHONY: build

fmt:
	go fmt ${PKGS}
.PHONY: fmt

test:
	go test ${ARGS} ${MOD}/lib
.PHONY: test

clean:
	go clean
	rm -f *~ ./*/*~
.PHONY: clean
