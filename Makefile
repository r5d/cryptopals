MOD=ricketyspace.net/cryptopals

build: fmt
	go build
.PHONY: build

fmt:
	go fmt ${MOD} ${MOD}/challenge ${MOD}/lib
.PHONY: fmt

test:
	go test ${MOD}/lib
.PHONY: test

clean:
	go clean
	rm -f *~ ./*/*~
.PHONY: clean
