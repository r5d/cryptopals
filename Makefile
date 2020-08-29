MOD=ricketyspace.net/cryptopals

build: fmt
	go build

fmt:
	go fmt ${MOD} ${MOD}/challenge ${MOD}/lib

clean:
	go clean
	rm -f *~ ./*/*~
.PHONY: clean
