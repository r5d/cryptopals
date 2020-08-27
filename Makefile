MOD=ricketyspace.net/cryptopals

build: fmt bin
	go build -o bin/c1 c1.go

fmt:
	go fmt -x ${MOD} ${MOD}/enc

bin:
	mkdir -p bin
