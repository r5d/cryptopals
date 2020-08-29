MOD=ricketyspace.net/cryptopals

build: fmt
	go build

fmt:
	go fmt -x ${MOD} ${MOD}/challenge ${MOD}/enc

