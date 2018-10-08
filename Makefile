linter:
	gometalinter.v2 ./...

default:
	(cd parser; ragel -Z -G2 -o lex.go straceLex.rl)
	(cd parser; goyacc -o strace.go -p Strace strace.y)
	mkdir -p bin deserialized
	go build -o ./bin/moonshine main.go
clean:
	rm -f parser/lex.go
	rm -f parser/strace.go
	rm -f ./bin/moonshine
	rm -f parser/y.output
