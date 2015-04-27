NO_COLOR=\033[0m
OK_COLOR=\033[32;01m
ERROR_COLOR=\033[31;01m

init:
	@echo "$(OK_COLOR)==> Installing tooling dependencies$(NO_COLOR)"
	go get github.com/stretchr/testify/assert


test:
	@echo "$(OK_COLOR)==> Testing$(NO_COLOR)"
	go test ./...


.PHONY: init test