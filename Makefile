NODE?=node

PRETTIER?=npx --yes prettier
PRETTIERFLAGS?=--no-config --use-tabs
PRETTIERSRC=*.js

MBIDLED_PATH?=../build
PEMS=key.pem csr.pem cert.pem

check : | $(PEMS)
	FORCE_COLOR=2 PATH=$(MBIDLED_PATH):$(PATH) $(NODE) --test --test-force-exit $(TEST_FLAGS)

$(PEMS) :
	openssl genrsa -out key.pem 2048
	openssl req -batch -new -key key.pem -out csr.pem
	openssl x509 -req -in csr.pem -signkey key.pem -out cert.pem

lint :
	clang-format -Werror --dry-run -- *.c *.h
	$(PRETTIER) $(PRETTIERFLAGS) --check $(PRETTIERSRC)

fix :
	clang-format -i -- *.c *.h
	$(PRETTIER) $(PRETTIERFLAGS) --write $(PRETTIERSRC)

clean :
	$(RM) *.pem
