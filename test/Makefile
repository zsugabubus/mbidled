NODE?=node

PRETTIER?=npx --yes prettier
PRETTIERFLAGS?=--no-config --use-tabs --single-quote
PRETTIERSRC=*.mjs

MBIDLED_PATH?=../build
PEMS=key.pem csr.pem cert.pem

run : | $(PEMS)
	PATH=$(MBIDLED_PATH):$(PATH) $(NODE) ./index.mjs $(TEST_FLAGS)

$(PEMS) :
	openssl genrsa -out key.pem 2048
	openssl req -batch -new -key key.pem -out csr.pem
	openssl x509 -req -in csr.pem -signkey key.pem -out cert.pem

lint :
	$(PRETTIER) $(PRETTIERFLAGS) --check $(PRETTIERSRC)

fix :
	$(PRETTIER) $(PRETTIERFLAGS) --write $(PRETTIERSRC)

clean :
	$(RM) *.pem
