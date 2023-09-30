NODE?=node

PRETTIER?=npx --yes prettier
PRETTIERFLAGS?=--no-config --use-tabs --single-quote
PRETTIERSRC=*.mjs

MBIDLED_PATH?=../build

run :
	PATH=$(MBIDLED_PATH):$(PATH) $(NODE) ./run-tests.mjs

pre-run :
	openssl genrsa -out key.pem 1024
	openssl req -batch -new -key key.pem -out csr.pem
	openssl x509 -req -in csr.pem -signkey key.pem -out cert.pem

lint :
	$(PRETTIER) $(PRETTIERFLAGS) --check $(PRETTIERSRC)

fix :
	$(PRETTIER) $(PRETTIERFLAGS) --write $(PRETTIERSRC)

clean :
	$(RM) *.pem
