lint :
	clang-format -Werror --dry-run -- *.c *.h

fix :
	clang-format -i -- *.c *.h
