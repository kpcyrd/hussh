all: docs

docs: contrib/hussh.1

%.1: %.1.scd
	scdoc < $^ > $@
