.PHONY: all compile test lint doc edown ex_doc clean eep48

all: compile

compile:
	rebar3 compile

test:
	rebar3 eunit

lint:
	elvis rock --verbose

doc: edown
	rebar3 edoc

edown:
	rebar3 as edown edoc

clean:
	rebar3 clean
	rm -rf _build

run:
	rebar3 shell --name jwt

ex_doc: eep48
	mix deps.get
	mix docs

eep48:
	rebar3 eep48
