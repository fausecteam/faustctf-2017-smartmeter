#!/usr/bin/make -f

.PHONY: build kore bjnfc clean

export PATH := $(shell pwd)/root/bin/:$(PATH)

build:
	$(MAKE) -C kore/ all install PREFIX=$(shell pwd)/root/ PGSQL=1
	$(MAKE) -C schnorr/ all install PREFIX=$(shell pwd)/root/
	$(MAKE) -C bjnfc/

clean:
	$(MAKE) -C bjnfc/ clean
	$(MAKE) -C kore/ clean
	$(MAKE) -C schnorr/ clean
	rm -rf root/
