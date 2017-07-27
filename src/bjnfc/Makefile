all: bjnfc-prod

deps=$(shell find src/ conf/)

conf/build.conf: conf/build.conf.pre $(MAKEFILE_LIST)
	sed -e "s|\$${KORE_HOME}|$(shell pwd)/../root/|" "$<" > "$@"

src/systemd.c: org.freedesktop.systemd1.xml $(MAKEFILE_LIST)
	cd src ; gdbus-codegen --generate-c-code systemd --interface-prefix org.freedesktop. --c-generate-object-manager ../org.freedesktop.systemd1.xml

.flavor:
	touch .flavor

bjnfc-%: $(deps) .flavor conf/build.conf src/systemd.c
	[ "$$(cat .flavor)" = "$*" ] || kore flavor "$*"
	kore build
	mv bjnfc "$@"

run-%: bjnfc-%
	"./bjnfc-$*" -f -n -r

clean:
	rm -f bjnfc-* conf/build.conf .flavor src/systemd.c src/systemd.h
	kore clean

.PHONY: all run-% clean
