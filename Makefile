#!/usr/bin/make -f

USER    ?= smartmeter
INST_HOME    ?= /srv/$(USER)

DEBS	= dpkg/libbsd0_0.8.3-1_amd64.deb dpkg/libbsd-dev_0.8.3-1_amd64.deb

build: pubkey_rfc5114.pem dpkg.stamp
	$(MAKE) -C src build

%.deb:
	(cd dpkg; wget -q https://ctf00.informatik.uni-erlangen.de/dl/smartmeter/$@)

dpkg.stamp: $(DEBS)
	sha256sum -c dpkg/SHA256SUM
	dpkg -i $^

install: build
	chmod 0500 $(INST_HOME)
	install -m 700 -o $(USER) -d $(INST_HOME)/cert
	#cp src/bjnfc/bjnfc-prod /tmp/bjnfc
	#cd patches && ./dir_traversal.sh
	#mv /tmp/bjnfc.no_dir_trav /tmp/bjnfc
	#cd patches && ./sqli.sh
	#mv /tmp/bjnfc.no_sqli /tmp/bjnfc
	#cd patches && ./overflow.sh
	#install -m 755 -o root /tmp/bjnfc.no_overflow $(INST_HOME)/bjnfc
	install -m 755 -o root src/bjnfc/bjnfc-prod $(INST_HOME)/bjnfc
	install -m 444 -o root src/bjnfc/dh2048.pem --target-directory $(INST_HOME)
	install -m 444 -o root param_rfc5114.pem --target-directory $(INST_HOME)
	install -m 444 -o root pubkey_rfc5114.pem --target-directory $(INST_HOME)
	install -m 444 -o root -D src/bjnfc/static/* --target-directory $(INST_HOME)/static/
	install -m 644 -o root ./src/smartmeter.service /etc/systemd/system
	systemctl enable smartmeter.service
	install -m 644 -o root ./src/uwsgi.service /etc/systemd/system
	systemctl enable uwsgi.service
	install -m 755 src/schnorr/libschnorr.so -t checker/smartmeter/
	install -m 755 privkey_rfc5114.pem -t checker/smartmeter/
	echo "local $(USER) $(USER) peer" >> /etc/postgresql/9.6/main/pg_hba.conf
	install -m 444 src/bjnfc/init.sql -T /tmp/init$(USER).sql
	su -s /bin/sh -c 'createdb $(USER) && psql -f /tmp/init$(USER).sql $(USER)' - postgres
	sed -i -e 's|^#log_min_messages = warning|log_min_messages = log|' /etc/postgresql/9.6/main/postgresql.conf
	sed -i -e 's|^#log_min_error_statement = error|log_min_error_statement = log|' /etc/postgresql/9.6/main/postgresql.conf
	rm /tmp/init$(USER).sql
	rm -f $(INST_HOME)/.rnd

param_rfc5114.pem:
	openssl genpkey -genparam -algorithm DH -out param_rfc5114.pem -pkeyopt dh_rfc5114:3

privkey_rfc5114.pem: param_rfc5114.pem
	openssl genpkey -paramfile param_rfc5114.pem -out privkey_rfc5114.pem -pkeyopt dh_rfc5114:3
	openssl pkey -in privkey_rfc5114.pem -text_pub -noout

pubkey_rfc5114.pem: privkey_rfc5114.pem
	openssl pkey -in privkey_rfc5114.pem -pubout -out pubkey_rfc5114.pem

clean:
	rm -rf $(INST_HOME) /etc/systemd/system/smartmeter.service
	make -C src clean


.PHONY: build install clean
