#!/bin/sh

sed -e 's/# bjnfc configuration/# bjnfc configurati/' -e 's/validator v_device regex \[\[:alnum:\]\]{,20}/validator v_device regex \^[[:alnum:]]{,20}\$/' < /tmp/bjnfc > /tmp/bjnfc.no_overflow
