SmartMeter
==========

This is the source code for the "SmartMeter" service from [FAUST CTF 2017](https://2017.faustctf.net).

**As it was written for a CTF service, the code is deliberately insecure and contains exploitable bugs. It
is provided for educational purposes only, do not even think about (re-) using it for anything productive!**

The code is released under the ISC License, see LICENSE.txt for details.

Example Exploits
----------------

* The files `retdeobfu.py`, `smartmeter.py` and `reanalyze.py` show how a IDA Python script could deobfuscate the binary. They don't actually correctly deobfuscate though, because we stopped at the point where we'd shown that and how it's possible.
* The file `sql_injection.py` performs a blind SQL injection to steal all currently stored flags.
* The file `dir_traversal.py` uses a directory traversal to steal the database of the toaster service.
* The file `buffer_overflow_chall.py` exploits a buffer overflow to execute a ROP chain that calls system() to dump all flags from the database over the existing TCP connection (but necessarily without the TLS tunnel). Please note that this script was developed for a different compile run than the actual CTF, so the exact addresses for the ROP chain are likely to be slightly different.