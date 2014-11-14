A simple TCP desktop receiver for android-notifier. It only works with "v2" messages, but it can decrypt and encrypt messages. It could fail at any moment because of all the log.Fatal possibilities, but I'd rather crash then get somewhere bad...

To compile:
go build auscult.go

To run:
./auscult [-p "passphrase"] [-a address:port] [-m "message"]

Can be used to send a message to another address:port with the -m command line parameterized switch.

The crypto in this program is not recommended for security (it reuses the same iv for every message) -- but that is how the original programmers designed it, so sticking to the "spec".
In addition I make some simplifying assumptions about PKCS7 padding which do not follow standards.


This entire repo is released under the CC0 license.

similar/related projects (that I have no affiliation with):
http://github.com/hades/Cyborg/wiki (C++ implementation that works with UDP as well and on Windows)
http://code.google.com/p/android-notifier/ (The android app that sends these notifications)
https://github.com/knopwob/dunst (a lightweight dbus notifier)
