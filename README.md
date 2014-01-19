A simple TCP desktop receiver for android-listener. It only works with "v2" messages, but it can decrypt encrypted messages. It could fail at any moment because of all the log.Fatal possibilities, but I'd rather crash then get somewhere bad...

To compile:
go build auscult.go

To run:
./auscult ["passphrase"]

This entire repo is released under the CC0 license.

similar/related projects (that I have no affiliation with):
http://github.com/hades/Cyborg/wiki (C++ implementation that works with UDP as well and on Windows)
http://code.google.com/p/android-notifier/ (The android app that sends these notifications)
https://github.com/knopwob/dunst (a lightweight dbus notifier)
