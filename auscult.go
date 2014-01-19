package main

import (
    "io"
    "os"
    "log"
    "net"
    "bufio"
    "bytes"
    "strings"
    "os/exec"
    "io/ioutil"
    "crypto/aes"
    "crypto/md5"
    "crypto/cipher"
)

const listenAddr = ":10600"
const hashCount = int(10)

func main() {
    decrypting := true
    passphrase := ""
    if len(os.Args) == 2 {
        passphrase = os.Args[1]
    }
    server, err := net.Listen("tcp", listenAddr)
    defer server.Close()
    if err != nil {
        log.Fatal(err)
    }
    for {
        connection, err := server.Accept()
        if err != nil {
            connection.Close()
            log.Fatal(err)
        }
        go handleConn(connection, decrypting, passphrase)
    }
}

func notify(status []byte){
    result := strings.SplitN(strings.TrimSuffix(string(status), "\x00"), "/", 6)
    cmd := exec.Command("notify-send", strings.Join(result[3:], "\n"))
    err := cmd.Run();
    if err != nil {
        log.Fatal(err)
    }
}

func decrypt(status []byte, passphrase string) []byte{
    hash := md5.New()
    io.WriteString(hash, passphrase)
    iv := hash.Sum(nil)
    key := iv
    for index := 0; index < hashCount; index++ {
        key = iv
        hash = md5.New()
        io.WriteString(hash, string(iv))
        iv = hash.Sum(nil)
    }

    instance, err := aes.NewCipher(key)
    if err != nil {
        log.Fatal(err)
    }
    decrypter := cipher.NewCBCDecrypter(instance, iv)
    decrypter.CryptBlocks(status, status)
    //poor man's PKCS7 padding removal
    return bytes.TrimRight(status, "\x01\x02\x03\x04\x05\x06\x07\x08")
}

func handleConn(connection net.Conn, decrypting bool, passphrase string) {
    defer connection.Close()
    status, err := ioutil.ReadAll(bufio.NewReader(connection))
    if err != nil {
        log.Fatal(err)
    }
    if decrypting {
        status = decrypt(status, passphrase)
    }
    notify(status)
}