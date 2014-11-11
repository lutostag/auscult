package main

import (
    "io"
    "fmt"
    "log"
    "net"
    "flag"
    "bufio"
    "bytes"
    "strings"
    "os/exec"
    "io/ioutil"
    "crypto/aes"
    "crypto/md5"
    "crypto/cipher"
)

var address = flag.String("a", ":10600", "listen on/send to the given address (ip:port)")
var passphrase = flag.String("p", "", "passphrase for crypto")
var message = flag.String("m", "", "message to send, does not listen")
const hashCount = int(10)
const pkcsPad = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
var pkcsPadBytes = []byte(pkcsPad)

func main() {
    crypting := false
    sending := false
    flag.Parse()
    if *passphrase != "" {
        crypting = true
    }
    if *message != "" {
        sending = true
    }
    if ! sending {
        server, err := net.Listen("tcp", *address)
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
            go handleConn(connection, crypting, *passphrase)
        }
    } else {
        conn, err := net.Dial("tcp", *address)
        if err != nil {
            log.Fatal(err)
        }
        scrubbedMessage := "///" + strings.Replace(*message, "/", "", -1) + "//"
        messageBytes := []byte(scrubbedMessage)
        if crypting {
            messageBytes = encrypt(messageBytes, *passphrase)
        }
        conn.Write(messageBytes)
    }
}

func notify(status []byte){
    result := strings.SplitN(strings.TrimSuffix(string(status), "\x00"), "/", 6)
    resultVal := ""
    urgency := "--urgency=normal"
    timeout := "--expire-time=5000"
    if result[4] != "" || result [5] != "" {
        resultVal = strings.Trim(strings.Join(result[3:], "\n"), " ")
    } else {
        urgency = "--urgency=critical"
        resultVal = strings.Trim(string(result[3]), " ")
    }
    cmd := exec.Command("notify-send", urgency, timeout, resultVal)
    err := cmd.Run();
    if err != nil {
        fmt.Printf("[% x]", []byte(strings.Join(result[3:], "\n")))
        log.Fatal(err)
    }
}

func encrypt(plaintext []byte, passphrase string) []byte{
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
    //wrong man's PKCS7 padding addition
    if len(plaintext)%aes.BlockSize != 0 {
        pad_length := aes.BlockSize - len(plaintext)%aes.BlockSize
        plaintextPadded := make([]byte, len(plaintext)+pad_length) 
        plaintextPadded = append(plaintext, pkcsPadBytes[:pad_length]...)
        plaintext = plaintextPadded
    }

    ciphertext := make([]byte, aes.BlockSize+len(plaintext))
    encrypter := cipher.NewCBCEncrypter(instance, iv)
    encrypter.CryptBlocks(ciphertext, plaintext)
    return ciphertext[:len(plaintext)]
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
    return bytes.TrimRight(status, pkcsPad)
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
