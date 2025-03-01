# **GoBinPad - A One-Time Pad Encryption Tool in Go**  

*A lightweight, secure, and deterministic one-time pad encryption tool written in Go.*  

---

## **About**  
GoBinPad is a command-line utility that provides strong encryption using a **one-time pad (OTP)**. This tool was inspired by [PixelPad](https://github.com/mcbethr/PixelPad) and extends the idea to a Go-based implementation, allowing users to securely encrypt and decrypt files with a truly unbreakable cipher—when used correctly.  

- **Fisher-Yates shuffle** of the OTP for additional security.  
- **ASCII mode** for preserving printable characters.  
- **Flexible OTP sources** – The OTP can be **any file**, such as an **image, video, or random binary data**.  

---

## **Installation**  

### **Using `go install`**  
If you have Go installed, you can install GoBinPad directly from the repository:  

```sh
go install github.com/sarange/GoBinPad@latest
```  
This will install `gobinpad` in your `$GOPATH/bin` directory, allowing you to run it globally.  

### **From Source**  
Alternatively, you can build GoBinPad manually:  

```sh
git clone https://github.com/sarange/GoBinPad.git
cd GoBinPad
go build
```  
You can now run `./gobinpad` from the current directory.  

---

## **Usage**  

GoBinPad operates via the command line and provides **encryption** and **decryption** functionality.  

### **Encrypt a File**  
```sh
gobinpad encrypt -i input.txt -p otp.bin -o encrypted.bin
```  
This encrypts `input.txt` using the OTP file `otp.bin` and saves the output as `encrypted.bin`.  

### **Decrypt a File**  
```sh
gobinpad decrypt -i encrypted.bin -p otp.bin -o decrypted.txt
```  
This reverses the encryption and restores the original file.  

### **Encrypt in ASCII Mode**  
```sh
gobinpad encrypt -i input.txt -p otp.bin -o encrypted_ascii.txt --ascii
```  
This ensures that encrypted output remains within the **printable ASCII range**.  

### **Decrypt in ASCII Mode**  
```sh
gobinpad decrypt -i encrypted_ascii.txt -p otp.bin -o decrypted.txt --ascii
```  

### **Output to Terminal Instead of a File**  
```sh
gobinpad encrypt -i input.txt -p otp.bin --ascii --stdout
```  

## **Important Security Notice**  

> **If the OTP is compromised, the encrypted message is no longer secure.**

- The security of the **one-time pad** relies entirely on the secrecy and randomness of the OTP.  
- **Never reuse an OTP** – each encryption must have a unique OTP file.  
- **Your OTP can be any file**, such as **images, videos, or random binary data**, but it must be **statistically unpredictable and at least as long as the input file**.  
- If an attacker gains access to both the encrypted message and the OTP, they can decrypt it instantly.  

## **License**  
**GoBinPad** is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.  
See the [LICENSE](LICENSE) file for more details.  

## **Acknowledgments**  
Inspired by [PixelPad](https://github.com/mcbethr/PixelPad).  
