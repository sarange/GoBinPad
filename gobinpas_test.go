package main

import (
	"bytes"
	"os"
	"testing"
)

// Helper function to read a file
func readFile(t *testing.T, path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read file %s: %v", path, err)
	}
	return data
}

// Test function for encryption and decryption
func TestOneTimePadEncryption(t *testing.T) {
	// Load test files
	inputFile := "tests/lorem_ipsum.txt"
	otpFile := "tests/Lizzo.png"

	inputData := readFile(t, inputFile)
	otpData := readFile(t, otpFile)

	// Ensure OTP is large enough
	if len(inputData) > len(otpData) {
		t.Fatalf("OTP file is too short for input.")
	}

	// Encrypt the input
	encryptedData, err := crypt(inputFile, otpFile, false, false)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Save encrypted data for manual inspection (optional)
	err = os.WriteFile("tests/encrypted_output.bin", encryptedData, 0644)
	if err != nil {
		t.Fatalf("Failed to write encrypted file: %v", err)
	}

	// Decrypt the encrypted data
	os.WriteFile("tests/temp_encrypted.bin", encryptedData, 0644) // Save encrypted data as temp input file
	decryptedData, err := crypt("tests/temp_encrypted.bin", otpFile, true, false)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Check if decryption matches the original input
	if !bytes.Equal(inputData, decryptedData) {
		t.Fatalf("Decrypted data does not match original input.")
	}

	// Save decrypted file for manual inspection (optional)
	err = os.WriteFile("tests/decrypted_output.txt", decryptedData, 0644)
	if err != nil {
		t.Fatalf("Failed to write decrypted file: %v", err)
	}

	t.Log("Encryption and decryption successful.")
}

func TestOneTimePadEncryptionASCII(t *testing.T) {
	// Load test files
	inputFile := "tests/lorem_ipsum.txt"
	otpFile := "tests/Lizzo.png"

	inputData := readFile(t, inputFile)
	otpData := readFile(t, otpFile)

	// Ensure OTP is large enough
	if len(inputData) > len(otpData) {
		t.Fatalf("OTP file is too short for input.")
	}

	// Encrypt the input in ASCII mode
	encryptedData, err := crypt(inputFile, otpFile, false, true) // ASCII mode enabled
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Save encrypted output (optional)
	os.WriteFile("tests/encrypted_ascii.txt", encryptedData, 0644)

	// Decrypt back
	os.WriteFile("tests/temp_encrypted_ascii.txt", encryptedData, 0644)
	decryptedData, err := crypt("tests/temp_encrypted_ascii.txt", otpFile, true, true)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Check if decryption matches original input
	if !bytes.Equal(inputData, decryptedData) {
		t.Fatalf("Decrypted ASCII data does not match original input.")
	}

	// Save decrypted file for manual inspection
	os.WriteFile("tests/decrypted_ascii.txt", decryptedData, 0644)

	t.Log("ASCII mode encryption and decryption successful.")
}

