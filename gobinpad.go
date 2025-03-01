package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"os"

	"github.com/spf13/cobra"
)

const ASCII_MAX = 127 // Maximum ASCII value for ASCII mode encryption

func main() {
	// Define the root command
	var rootCmd = &cobra.Command{
		Use:   "gobinpad",
		Short: "A simple one-time pad encryption and decryption tool",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("You must specify a mode: encrypt or decrypt.")
		},
	}

	// Declare variables for command-line arguments
	var inputFile, otpFile, outputFile string
	var asciiMode, stdout, verbose bool

	// Define command-line flags
	rootCmd.PersistentFlags().StringVarP(&inputFile, "input", "i", "", "Path to the input file")
	rootCmd.PersistentFlags().StringVarP(&otpFile, "otp", "p", "", "Path to the one-time pad")
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "Path to the output file")
	rootCmd.PersistentFlags().BoolVarP(&asciiMode, "ascii", "a", false, "Enable ASCII mode")
	rootCmd.PersistentFlags().BoolVarP(&stdout, "stdout", "s", false, "Output to terminal if set")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	// Encrypt command
	var encryptCmd = &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypts the input file using a one-time pad",
		Run: func(cmd *cobra.Command, args []string) {
			validateInputs(inputFile, otpFile, outputFile, stdout)

			output, err := crypt(inputFile, otpFile, false, asciiMode)
			if err != nil {
				log.Fatal("Encryption failed:", err)
			}

			handleOutput(output, outputFile, stdout)
			fmt.Println("Encryption successful.")
		},
	}

	// Decrypt command
	var decryptCmd = &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypts the input file using a one-time pad",
		Run: func(cmd *cobra.Command, args []string) {
			validateInputs(inputFile, otpFile, outputFile, stdout)

			output, err := crypt(inputFile, otpFile, true, asciiMode)
			if err != nil {
				log.Fatal("Decryption failed:", err)
			}

			handleOutput(output, outputFile, stdout)
			fmt.Println("Decryption successful.")
		},
	}

	// Add encrypt and decrypt commands to the root command
	rootCmd.AddCommand(encryptCmd, decryptCmd)

	// Define the bash completion command
	var completionCmd = &cobra.Command{
		Use:   "completion",
		Short: "Generate bash completion script",
		Run: func(cmd *cobra.Command, args []string) {
			if err := rootCmd.GenBashCompletion(os.Stdout); err != nil {
				log.Fatal(err)
			}
		},
	}
	rootCmd.AddCommand(completionCmd)

	// Execute the root command
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

// validateInputs checks if required parameters are provided
func validateInputs(inputFile, otpFile, outputFile string, stdout bool) {
	if inputFile == "" || otpFile == "" || (outputFile == "" && !stdout) {
		fmt.Println("Error: Missing required parameters.")
		os.Exit(1)
	}
}

// crypt function encrypts or decrypts data using a one-time pad
func crypt(inputFile string, otpFile string, decrypt bool, asciiMode bool) ([]byte, error) {
	// Read input file
	input, err := os.ReadFile(inputFile)
	if err != nil {
		return nil, fmt.Errorf("error reading input file: %w", err)
	}

	// Read OTP file
	otp, err := os.ReadFile(otpFile)
	if err != nil {
		return nil, fmt.Errorf("error reading one-time pad file: %w", err)
	}

	// Check if OTP is large enough
	if len(input) > len(otp) {
		return nil, fmt.Errorf("error: one-time pad is too short for encryption")
	}

	// Apply deterministic scrambling to OTP
	otp = scramble(otp)

	// Create output buffer
	output := make([]byte, len(input))

	// Define operation function (encrypt/decrypt)
	op := func(a, b byte) byte {
		if decrypt {
			return a - b
		}
		return a + b
	}

	// Apply encryption or decryption
	for i := range input {
		shift := otp[i]
		if asciiMode {
			shift %= ASCII_MAX // Mod OTP with 127 to constrain shifts within ASCII
			if decrypt {
				output[i] = (input[i] - shift + ASCII_MAX) % ASCII_MAX // Reverse shift
			} else {
				output[i] = (input[i] + shift) % ASCII_MAX // Encrypt with wrapping
			}
		} else {
			output[i] = op(input[i], shift) // Standard binary mode
		}
	}

	return output, nil
}

// scramble applies a deterministic shuffle to the OTP bytes
func scramble(otp []byte) []byte {
	scrambled := make([]byte, len(otp))
	copy(scrambled, otp) // Work on a copy to avoid modifying the original

	// Generate a deterministic seed from the OTP using SHA-256
	hash := sha256.Sum256(otp)
	seed := binary.LittleEndian.Uint64(hash[:8]) // Use the first 8 bytes as seed

	// Initialize PRNG with the seed
	rng := rand.New(rand.NewSource(int64(seed)))

	// Fisher-Yates Shuffle (Knuth shuffle)
	for i := len(scrambled) - 1; i > 0; i-- {
		j := rng.Intn(i + 1) // Random index between 0 and i
		scrambled[i], scrambled[j] = scrambled[j], scrambled[i] // Swap
	}

	return scrambled
}

// handleOutput manages writing output to file or stdout
func handleOutput(output []byte, outputFile string, stdout bool) {
	if stdout {
		os.Stdout.Write(output)
	} else {
		err := os.WriteFile(outputFile, output, 0644)
		if err != nil {
			log.Fatal("Error writing output file:", err)
		}
	}
}
