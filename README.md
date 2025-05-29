# PortableSSL

Like openssl but fully portable, dependency-free implementation of cryptographic primitives and TLS protocol.

## Project Overview

PortableSSL is a lightweight, self-contained cryptographic and TLS library designed to have zero external dependencies. It provides core cryptographic algorithms and TLS functionality that can be used across any platform without relying on system libraries or pre-installed components.

=> This project aims to stop the planned obsolescence of systems and equipment.

### Key Features

- **Zero External Dependencies**: Everything needed is included in the library
- **Cross-Platform**: Works on Windows, Linux, macOS, and embedded systems
- **Core Cryptographic Primitives**: AES, SHA-256, RSA
- **TLS Protocol Support**: Client and server implementation
- **OpenSSL-Compatible CLI**: Familiar command-line interface
- **Minimal Codebase**: Focus on essential functionality and clean code
- **Modular Architecture**: Easy to extend and customize

## Building

PortableSSL uses CMake as its build system:

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

## Usage

### Library

```c
#include <portable_ssl.h>

int main() {
    // Initialize the library
    if (portable_ssl_init() != PORTABLE_SSL_SUCCESS) {
        // Handle error
        return 1;
    }
    
    // Use cryptographic functions
    uint8_t digest[32];
    sha256((uint8_t*)"hello", 5, digest);
    
    // Clean up
    portable_ssl_cleanup();
    return 0;
}
```

### Command Line

```bash
# Generate SHA-256 hash
portable_ssl dgst -sha256 file.txt

# Encrypt a file with AES-256
portable_ssl enc -aes-256-cbc -in plaintext.txt -out encrypted.bin -pass pass:mypassword

# Create TLS client connection
portable_ssl s_client -connect example.com:443
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Project Status

This is an early stage project under active development. The current implementation includes:

- Core framework and architecture
- Basic implementations of essential algorithms
- TLS protocol foundation

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
