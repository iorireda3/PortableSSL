/**
 * @file main.c
 * @brief CLI tool for PortableSSL
 */

#include "portable_ssl.h"
#include "platform/platform.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_COMMAND_LENGTH 256
#define MAX_ARGS 32

static void print_usage(void) {
    printf("PortableSSL - Portable OpenSSL Alternative\n");
    printf("Usage: portable_ssl <command> [options]\n\n");
    printf("Available commands:\n");
    printf("  version                        Display version information\n");
    printf("  help                           Display this help message\n");
    printf("  enc -<cipher> [options]        Encrypt/decrypt using <cipher>\n");
    printf("  dgst -<hash> [options]         Generate digest using <hash>\n");
    printf("  genrsa [bits]                  Generate RSA private key\n");
    printf("  rsa [options]                  Process RSA keys\n");
    printf("  s_client [options]             TLS/SSL client\n");
    printf("  s_server [options]             TLS/SSL server\n");
}

static void print_version(void) {
    int major, minor, patch;
    portable_ssl_version(&major, &minor, &patch);
    printf("PortableSSL %d.%d.%d\n", major, minor, patch);
}

static int cmd_version(int argc, char* argv[]) {
    print_version();
    return 0;
}

static int cmd_help(int argc, char* argv[]) {
    print_usage();
    return 0;
}

static int cmd_enc(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Error: No cipher specified\n");
        return 1;
    }
    
    const char* cipher = argv[1];
    if (strncmp(cipher, "-aes", 4) == 0) {
        printf("AES encryption/decryption not yet implemented\n");
    } else {
        printf("Unsupported cipher: %s\n", cipher);
    }
    
    return 0;
}

static int cmd_dgst(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Error: No hash algorithm specified\n");
        return 1;
    }
    
    const char* hash = argv[1];
    if (strcmp(hash, "-sha256") == 0) {
        printf("SHA-256 hash calculation not yet implemented\n");
    } else {
        printf("Unsupported hash algorithm: %s\n", hash);
    }
    
    return 0;
}

static int cmd_genrsa(int argc, char* argv[]) {
    int bits = 2048;  /* Default key size */
    
    if (argc >= 2) {
        bits = atoi(argv[1]);
        if (bits != 1024 && bits != 2048 && bits != 4096) {
            printf("Invalid key size. Supported sizes: 1024, 2048, 4096\n");
            return 1;
        }
    }
    
    printf("RSA key generation not yet implemented\n");
    return 0;
}

static int cmd_rsa(int argc, char* argv[]) {
    printf("RSA key processing not yet implemented\n");
    return 0;
}

static int cmd_s_client(int argc, char* argv[]) {
    printf("TLS client not yet implemented\n");
    return 0;
}

static int cmd_s_server(int argc, char* argv[]) {
    printf("TLS server not yet implemented\n");
    return 0;
}

typedef struct {
    const char* name;
    int (*func)(int, char**);
} command_t;

static const command_t commands[] = {
    { "version", cmd_version },
    { "help", cmd_help },
    { "enc", cmd_enc },
    { "dgst", cmd_dgst },
    { "genrsa", cmd_genrsa },
    { "rsa", cmd_rsa },
    { "s_client", cmd_s_client },
    { "s_server", cmd_s_server },
    { NULL, NULL }
};

int main(int argc, char* argv[]) {
    int i;
    
    /* Initialize library */
    if (portable_ssl_init() != PORTABLE_SSL_SUCCESS) {
        fprintf(stderr, "Failed to initialize PortableSSL\n");
        return 1;
    }
    
    /* Display usage if no command provided */
    if (argc < 2) {
        print_usage();
        portable_ssl_cleanup();
        return 1;
    }
    
    /* Find and execute command */
    for (i = 0; commands[i].name != NULL; i++) {
        if (strcmp(argv[1], commands[i].name) == 0) {
            int ret = commands[i].func(argc - 2, &argv[2]);
            portable_ssl_cleanup();
            return ret;
        }
    }
    
    /* Unknown command */
    printf("Unknown command: %s\n", argv[1]);
    print_usage();
    portable_ssl_cleanup();
    return 1;
}