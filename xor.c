#include <stdio.h>
#include <string.h>

// Function to perform XOR encryption
void xorEncrypt(char *message, char *key, int messageLength)
{
    for (int i = 0; i < messageLength; i++) {
        message[i] ^= key[i % sizeof(key)];
    }
}

// Function to perform XOR decryption
void xorDecrypt(char *message, char *key, int messageLength)
{
    for (int i = 0; i < messageLength; i++) {
        message[i] ^= key[i % sizeof(key)];
    }
}

int main()
{
    char message[100] = "Hello, World!";
    char key[11] = "secretpenis";
    int messageLength = strlen(message);

    printf("Enter a message to encrypt: ");
    gets(message);

    printf("Original message: %s\n", message);

    // Perform XOR encryption
    xorEncrypt(message, key, messageLength);
    printf("Encrypted message: %s\n", message);

    // Perform XOR decryption
    xorDecrypt(message, key, messageLength);
    printf("Decrypted message: %s\n", message);

    return 0;
}