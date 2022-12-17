/*
from https://chat.openai.com/chat
This program prompts the user to enter a message to encrypt and then uses the Caesar cipher method
to shift each letter in the message by a certain number of positions (in this case, 3).
The encrypted message is then printed to the screen.

The Caesar cipher is a very simple encryption method,
and it can easily be broken by someone who knows how it works. More secure encryption methods are available,
such as the Advanced Encryption Standard (AES).
*/

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define KEY 3

int main()
{
    char message[100];
    int i;

    printf("Enter a message to encrypt: ");
    gets(message);

    for (i = 0; i < strlen(message); i++)
    {
        if (isalpha(message[i]))
        {
            if (isupper(message[i]))
            {
                message[i] = (message[i] - 'A' + KEY) % 26 + 'A';
            }
            else
            {
                message[i] = (message[i] - 'a' + KEY) % 26 + 'a';
            }
        }
    }

    printf("Encrypted message: %s\n", message);

    return 0;
}