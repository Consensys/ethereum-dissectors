#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

EVP_CIPHER_CTX ctx;

int encode_string(char *string) {
    if (strlen(string) % 2 != 0 || strlen(string) > 32) {
        //Not valid hex data
	return 1;
    } else {
        for (int i = 0; i < strlen(string); i++) {
	    if ((string[i] >= '0' && string[i] <= '9') ||
		    (string[i] >= 'a' && string[i] <= 'f')) {
	        //This char is fine
		continue;
	    } else {
	        return 1;
	    }
	}
    }
    //Get the input hex data
    unsigned char *in = malloc(strlen(string) / 2 * sizeof(unsigned char));
    for (int i = 0; i < strlen(string) / 2; i++) {
        int first, second;
        if (string[2 * i] >= 'a' && string[2 * i] <= 'f') {
            first = (string[2 * i] - 'a' + 10);
        } else {
            first = (string[2 * i] - '0');
        }
        if (string[2 * i + 1] >= 'a' && string[2 * i + 1] <= 'f') {
            second = (string[2 * i + 1] - 'a' + 10);
        } else {
            second = (string[2 * i + 1] - '0');
        }
        in[i] = 16 * first + second;
    }
    
    unsigned char out[64];
    int outlen;
    EVP_EncryptUpdate(&ctx, out, &outlen, in, strlen(string) / 2);
    free(in);
    for (int i = 0; i < outlen; i++) {
        fprintf(stdout, "%02x", out[i]);
    }
    fprintf(stdout, "\n");
    fflush(stdout);
    return 0;
}

int main(int argc, char *argv[]) {
    //Check usage
    int trigger = 0;
    if (argc != 2) {
    	trigger = 1;    
    } else {
    	if (strlen(argv[1]) != 64) {
	    //not valid key
	    trigger = 1;
	} else {
	    //Test if key is valid or not
	    for (int i = 0; i < 64; i++) {
	        if ((argv[1][i] >= '0' && argv[1][i] <= '9') ||
			(argv[1][i] >= 'a' && argv[1][i] <= 'f')) {
		    //This char is fine
		    continue;
		} else {
		    trigger = 1;
		    break;
		}
	    }
	}
    }
    if (trigger == 1) {
        fprintf(stdout, "Usage: aes valid-256bit-key\n");
	fflush(stdout);
	return 1;
    }
    //Get key
    unsigned char key[32];
    for (int i = 0; i < 32; i++) {
        int first, second;
        if (argv[1][2 * i] >= 'a' && argv[1][2 * i] <= 'f') {
            first = (argv[1][2 * i] - 'a' + 10);
        } else {
            first = (argv[1][2 * i] - '0');
        }
        if (argv[1][2 * i + 1] >= 'a' && argv[1][2 * i + 1] <= 'f') {
            second = (argv[1][2 * i + 1] - 'a' + 10);
    	} else {
            second = (argv[1][2 * i + 1] - '0');
    	}
    	key[i] = 16 * first + second;
    }
    //Init the cipher
    unsigned char iv[16] = {0};
    EVP_EncryptInit(&ctx, EVP_aes_256_ctr(), key, iv);
    //Continue to decode/encode
    while (1) {
        char *string;
    	string = malloc(sizeof(char));
    	char in;
    	int i = 0;
    	while ((in = fgetc(stdin)) != '\n' && in != EOF) {
            string[i++] = (char)in;
	    string = realloc(string, (i + 1) * sizeof(char));
	}
	string[i] = '\0';
	int test = encode_string(string);
	free(string);
	if (test == 1) {
	    //Not valid data
	    fprintf(stdout, "Not valid string\n");
	    fflush(stdout);
	    return 1;
	}
    }
    return 0;
}
