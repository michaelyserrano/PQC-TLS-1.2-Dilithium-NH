// Lib PQ

#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/time.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "params.h"
#include "dilithium1aes/rng.h"
#include "newhope/apinh.h"
#include "newhope/fips202nh.h"
#include "ecdh/ecdh.h"
#include "opensslaes.h"
#include "pq.h"

unsigned long long cyclesAES;
unsigned long long cyclesNH;
unsigned long long cyclesDil;

/* pseudo random number generator with 128 bit internal state... probably not suited for cryptographical usage */
typedef struct {
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
} prng_t;

static prng_t prng_ctx;

static uint32_t prng_rotate(uint32_t x, uint32_t k) {
    return (x << k) | (x >> (32 - k));
}

static uint32_t prng_next(void) {
    uint32_t e = prng_ctx.a - prng_rotate(prng_ctx.b, 27);
    prng_ctx.a = prng_ctx.b ^ prng_rotate(prng_ctx.c, 17);
    prng_ctx.b = prng_ctx.c + prng_ctx.d;
    prng_ctx.c = prng_ctx.d + e;
    prng_ctx.d = e + prng_ctx.a;

    return prng_ctx.d;
}

static void prng_init(uint32_t seed) {
    uint32_t i;
    prng_ctx.a = 0xf1ea5eed;
    prng_ctx.b = prng_ctx.c = prng_ctx.d = seed;

    for (i = 0; i < 31; ++i) {
        (void) prng_next();
    }
}

void recv_timeout(int socket, unsigned char *c, double timeout)
{
    int size_recv, total_size = 0;
    struct timeval begin, now;
    char chunk[CHUNK_SIZE];
    double timediff;
    int flags;

    // Save the existing flags
    flags = fcntl(socket, F_GETFL, 0);
    //make socket non blocking
    fcntl(socket, F_SETFL, O_NONBLOCK);

    //beginning time
    gettimeofday(&begin, NULL);

    while (1)
    {
        gettimeofday(&now, NULL);

        //time elapsed in miliseconds
        timediff = ((now.tv_sec - begin.tv_sec) * 1e6 + (now.tv_usec - begin.tv_usec))/1000;

        //if you got some data, then break after timeout
        if (timediff > timeout)
        {
            break;
        }
        else if (timediff > timeout*2)//if you got no data at all, wait a little longer, twice the timeout
        {
            break;
        }

        memset(chunk ,0 , CHUNK_SIZE);  //clear the variable

        if((size_recv =  recv(socket, chunk, CHUNK_SIZE, 0) ) < 0)
        {
            //if nothing was received then we want to wait a little before trying again, 500 milliseconds
            usleep(500000);
        }
        else
        {
            memcpy(c + total_size, chunk, CHUNK_SIZE);
            total_size += size_recv;
            //reset beginning time
            gettimeofday(&begin, NULL);
        }
    }

    /* Clear the blocking flag. */
    flags &= ~O_NONBLOCK;
    //make socket blocking
    fcntl(socket, F_SETFL, flags);
}

void printBstr(char *S, unsigned char *A, unsigned long long len)
{
    unsigned long long  i;

    printf("%s", S);

    for ( i=0; i<len; i++ )
        printf("%02X", A[i]);

    if ( len == 0 )
        printf("00");

    printf("\n");
}

void fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long len)
{
    unsigned long long  i;

    fprintf(fp, "%s", S);

    for ( i=0; i<len; i++ )
        fprintf(fp, "%02X", A[i]);

    if ( len == 0 )
        fprintf(fp, "00");

    fprintf(fp, "\n");
}

void mfiles (char *filename, unsigned long long dilithium, unsigned long long newhope, unsigned long long aes, unsigned long long total)
{
    FILE *fp = fopen(filename, "a");
    if(fp)
    {
        fprintf(fp,"%llu,%llu,%llu,%llu\n", dilithium, newhope, aes, total); //print file
    }
    fclose(fp);
}

/****** -> RSA ******/
/**
 * ref:
 * https://shanetully.com/2012/06/openssl-rsa-aes-and-c/
 * https://shanetully.com/2012/04/simple-public-key-encryption-with-rsa-and-openssl/
 * http://hayageek.com/rsa-encryption-decryption-openssl-c/
 *
 * @param sock
 * @param opt
 * @return
 */
// opt = 1: KeyGen, Sign; opt = 0: Verification
int rsa(int sock, int opt) {

    int ret, j;
    int flag = 0;
    unsigned char buffer[NBYTES];
    int encrypt_len;
    unsigned char msg[MLEN];
    unsigned char *decrypt = NULL;
    unsigned char *encrypt = NULL;
    char err[130];
    RSA *keypair = RSA_new();;
    BIO *pub = NULL;
    char *pub_key = NULL;


    bzero(buffer, NBYTES);
    bzero(msg, MLEN);
    bzero(err, 130);

    // KeyGen and Sign
    // opt = 1 | send pk and cert with sign
    if (opt) {
        BIGNUM *bn;
        bn = BN_new();
        BN_set_word(bn, RSA_F4);

        ret = RSA_generate_key_ex(keypair, 2048, bn, NULL);
        send(sock, &ret, sizeof(ret), 0);
        if(!ret) {
            flag = 1;
            strcpy(buffer, "Generation the public/private keypair failed (Dilithium)");
            printf("ERROR: %s\n", buffer);
            send(sock, buffer, strlen(buffer), 0);
            return flag;
        }

        // Split keypair into public and private
        BIO *pri = BIO_new(BIO_s_mem());
        pub = BIO_new(BIO_s_mem());

        PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
        PEM_write_bio_RSAPublicKey(pub, keypair);

        size_t pri_len = BIO_pending(pri);
        size_t pub_len = BIO_pending(pub);

        char *pri_key = malloc(pri_len + 1);
        pub_key = malloc(pub_len + 1);

        BIO_read(pri, pri_key, pri_len);
        BIO_read(pub, pub_key, pub_len);


        pri_key[pri_len] = '\0';
        pub_key[pub_len] = '\0';

        // create random message
        randombytes(msg, MLEN-1);
        msg[MLEN-1] = 0;

        // Encrypt the message
        encrypt = malloc(RSA_size(keypair));
        encrypt_len = RSA_private_encrypt(MLEN, msg, encrypt, keypair, RSA_PKCS1_PADDING);
        send(sock, &ret, sizeof(ret), 0);
        if (encrypt_len == -1) {
            flag = 1;
            ERR_load_crypto_strings();
            ERR_error_string(ERR_get_error(), err);
            fprintf(stderr, "Error encrypting message with RSA: %s\n", err);
            send(sock, err, strlen(err), 0);
            goto free_stuff1;
        }


        send(sock, &encrypt_len, sizeof(encrypt_len), 0);
        send(sock, encrypt, encrypt_len, 0);

        send(sock, &pub_len, sizeof(pub_len), 0);
        send(sock, pub_key, pub_len+1, 0);

        send(sock, msg, MLEN, 0);

        ret = read(sock, &flag, sizeof(flag));

        if (flag) {
            ret = read(sock, buffer, NBYTES);
            buffer[ret] = '\0';
            printf("ERROR: %s\n", buffer);
        }

        free_stuff1:
        BIO_free_all(pri);
        free(pri_key);

    } else { // Verification
        // Keypair
        read(sock, &flag, sizeof(flag));
        if (!flag) {
            ret = read(sock, buffer, NBYTES);
            buffer[ret] = '\0';
            printf("ERROR: %s\n", buffer);
            return flag;
        }

        // Sign
        read(sock, &flag, sizeof(flag));
        if (flag == -1) {
            ret = read(sock, buffer, NBYTES);
            buffer[ret] = '\0';
            printf("ERROR: %s\n", buffer);
            return flag;
        }

        read(sock, &encrypt_len, sizeof(encrypt_len));
        encrypt = malloc(encrypt_len);
        read(sock, encrypt, encrypt_len);

        size_t pub_len;
        read(sock, &pub_len, sizeof(pub_len));
        pub_key = malloc(pub_len+1);
        read(sock, pub_key, pub_len+1);

        //printf("\n%s\n", pub_key);

        read(sock, msg, MLEN);

        //set new RSA key
        pub = BIO_new_mem_buf(pub_key, pub_len);
        keypair = PEM_read_bio_RSAPublicKey(pub, &keypair,NULL, NULL);
        ERR_print_errors_fp(stderr);

        // decrypt
        decrypt = malloc(MLEN);
        int decrypt_len = RSA_public_decrypt(encrypt_len, encrypt, decrypt, keypair, RSA_PKCS1_PADDING);


        if (decrypt_len == -1) {
            ERR_load_crypto_strings();
            ERR_error_string(ERR_get_error(), err);
            fprintf(stderr, "Error decrypting message: %s\n", err);
            flag = 1;

        } else if (decrypt_len != MLEN) {
            strcpy(buffer, "Message lengths don't match");
            flag = 1;

        } else {
            for (j = 0; j < decrypt_len; ++j) {
                if (msg[j] != decrypt[j]) {
                    strcpy(buffer, "Messages don't match");
                    flag = 1;
                    break;
                }
            }
            flag = 0;
        }

        send(sock, &flag, sizeof(flag), 0);

        if (flag) {
            printf("ERROR: %s\n", err);
            send(sock, err, strlen(err), 0);
        }

        free(decrypt);
    }


    RSA_free(keypair);
    BIO_free_all(pub);
    free(pub_key);
    free(encrypt);

    return flag;
}
/****** RSA <- ******/

/****** -> ECDH ******/
// opt = 1: Server; opt = 0: Client
int ecdh(int sock, int opt, unsigned char *ss) {

    int ret;
    int flag = 0;
    unsigned char buffer[NBYTES];

    uint8_t puba[ECC_PUB_KEY_SIZE];
    uint8_t prva[ECC_PRV_KEY_SIZE];
    uint8_t seca[ECC_PUB_KEY_SIZE];
    uint8_t pubb[ECC_PUB_KEY_SIZE];
    uint8_t prvb[ECC_PRV_KEY_SIZE];
    uint8_t secb[ECC_PUB_KEY_SIZE];
    uint32_t i;

    static int initialized = 0;
    if (!initialized) {
        prng_init((0xbad ^ 0xc0ffee ^ 42) | 0xcafebabe | 666);
        initialized = 1;
    }

    bzero(buffer, NBYTES);

    //KeyGen and Desencapsulate (server)
    if (opt) {
        for (i = 0; i < ECC_PRV_KEY_SIZE; ++i)
            prva[i] = prng_next();

        ret = !ecdh_generate_keys(puba, prva);

        send(sock, &ret, sizeof(ret), 0);
        if (ret) {
            flag = 1;
            strcpy(buffer, "Generation the public/private keypair failed (NewHope)");
            printf("ERROR: %s\n", buffer);
            send(sock, buffer, strlen(buffer), 0);
            return flag;
        }

        send(sock, puba, ECC_PUB_KEY_SIZE, 0);

        ret = read(sock, &flag, sizeof(flag));
        if (flag) {
            ret = read(sock, buffer, NBYTES);
            buffer[ret] = '\0';
            printf("ERROR: %s\n", buffer);
            return flag;
        }

        ret = read(sock, pubb, ECC_PUB_KEY_SIZE);

        ecdh_shared_secret(prva, pubb, seca);

        ret = read(sock, &secb, ECC_PUB_KEY_SIZE);

        ret = 0;
        for (i = 0; i < ECC_PUB_KEY_SIZE; ++i) {
            if (seca[i] != secb[i]) {
                ret = 1;
                break;
            }
        }

        send(sock, &ret, sizeof(ret), 0);
        if (ret) {
            flag = 1;
            strcpy(buffer, "Encapsultaion failed");
            send(sock, buffer, strlen(buffer), 0);
            printf("ERROR: %d\n", ret);
            return flag;
        }


    } else { // Encapsulate
        // Keypair
        ret = read(sock, &flag, sizeof(flag));
        if (flag) {
            ret = read(sock, buffer, NBYTES);
            buffer[ret] = '\0';
            printf("ERROR: %s\n", buffer);
            return flag;
        }

        ret = read(sock, puba, ECC_PUB_KEY_SIZE);

        for (i = 0; i < ECC_PRV_KEY_SIZE; ++i)
            prvb[i] = prng_next();
        ret = !ecdh_generate_keys(pubb, prvb);

        send(sock, &ret, sizeof(ret), 0);
        if (ret) {
            flag = 1;
            strcpy(buffer, "Desencapsultaion failed");
            send(sock, buffer, strlen(buffer), 0);
            return flag;
        }

        send(sock, pubb, ECC_PUB_KEY_SIZE, 0);

        ecdh_shared_secret(prvb, puba, secb);

        send(sock, secb, ECC_PUB_KEY_SIZE, 0);

        ret = read(sock, &flag, sizeof(flag));
        if (flag) {
            ret = read(sock, buffer, NBYTES);
            buffer[ret] = '\0';
            return flag;
        }
    }

    return flag;
}
/****** ECDH <- ******/

/****** -> AES ******/
void symmetric_enc_dec(int sock, int flag, unsigned char *k1, unsigned char *k2, unsigned char *msg) {
    int decryptedtext_len;
    /*
      * Buffer for ciphertext. Ensure the buffer is long enough for the
      * ciphertext which may be longer than the plaintext, depending on the
      * algorithm and mode.
    */
    unsigned char ciphertext[BS];
    /* Buffer for the decrypted text */
    //unsigned char decryptedtext[BS];

    bzero(ciphertext, BS);

    // Server
    if (flag) {
        recv_timeout(sock, ciphertext, TW);

        // Decrypt the ciphertext
        decryptedtext_len = decrypt(ciphertext, strlen(ciphertext), k1, k2, msg);
        // Add a NULL terminator. We are expecting printable text
        msg[decryptedtext_len] = '\0';

    } else { // client
        // Encrypt the plaintext (key, iv)
        encrypt(msg, strlen(msg), k1, k2, ciphertext);

        send(sock, ciphertext, strlen(ciphertext), 0);

        // 0.1 seg
        usleep(1000000);
    }

    return;
}
/****** AES <- ******/

void safe_channel(int sock, int flag) {
    unsigned char k1[CRYPTO_BYTES_NH];
    unsigned char k2[CRYPTO_BYTES_NH];

    // File or message
    unsigned char msg[BS];

    bzero(k1, CRYPTO_BYTES_NH);
    bzero(k2, CRYPTO_BYTES_NH);
    bzero(msg, BS);

    // Shared key
    unsigned long long initCycles = rdtsc();

    if (ecdh(sock, flag, k1)) { return; }

    shake256_nh(k2, CRYPTO_BYTES_NH, k1, CRYPTO_BYTES_NH);
    cyclesNH = rdtsc() - initCycles;

    // Client
    if (flag == 0) {
        // Message
        //randombytes(msg, 5);
        strcpy(msg, "Push yourself, because no one else is going to do it for you.");

        printf("Client: %s\n", msg);
    }

    initCycles = rdtsc();
    symmetric_enc_dec(sock, flag, k1, k2, msg);
    cyclesAES = rdtsc() - initCycles;

    // Server
    if (flag) {
        printf("Server: %s\n", msg);
    }
}

/****** -> TLS ******/
void TLS(int sock, char *opt, int opt2, int flag) {
    //opt2 = 0 no sign || opt2 = 1 server cert verify || opt2 = 2 both verify
    unsigned long long initCycles;

    if (opt2 == 0) //no sign
    {
        cyclesDil = 0;
        safe_channel(sock, flag);
    }
    else if (opt2 == 1)//verificacion server cert
    {
        initCycles = rdtsc();
        if (rsa(sock, flag))
        {
            return;
        }
        cyclesDil = rdtsc() - initCycles;
        safe_channel(sock, flag);
    }
    else if (opt2 == 2) // Both
    {
        initCycles = rdtsc();
        if (rsa(sock, flag)) {
            return;
        }
        if (rsa(sock, !flag)) {
            return;
        }
        cyclesDil = rdtsc() - initCycles;
        safe_channel(sock, flag);
    }
}
/****** TLS <- ******/