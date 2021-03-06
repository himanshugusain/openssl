#include "aes-encryptDecrypt.h"

#define RANDOM_NUM_SIZE 32

void errordetail(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int base64encode(const uint8_t *pBuffToEnc, const uint32_t *buffLen, uint8_t *pEncBuff, const uint32_t *pEncBuffLen)
{
    BIO *bio = NULL;
    BIO *b64 = NULL;

    FILE *stream = NULL;
    uint32_t inBufLen = *buffLen;

    stream = fmemopen(pEncBuff, *pEncBuffLen, "w");
    if (NULL == stream)
    {
        printf("failed to open mem\n");
        return 1;
    }

    b64 = BIO_new(BIO_f_base64());
    if (NULL == b64)
    {
        printf("failed to BIO_new\n");
        return 1;
    }

    bio = BIO_new_fp(stream, BIO_NOCLOSE);
    if (NULL == bio)
    {
        printf("failed to BIO_new_fp\n");
        return 1;
    }
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, pBuffToEnc, inBufLen);
    BIO_flush(bio);
    BIO_free_all(bio);
    fclose(stream);
}

int base64decode(uint8_t *pEncBuff, const uint32_t *buffLen, uint8_t *pDecBuff, uint32_t *pDecBuffLen)
{
    BIO *bio = NULL;
    BIO *b64 = NULL;
    int32_t actualRead = 0;
    FILE *stream = NULL;

    uint32_t encBufLen = *buffLen;

    stream = fmemopen(pEncBuff, encBufLen, "r");
    if (NULL == stream)
    {
        printf("failed to open mem\n");
        return 1;
    }

    b64 = BIO_new(BIO_f_base64());
    if (NULL == b64)
    {
        printf("failed to BIO_new\n");
        return 1;
    }

    bio = BIO_new_fp(stream, BIO_NOCLOSE);
    if (NULL == bio)
    {
        printf("failed to BIO_new_fp\n");
        return 1;
    }

    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer

    actualRead = BIO_read(bio, pDecBuff, encBufLen);
    BIO_flush(bio);

    *pDecBuffLen = actualRead;

    BIO_free_all(bio);
    fclose(stream);
}

int generateRandomKey(unsigned char *keyVal, uint32_t keysize)
{
    unsigned char fixedkey[] = "GVkX18gQ9dtSgO0Q9mKeBy03KXfqKVOsI";
    int ret;
    int ranKeylen;

    ret = RAND_bytes(keyVal, keysize);
    if (ret != 1)
    {
        memcpy(keyVal, fixedkey, keysize);
    }

    ranKeylen = strlen(keyVal);

    if (ranKeylen < keysize)
    {
        int i = --ranKeylen;
        while (i < keysize)
        {
            *(keyVal + i) = fixedkey[i];
            i++;
        }
    }
}

int encrypt(const uint8_t *buffToEnc, int lengthPlainBuff, const uint8_t *key,
            const uint8_t *iv, uint8_t *encryptBuff)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        errordetail();
    }

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits 
   * */

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        errordetail();
    }

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */

    if (1 != EVP_EncryptUpdate(ctx, encryptBuff, &len, buffToEnc, lengthPlainBuff))
    {
        errordetail();
    }
    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
    if (1 != EVP_EncryptFinal_ex(ctx, encryptBuff + len, &len))
    {
        errordetail();
    }

    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int decrypt(const uint8_t *encryptBuff, int ciphertext_len, const uint8_t *key,
            const uint8_t *iv, uint8_t *decryptBuff)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        errordetail();
    }

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        errordetail();
    }

    /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
    if (1 != EVP_DecryptUpdate(ctx, decryptBuff, &len, encryptBuff, ciphertext_len))
    {
        errordetail();
    }

    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
    if (1 != EVP_DecryptFinal_ex(ctx, decryptBuff + len, &len))
    {
        errordetail();
    }
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int main(int argc, char *argv[])
{
    uint8_t randomKey[RANDOM_NUM_SIZE + 1] = {0};
    uint8_t *keyPtr = randomKey;
    uint32_t keysize = 32;
    const uint8_t key[] = "SGnliCD0Qp3zvVeGL9BGkBmfBehYyA";
    const uint8_t iv[] = "F4126A5X0BC3E987";
    const uint8_t buffToEnc[] = "Himanshu";

    generateRandomKey(keyPtr, keysize);
    printf("Random key = %s\n", randomKey);

    uint8_t encryptBuff[1024] = {0};
    uint8_t base64EncBuff[1024] = {0};
    uint8_t base64DecBuff[1024] = {0};
    uint8_t decryptBuff[1024] = {0};
    int base64BuffLen = 64;

    int enc_length = encrypt(buffToEnc, (int)strlen(buffToEnc), key, iv, encryptBuff);
    uint32_t encrBuffLen = (int)strlen(encryptBuff);

    base64encode(encryptBuff, &encrBuffLen, base64EncBuff, &base64BuffLen);
    uint32_t encodBuffLen = (int)strlen(base64EncBuff);

    base64decode(base64EncBuff, &encodBuffLen, base64DecBuff, &base64BuffLen);

    decrypt(base64DecBuff, enc_length, key, iv, decryptBuff);
    puts(decryptBuff);
}
