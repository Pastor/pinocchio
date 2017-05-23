#include <gtest/gtest.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

void
handleErrors(void) {
    ERR_print_errors_fp(stderr);
}

int
encrypt(unsigned char *plaintext,
        int plaintext_len,
        unsigned char *key,
        unsigned char *iv,
        unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int
decrypt(unsigned char *ciphertext,
        int ciphertext_len,
        unsigned char *key,
        unsigned char *iv,
        unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

TEST(OpenSSL_BaseProvider_C, SymmetricKey) {
    unsigned char *key = (unsigned char *) "01234567890123456789012345678901";
    unsigned char *iv = (unsigned char *) "0123456789012345";
    unsigned char *plaintext =
            (unsigned char *) "Message";
    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];
    int decryptedtext_len, ciphertext_len;

    ciphertext_len = encrypt(plaintext, (int) strlen((char *) plaintext), key, iv,
                             ciphertext);
    //BIO_dump_fp(stdout, (const char *)plaintext, strlen((char *)plaintext));
    //BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
                                decryptedtext);
    decryptedtext[decryptedtext_len] = '\0';
    ASSERT_STREQ((char *) plaintext, (char *) decryptedtext);
}

int
add_ext(X509 *cert, int nid, char *value) {
    X509_EXTENSION *ex;
    X509V3_CTX ctx;
    /* This sets the 'context' of the extensions. */
    /* No configuration database */
    X509V3_set_ctx_nodb(&ctx);
    /* Issuer and subject certs: both the target since it is self signed,
    * no request and no CRL
    */
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ex)
        return 0;

    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return 1;
}

TEST(OpenSSL_BaseProvider_C, PKI_Generate) {
    BIGNUM *big = BN_new();
    RSA *rsa = RSA_new();
    int ret;

    ret = BN_set_word(big, RSA_F4);
    ASSERT_EQ(ret, 1);
    ret = RSA_generate_key_ex(rsa, 2048, big, NULL);
    ASSERT_EQ(ret, 1);

    {
        auto public_key = RSAPublicKey_dup(rsa);
        auto private_key = RSAPrivateKey_dup(rsa);

        //RSA_print_fp(stdout, public_key, 0);
        //RSA_print_fp(stdout, private_key, 0);

        ASSERT_TRUE(public_key != NULL);
        ASSERT_TRUE(private_key != NULL);

        RSA_free(public_key);
        RSA_free(private_key);
    }

    {
        BIO *private_key = BIO_new(BIO_s_mem());
        BIO *public_key = BIO_new(BIO_s_mem());

        PEM_write_bio_RSAPrivateKey(private_key, rsa, NULL, NULL, 0, NULL, NULL);
        PEM_write_bio_RSAPublicKey(public_key, rsa);

        int private_key_len = BIO_pending(private_key);
        int public_key_len = BIO_pending(public_key);

        char *private_key_text = (char *) malloc((size_t) (private_key_len + 1));
        char *public_key_text = (char *) malloc((size_t) (public_key_len + 1));

        BIO_read(private_key, private_key_text, private_key_len);
        BIO_read(public_key, public_key_text, public_key_len);
        private_key_text[private_key_len] = 0;
        public_key_text[public_key_len] = 0;

        fprintf(stdout, "\n%s\n%s\n", private_key_text, public_key_text);

        free(private_key_text);
        free(public_key_text);
        BIO_free(private_key);
        BIO_free(public_key);
    }

    {
        //PKI
        //http://stackoverflow.com/questions/9406840/rsa-encrypt-decrypt
        //https://wiki.openssl.org/index.php/EVP_Asymmetric_Encryption_and_Decryption_of_an_Envelope
        //https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying
        //https://wiki.openssl.org/index.php/EVP_Key_and_Parameter_Generation
    }

    {
        //x509 Certificate request
        //http://www.codepool.biz/how-to-use-openssl-to-generate-x-509-certificate-request.html
    }

    {
        //x509 Signed Certificate request
        //http://fm4dd.com/openssl/certcreate.htm
    }

    {
        //x509 Certificate extension for signature
        //https://rfc2.ru/5280.rfc
        //http://pro-ldap.ru/tr/zytrax/tech/ssl.html
    }

    {
        //X509 Self-Signed certificate
        //http://fm4dd.com/openssl/certpubkey.htm
        //http://stackoverflow.com/questions/2756553/x509-certificate-verification-in-c
        //https://opensource.apple.com/source/OpenSSL/OpenSSL-22/openssl/demos/x509/mkcert.c

        int serial = 0; //serial number
        int days = 365;

        const EVP_MD *evp_md = EVP_sha256();
        X509_NAME *name = NULL;
        X509 *x = X509_new();
        ASSERT_TRUE(x != NULL);
        EVP_PKEY *pk = EVP_PKEY_new();
        ASSERT_TRUE(pk != NULL);
        ret = EVP_PKEY_assign_RSA(pk, RSAPrivateKey_dup(rsa));
        ASSERT_EQ(ret, 1);

        X509_set_version(x, 3);
        ASN1_INTEGER_set(X509_get_serialNumber(x), serial);
        X509_gmtime_adj(X509_get_notBefore(x), 0);
        X509_gmtime_adj(X509_get_notAfter(x), (long) 60 * 60 * 24 * days);
        X509_set_pubkey(x, pk);

        name = X509_get_subject_name(x);
        X509_NAME_add_entry_by_txt(name, "C",
                                   MBSTRING_ASC, (unsigned char *) "RUS", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "CN",
                                   MBSTRING_ASC, (unsigned char *) "CryptoService", -1, -1, 0);
        X509_set_issuer_name(x, name);

        add_ext(x, NID_basic_constraints, (char *) "critical,CA:TRUE");
        //add_ext(x, NID_basic_constraints, (char *) "critical,CA:FALSE");
        /**
         "digitalSignature",
         "nonRepudiation",
         "keyEncipherment",
         "dataEncipherment",
         "keyAgreement",
         "keyCertSign",
         "cRLSign",
         "encipherOnly",
         "decipherOnly"
        */
        add_ext(x, NID_key_usage, (char *) "critical,keyCertSign,cRLSign");
        //Organization
        //add_ext(x, NID_key_usage, (char *) "critical,keyCertSign,digitalSignature,keyEncipherment");
        //End-User
        //add_ext(x, NID_key_usage, (char *) "critical,digitalSignature,keyEncipherment");


        //Server
        //add_ext(x, NID_ext_key_usage, (char *) "critical,clientAuth,serverAuth,codeSigning,emailProtection");
        //Client
        //add_ext(x, NID_ext_key_usage, (char *) "critical,clientAuth,codeSigning,emailProtection");

        add_ext(x, NID_subject_key_identifier, (char *) "hash");
        add_ext(x, NID_netscape_cert_type, (char *) "sslCA");
        //add_ext(x, NID_netscape_cert_type, (char *) "client, email");
        //add_ext(x, NID_netscape_cert_type, (char *) "server, email");


        add_ext(x, NID_netscape_comment, (char *) "example comment extension");
#ifdef CUSTOM_EXT
        /* Maybe even add our own extension based on existing */
        {
            int nid;
            nid = OBJ_create("1.2.3.4", "MyAlias", "My Test Alias Extension");
            X509V3_EXT_add_alias(nid, NID_netscape_comment);
            add_ext(x, nid, "example comment alias");
        }
#endif
        ret = X509_sign(x, pk, evp_md);
        ASSERT_TRUE(ret > 0);

        {
            BIO *x509 = BIO_new(BIO_s_mem());
            PEM_write_bio_X509(x509, x);
            int x509_len = BIO_pending(x509);
            char *x509_text = (char *) malloc((size_t) (x509_len + 1));
            BIO_read(x509, x509_text, x509_len);
            x509_text[x509_len] = 0;
            //use
            free(x509_text);
            BIO_free(x509);
        }

        X509_print_fp(stdout, x);

        X509_free(x);
        EVP_PKEY_free(pk);
    }

    {
        //Verify
        //http://stackoverflow.com/questions/16291809/programmatically-verify-certificate-chain-using-openssl-api
    }

    BN_free(big);
    RSA_free(rsa);
}
