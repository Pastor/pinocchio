#include <gtest/gtest.h>
#if defined(USE_STATIC_BOTAN)
#include <botan_all.h>
#else
#include <botan/botan.h>
#include <botan/pipe.h>
#include <botan/basefilt.h>
#include <botan/filters.h>
#endif
#include <fstream>

TEST(BaseProvider, CipherDES) {
    Botan::AutoSeeded_RNG rng;
    std::vector<uint8_t> key = {0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t buf[8];
    uint8_t copy[sizeof(buf)];
    auto cipher(Botan::BlockCipher::create_or_throw("DES", "base"));

    EXPECT_EQ(cipher->block_size(), 8);
    ASSERT_TRUE(cipher->valid_keylength(8));

    rng.randomize(key.data(), key.size());
    cipher->set_key(key);
    memset(buf, 0, sizeof(buf));
    memcpy(copy, buf, sizeof(buf));
    cipher->encrypt(buf);
    cipher->decrypt(buf);
    ASSERT_TRUE(memcmp(copy, buf, sizeof(buf)) == 0);
}

void
process_pipe(Botan::Pipe &pipe, const char *const input, const char *const output) {
    pipe.start_msg();
    Botan::secure_vector<Botan::byte> buffer(4096);
    std::ifstream infile(input, std::ios::binary);
    std::ofstream outfile(output, std::ios::binary);
    while (infile.good()) {
        infile.read(reinterpret_cast<char *>(&buffer[0]), buffer.size());
        const auto got_from_infile = static_cast<const size_t>(infile.gcount());
        pipe.write(&buffer[0], got_from_infile);

        if (infile.eof())
            pipe.end_msg();

        while (pipe.remaining(0) > 0) {
            const auto buffered = pipe.read(&buffer[0], buffer.size(), 0);
            outfile.write(reinterpret_cast<const char *>(&buffer[0]), buffered);
        }
    }
    ASSERT_FALSE(infile.bad() || (infile.fail() && !infile.eof()));
}

TEST(BaseProvider, Pipe) {
    Botan::AutoSeeded_RNG rng;
    Botan::SymmetricKey key(rng, 32);
    Botan::InitializationVector iv(rng, 16);
    Botan::Pipe encrypt(
            new Botan::Fork(
                    Botan::get_cipher("AES-256/CBC/PKCS7", key, iv, Botan::ENCRYPTION),
                    new Botan::Chain(
                            new Botan::Hash_Filter("SHA-256"),
                            new Botan::Hex_Encoder
                    )
            )
    );
    process_pipe(encrypt, "test_data/request_body.txt", "test_data/request_body_encrypted.txt");
    auto original = encrypt.read_all_as_string(1);
    Botan::Pipe decrypt(
            Botan::get_cipher("AES-256/CBC/PKCS7", key, iv, Botan::DECRYPTION),
            new Botan::Fork(
                    nullptr,
                    new Botan::Chain(
                            new Botan::Hash_Filter("SHA-256"),
                            new Botan::Hex_Encoder
                    )
            )
    );
    process_pipe(decrypt, "test_data/request_body_encrypted.txt", "test_data/request_body_decrypted.txt");
    auto decrypted = decrypt.read_all_as_string(1);
    ASSERT_EQ(original, decrypted);
}