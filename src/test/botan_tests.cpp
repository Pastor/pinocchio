#include <gtest/gtest.h>

#if defined(USE_STATIC)
#include <botan_all.h>
#else

#include <botan/botan.h>
#include <botan/pipe.h>
#include <botan/basefilt.h>
#include <botan/filters.h>
#include <botan/p11_rsa.h>
#include <botan/x509self.h>
#include <botan/x509path.h>
#include <botan/x509_ca.h>
#include <botan/calendar.h>
#include <botan/pkcs8.h>
#include <botan/pk_algs.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/oids.h>

#endif

#include <fstream>

static void
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

TEST(Botan_BaseProvider, CipherDES) {
    Botan::AutoSeeded_RNG rng;
    std::vector<uint8_t> key = {0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t buf[8];
    uint8_t copy[sizeof(buf)];
    std::unique_ptr<Botan::BlockCipher> cipher(Botan::BlockCipher::create_or_throw("DES", "base"));

    EXPECT_EQ((*cipher).block_size(), 8);
    ASSERT_TRUE((*cipher).valid_keylength(8));

    rng.randomize(key.data(), key.size());
    (*cipher).set_key(key);
    memset(buf, 0, sizeof(buf));
    memcpy(copy, buf, sizeof(buf));
    (*cipher).encrypt(buf);
    (*cipher).decrypt(buf);
    ASSERT_TRUE(memcmp(copy, buf, sizeof(buf)) == 0);
}

TEST(Botan_BaseProvider, Pipe) {
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

struct Key {
    Botan::X509_Certificate certificate;
    std::unique_ptr<Botan::Private_Key> private_key;

    Key(Botan::X509_Certificate _certificate,
        std::unique_ptr<Botan::Private_Key> _private_key)
            : certificate(_certificate), private_key(std::move(_private_key)) {}
};

struct UserKey : public Key {
    Botan::PKCS10_Request request;
    Botan::X509_Certificate signed_certificate;

    UserKey(Botan::X509_Certificate certificate,
            std::unique_ptr<Botan::Private_Key> private_key,
            Botan::PKCS10_Request _request,
            Botan::X509_Certificate _signed_certificate)
            : Key(certificate, std::move(private_key)), request(_request),
              signed_certificate(_signed_certificate) {}
};

struct CA_Support {
    Botan::X509_Certificate certificate;
    std::unique_ptr<Botan::Private_Key> private_key;
    Botan::X509_CA ca;
    Botan::X509_CRL crl;

    Botan::Path_Validation_Restrictions restrictions;
    Botan::Certificate_Store_In_Memory store;

    CA_Support(Botan::X509_Certificate _certificate,
               std::unique_ptr<Botan::Private_Key> _private_key,
               const std::string &hash,
               Botan::RandomNumberGenerator &rand)
            : certificate(_certificate), private_key(std::move(_private_key)), ca(certificate, (*private_key), hash, rand),
              crl(ca.new_crl(rand)), restrictions(false, 80) {
        store.add_crl(crl);
        store.add_certificate(ca.ca_certificate());
    }

    bool validate(const UserKey &key) const {
        auto result = Botan::x509_path_validate(key.signed_certificate, restrictions, store);
        auto known = store.certificate_known(key.certificate);
        return result.successful_validation();
    }

    void revoke(Botan::RandomNumberGenerator &rand, const UserKey &key, Botan::CRL_Code why = Botan::KEY_COMPROMISE) {
        std::vector<Botan::CRL_Entry> revoked;

        revoked.emplace_back(Botan::CRL_Entry(key.signed_certificate, why));
        crl = ca.update_crl(crl, revoked, rand);
        store.add_crl(crl);
    }

    Botan::X509_Certificate sign(Botan::RandomNumberGenerator &rand, Botan::PKCS10_Request &request) {
        auto signed_certificate = ca.sign_request(request, rand,
                                                  from_date(2017, 05, 17),
                                                  from_date(2033, 01, 01));
        store.add_certificate(signed_certificate);
        return signed_certificate;
    }

private:
    Botan::X509_Time from_date(const uint32_t y, const uint32_t m, const uint32_t d) const {
        Botan::calendar_point t(y, m, d, 0, 0, 0);
        return Botan::X509_Time(t.to_std_timepoint());
    }
};

class KeyStorage {
    Botan::AutoSeeded_RNG _rand;
    const std::string _algorithm;
    const std::string _hash;

    std::unique_ptr<CA_Support> _ca;

public:
    KeyStorage(const std::string &algorithm, const std::string &hash)
            : _algorithm(algorithm), _hash(hash) {
        auto key = create_user(CA);
        _ca = std::unique_ptr<CA_Support>(
                new CA_Support(key.certificate, std::move(key.private_key), _hash, _rand));
    }

    enum OptionsType {
        CA,
        USER1,
        USER2
    };

    bool ca_has_contains(const Botan::Key_Constraints &constraints) const {
        return ((*_ca).certificate.constraints() & constraints) == constraints;
    }

    Botan::X509_Cert_Options options(OptionsType type) const {
        Botan::X509_Cert_Options cert_options(to_string(type) + "/RU/CryptoService/Testing");

        cert_options.uri = "http://example.net";
        cert_options.dns = "example.net";
        cert_options.email = "testing@example.net";
        switch (type) {
            case USER1:
                if (_algorithm == "RSA") {
                    cert_options.constraints = Botan::Key_Constraints(Botan::KEY_ENCIPHERMENT);
                } else if (_algorithm == "DSA" || _algorithm == "ECDSA" || _algorithm == "ECGDSA" ||
                           _algorithm == "ECKCDSA") {
                    cert_options.constraints = Botan::Key_Constraints(Botan::DIGITAL_SIGNATURE);
                }
                break;
            case USER2:
                cert_options.add_ex_constraint("PKIX.EmailProtection");
                break;
            case CA:
            default:
                cert_options.CA_key(1);
                break;
        }
        return cert_options;
    }

    std::unique_ptr<Botan::Private_Key> make_private_key() {
        const std::string params = [&] {
            if (_algorithm == "RSA") {
                return "1024";
            }
            if (_algorithm == "GOST-34.10") {
                return "gost_256A";
            }
            if (_algorithm == "ECKCDSA" || _algorithm == "ECGDSA") {
                return "brainpool256r1";
            }
            return "";
        }();
        return Botan::create_private_key(_algorithm, _rand, params);
    }


    UserKey create_user(OptionsType type) {
        auto private_key = make_private_key();
        Botan::X509_Cert_Options opts = options(type);
        auto request = Botan::X509::create_cert_req(opts,
                                                    *private_key,
                                                    _hash,
                                                    _rand);
        auto certificate = Botan::X509::create_self_signed_cert(opts, *private_key, _hash, _rand);
        auto signed_certificate = _ca ? (*_ca).sign(_rand, request) : certificate;
        return UserKey{certificate, std::move(private_key), request, signed_certificate};
    }

    bool validate(const UserKey &key) const {
        return (*_ca).validate(key);
    }

    void revoke(const UserKey &key, Botan::CRL_Code why = Botan::KEY_COMPROMISE) {
        (*_ca).revoke(_rand, key, why);
    }

	Botan::X509_Certificate ca_certificate() {
		return _ca->certificate;
	}

private:
    std::string to_string(OptionsType type) const {
        switch (type) {
            case USER1:
                return "User1";
            case USER2:
                return "User2";
            default:
                return "CA";
        }
    }
};

TEST(Botan_BaseProvider, KeyStorage) {
    KeyStorage storage(/*"RSA"*/"GOST-34.10", "SHA-256");
    const auto constraints = Botan::Key_Constraints(Botan::KEY_CERT_SIGN | Botan::CRL_SIGN);
    ASSERT_TRUE(storage.ca_has_contains(constraints));
    UserKey key1 = storage.create_user(KeyStorage::USER1);
    UserKey key2 = storage.create_user(KeyStorage::USER2);
    ASSERT_TRUE(storage.validate(key1));
    ASSERT_TRUE(storage.validate(key2));
    storage.revoke(key1);
    ASSERT_FALSE(storage.validate(key1));
    storage.revoke(key1, Botan::REMOVE_FROM_CRL);
    ASSERT_TRUE(storage.validate(key1));
	//std::cout << storage.ca_certificate().to_string() << std::endl;
	//std::cout << key1.signed_certificate.to_string() << std::endl;
	//std::cout << key2.signed_certificate.to_string() << std::endl;
}