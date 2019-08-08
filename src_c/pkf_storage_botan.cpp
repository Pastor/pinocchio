#include <cstdlib>

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

#include "pkf_storage.h"


struct PkfStorage {
    std::unique_ptr<Botan::Certificate_Store_In_SQL> store;
    Botan::AutoSeeded_RNG generator;
public:
    PkfStorage(const std::string &path,
               const std::string &password,
               const std::string &prefix = "")
            : generator(), store(
            std::make_unique<Botan::Certificate_Store_In_SQLite>(
                    path,
                    password,
                    generator,
                    prefix)) {}
};

struct pkf_storage {
    PkfStorage *stor;
};

static void
pkf_storage_init(struct pkf_storage *storage) {
    (void)storage;
}

struct pkf_storage *
pkf_storage_new(const char *const path, const char *const passwd) {
    auto *storage = new pkf_storage;
    storage->stor = new PkfStorage(path, passwd);
    pkf_storage_init(storage);
    return storage;
}

void
pkf_storage_free(struct pkf_storage **storage) {
    if (storage != nullptr && (*storage) != nullptr) {
        delete (*storage)->stor;
        delete (*storage);
        (*storage) = nullptr;
    }
}


