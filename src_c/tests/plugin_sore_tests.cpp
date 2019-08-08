#include <gtest/gtest.h>
#include <plugins/plugin_store.h>

#if defined(USE_STATIC)

#include <botan_all.h>

#include <memory>

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


TEST(Plugin_Store, Load) {
    Botan::AutoSeeded_RNG rand;
    auto db = std::shared_ptr<Botan::SQL_Database>(new Botan::Sqlite3_Database(":memory:"));
    auto plugin = std::make_shared<Botan::Plugin_Certificate_Store>(db, "1234567890", rand);
    ASSERT_EQ(plugin->all_subjects().size(), 0);
}
