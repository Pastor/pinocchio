#include <iostream>
#include <fstream>
#include <sstream>
#include <gtest/gtest.h>

#if defined(CRYPTO_BOTAN)
#if defined(USE_STATIC)
#include <botan_all.h>
#else
#include <botan/version.h>
#include <botan/init.h>
#endif
#elif defined(CRYPTO_OPENSSL)

#include <openssl/opensslv.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>

#endif

int main(int argc, char **argv) {
#if defined(CRYPTO_BOTAN)
    std::cerr << Botan::runtime_version_check(BOTAN_VERSION_MAJOR, BOTAN_VERSION_MINOR, BOTAN_VERSION_PATCH) << std::endl;
#elif defined(CRYPTO_OPENSSL)
    auto p = getenv("OPENSSL_DEBUG_MEMORY");

    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
#	ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#	endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (p != NULL && strcmp(p, "on") == 0) {
        CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL);
        CRYPTO_malloc_debug_init();
    }
    OPENSSL_init();
    ERR_load_CRYPTO_strings();
#else
    if (p != nullptr && strcmp(p, "on") == 0)
        CRYPTO_set_mem_debug(1);
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG, nullptr);
#endif

#endif
    ::testing::InitGoogleTest(&argc, argv);
#if defined(MEMORY_LEAK_DETECT)
    _CrtMemState _checkpoint_start;
    _CrtMemState _checkpoint_end;
    _CrtMemState _checkpoint_diff;

    fprintf(stderr, "Memory leak detection enabled\n");
     _CrtSetDbgFlag ( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF );
     _CrtSetReportMode( _CRT_WARN, _CRTDBG_MODE_FILE );
     _CrtSetReportFile( _CRT_WARN, _CRTDBG_FILE_STDERR );
    _CrtMemCheckpoint(&_checkpoint_start);

#endif
    auto ret = RUN_ALL_TESTS();
#if defined(MEMORY_LEAK_DETECT)
    _CrtMemCheckpoint(&_checkpoint_end);
    if (_CrtMemDifference(&_checkpoint_diff, &_checkpoint_start, &_checkpoint_end))
        _CrtMemDumpStatistics( &_checkpoint_diff );
#endif

#if defined(CRYPTO_OPENSSL)
    CRYPTO_cleanup_all_ex_data();
#endif

    return ret;
}