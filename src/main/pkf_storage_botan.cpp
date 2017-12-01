#include <memory.h>
#include <stdlib.h>
#include <botan_all.h>
#include <sqlite3.h>
#include "pkf_storage.h"


struct PkfStorage {
	std::unique_ptr<Botan::Certificate_Store_In_SQLite> store;
	Botan::AutoSeeded_RNG generator;
public:
	PkfStorage(const std::string& path,
		const std::string& passwd,
		const std::string& prefix = "")
		: generator(), store(
			std::unique_ptr<Botan::Certificate_Store_In_SQLite>(
				new Botan::Certificate_Store_In_SQLite(
					path,
					passwd,
					generator,
					prefix))) {	}
};

struct pkf_storage {
	PkfStorage *stor;
};

static void
pkf_storage_init(struct pkf_storage *storage) {

}

struct pkf_storage  *
pkf_storage_new(const char * const path, const char * const passwd) {
	struct pkf_storage *storage = new pkf_storage;
	storage->stor = new PkfStorage(path, passwd);
	pkf_storage_init(storage);
	return storage;
}

void
pkf_storage_free(struct pkf_storage **storage) {
	if (storage != NULL && (*storage) != NULL) {
		delete (*storage)->stor;
		delete (*storage);
		(*storage) = NULL;
	}
}


