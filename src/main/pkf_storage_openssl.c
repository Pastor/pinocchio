#include <memory.h>
#include <stdlib.h>
#include <sqlite3.h>
#include "pkf_storage.h"

struct pkf_storage {
	sqlite3 *db;
};

static void 
pkf_storage_init(struct pkf_storage *storage) {
	/*struct pkf_storage *db = storage->db;*/
}

struct pkf_storage  *
pkf_storage_new(const char * const storage_name, const char * const password) {
	struct pkf_storage *storage = malloc(sizeof(struct pkf_storage));
	if (sqlite3_open(storage_name, &storage->db) != SQLITE_OK) {
		free(storage);
		return NULL;
	}
	pkf_storage_init(storage);
	return storage;
}

void 
pkf_storage_free(struct pkf_storage **storage) {
	if (storage != NULL && (*storage) != NULL) {
		if ((*storage)->db != NULL) {
			sqlite3_close((*storage)->db);
		}
		free((*storage));
		(*storage) = NULL;
	}
}


