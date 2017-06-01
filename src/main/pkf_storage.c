#include <memory.h>
#include <stdlib.h>
#include <sqlite3.h>
#include "pkf_storage.h"

struct pkf_storage {
	sqlite3 *db;
};


struct pkf_storage  *
pkf_storage_new(const char * const storage_name, enum pkf_storage_type type) {
	struct pkf_storage *storage = malloc(sizeof(struct pkf_storage));
	if (sqlite3_open((type == STORAGE_TYPE_FILE ? storage_name : ":memory:"), &storage->db) != SQLITE_OK) {
		free(storage);
		return NULL;
	}
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


