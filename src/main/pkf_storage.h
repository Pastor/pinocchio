#pragma once

#if defined(__cplusplus)
extern "C" {
#endif

struct pkf_storage;

enum pkf_storage_type {
	STORAGE_TYPE_FILE, STORAGE_TYPE_MEMORY
};

struct pkf_storage  *pkf_storage_new(const char * const storage_name, enum pkf_storage_type type);

void				 pkf_storage_free(struct pkf_storage **);



#if defined(__cplusplus)
}
#endif

