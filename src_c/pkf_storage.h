#pragma once

#if defined(__cplusplus)
extern "C" {
#endif

	struct pkf_storage;

	struct pkf_storage  *pkf_storage_new(const char * const path, const char * const passwd);

	void	      pkf_storage_free(struct pkf_storage **);


#if defined(__cplusplus)
}
#endif

