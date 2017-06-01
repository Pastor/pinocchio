#pragma once
#include <stdlib.h>
#ifndef MG_VERSION
#include <mongoose.h>
#endif

#ifndef CS_COMMON_MBUF_H_
#define CS_COMMON_MBUF_H_
#define CS_COMMON_MBUF_MY

#pragma message("Copy from mongoose(https://github.com/cesanta/mongoose)")

#if defined(__cplusplus)
extern "C" {
#endif

#ifndef MBUF_SIZE_MULTIPLIER
#define MBUF_SIZE_MULTIPLIER 1.5
#endif


	struct mbuf;

	void mbuf_init(struct mbuf *mbuf, size_t initial_size);
	void mbuf_free(struct mbuf *mbuf);
	void mbuf_resize(struct mbuf *a, size_t new_size);
	void mbuf_trim(struct mbuf *mbuf);
	size_t mbuf_insert(struct mbuf *a, size_t off, const void *buf, size_t);
	size_t mbuf_append(struct mbuf *a, const void *buf, size_t len);
	void mbuf_remove(struct mbuf *mb, size_t n);

#if defined(__cplusplus)
}
#endif

#endif

#ifndef CS_COMMON_MG_STR_H_
#define CS_COMMON_MG_STR_H_
#define CS_COMMON_MG_STR_MY

#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
	struct mg_str {
		const char *p;
		size_t len;
	};

	struct mg_str mg_mk_str(const char *s);
	struct mg_str mg_mk_str_n(const char *s, size_t len);

#define MG_MK_STR(str_literal) \
  { str_literal, sizeof(str_literal) - 1 }


	int mg_vcmp(const struct mg_str *str2, const char *str1);


	int mg_vcasecmp(const struct mg_str *str2, const char *str1);

	struct mg_str mg_strdup(const struct mg_str s);
	int mg_strcmp(const struct mg_str str1, const struct mg_str str2);
	int mg_strncmp(const struct mg_str str1, const struct mg_str str2, size_t n);

#ifdef __cplusplus
}
#endif
#endif
