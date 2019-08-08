#include <memory.h>
#include <assert.h>
#include "common.h"

#if defined(CS_COMMON_MBUF_MY)

struct mbuf {
	char *buf;
	size_t len;
	size_t size;
};


void mbuf_init(struct mbuf *mbuf, size_t initial_size) {
	mbuf->len = mbuf->size = 0;
	mbuf->buf = NULL;
	mbuf_resize(mbuf, initial_size);
}


void mbuf_free(struct mbuf *mbuf) {
	if (mbuf->buf != NULL) {
		free(mbuf->buf);
		mbuf_init(mbuf, 0);
	}
}

void mbuf_resize(struct mbuf *a, size_t new_size) {
	if (new_size > a->size || (new_size < a->size && new_size >= a->len)) {
		char *buf = (char *)realloc(a->buf, new_size);
		if (buf == NULL && new_size != 0) return;
		a->buf = buf;
		a->size = new_size;
	}
}

void mbuf_trim(struct mbuf *mbuf) {
	mbuf_resize(mbuf, mbuf->len);
}

size_t mbuf_insert(struct mbuf *a, size_t off, const void *buf, size_t len) {
	char *p = NULL;

	assert(a != NULL);
	assert(a->len <= a->size);
	assert(off <= a->len);

	if (~(size_t)0 - (size_t)a->buf < len) return 0;

	if (a->len + len <= a->size) {
		memmove(a->buf + off + len, a->buf + off, a->len - off);
		if (buf != NULL) {
			memcpy(a->buf + off, buf, len);
		}
		a->len += len;
	}
	else {
		size_t new_size = (size_t)((a->len + len) * MBUF_SIZE_MULTIPLIER);
		if ((p = (char *)realloc(a->buf, new_size)) != NULL) {
			a->buf = p;
			memmove(a->buf + off + len, a->buf + off, a->len - off);
			if (buf != NULL) memcpy(a->buf + off, buf, len);
			a->len += len;
			a->size = new_size;
		}
		else {
			len = 0;
		}
	}

	return len;
}


size_t mbuf_append(struct mbuf *a, const void *buf, size_t len) {
	return mbuf_insert(a, a->len, buf, len);
}


void mbuf_remove(struct mbuf *mb, size_t n) {
	if (n > 0 && n <= mb->len) {
		memmove(mb->buf, mb->buf + n, mb->len - n);
		mb->len -= n;
	}
}
#endif

#if defined(CS_COMMON_MG_STR_MY)
static int str_util_lowercase(const char *s) {
	return tolower(*(const unsigned char *)s);
}

int mg_ncasecmp(const char *s1, const char *s2, size_t len) {
	int diff = 0;

	if (len > 0) do {
		diff = str_util_lowercase(s1++) - str_util_lowercase(s2++);
	} while (diff == 0 && s1[-1] != '\0' && --len > 0);

	return diff;
}

int mg_casecmp(const char *s1, const char *s2) {
	return mg_ncasecmp(s1, s2, (size_t)~0);
}

struct mg_str mg_mk_str(const char *s) {
	struct mg_str ret = { s, 0 };
	if (s != NULL) ret.len = strlen(s);
	return ret;
}

struct mg_str mg_mk_str_n(const char *s, size_t len) {
	struct mg_str ret = { s, len };
	return ret;
}

int mg_vcmp(const struct mg_str *str1, const char *str2) {
	size_t n2 = strlen(str2), n1 = str1->len;
	int r = memcmp(str1->p, str2, (n1 < n2) ? n1 : n2);
	if (r == 0) {
		return n1 - n2;
	}
	return r;
}

int mg_vcasecmp(const struct mg_str *str1, const char *str2) {
	size_t n2 = strlen(str2), n1 = str1->len;
	int r = mg_ncasecmp(str1->p, str2, (n1 < n2) ? n1 : n2);
	if (r == 0) {
		return n1 - n2;
	}
	return r;
}

struct mg_str mg_strdup(const struct mg_str s) {
	struct mg_str r = { NULL, 0 };
	if (s.len > 0 && s.p != NULL) {
		r.p = (char *)malloc(s.len);
		if (r.p != NULL) {
			memcpy((char *)r.p, s.p, s.len);
			r.len = s.len;
		}
	}
	return r;
}

int mg_strcmp(const struct mg_str str1, const struct mg_str str2) {
	size_t i = 0;
	while (i < str1.len && i < str2.len) {
		if (str1.p[i] < str2.p[i]) return -1;
		if (str1.p[i] > str2.p[i]) return 1;
		i++;
	}
	if (i < str1.len) return 1;
	if (i < str2.len) return -1;
	return 0;
}

int mg_strncmp(const struct mg_str str1, const struct mg_str str2, size_t n) {
	struct mg_str s1 = str1;
	struct mg_str s2 = str2;

	if (s1.len > n) {
		s1.len = n;
	}
	if (s2.len > n) {
		s2.len = n;
	}
	return mg_strcmp(s1, s2);
}

#endif
