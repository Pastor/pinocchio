#include <gtest/gtest.h>
#include <pkf_storage.h>

TEST(PKF_Storage, NewDelete) {
	auto storage = pkf_storage_new(nullptr, STORAGE_TYPE_MEMORY);
	ASSERT_TRUE(storage != nullptr);
	pkf_storage_free(&storage);
	ASSERT_TRUE(storage == nullptr);
}