#include <stdio.h>
#include <gtest/gtest.h>
#include <pkf_storage.h>

TEST(PKF_Storage, New_InMemory_Delete) {
	auto storage = pkf_storage_new(":memory:", "password");
	ASSERT_TRUE(storage != nullptr);
	pkf_storage_free(&storage);
	ASSERT_TRUE(storage == nullptr);
}

TEST(PKF_Storage, New_File_Delete) {
	const char * const db = "file:pkf_storage_tests.db3";
	auto storage = pkf_storage_new(db, "password");
	ASSERT_TRUE(storage != nullptr);
	pkf_storage_free(&storage);
	ASSERT_TRUE(storage == nullptr);
	auto fd = fopen(db, "r");
	EXPECT_TRUE(fd != nullptr);
	fclose(fd);
	remove(db);
}
