
#define main CampusLMS_Application_Main
#include "../src/main.cpp"
#undef main

#include <gtest/gtest.h>

// ==========================================
// PHASE 5: UNIT TESTS
// Late submission calculations
// ==========================================

TEST(LateDaysTests, SubmissionBeforeDeadline)
{
    EXPECT_EQ(
        lateDays("2026-01-10 11:59:00",
                 "2026-01-10 12:00:00"),
        0
    );
}

TEST(LateDaysTests, SubmissionExactlyAtDeadline)
{
    EXPECT_EQ(
        lateDays("2026-01-10 12:00:00",
                 "2026-01-10 12:00:00"),
        0
    );
}

TEST(LateDaysTests, SubmissionOneSecondLate)
{
    EXPECT_EQ(
        lateDays("2026-01-10 12:00:01",
                 "2026-01-10 12:00:00"),
        1
    );
}

TEST(LateDaysTests, SubmissionExactlyOneDayLate)
{
    EXPECT_EQ(
        lateDays("2026-01-11 12:00:00",
                 "2026-01-10 12:00:00"),
        1
    );
}

TEST(LateDaysTests, SubmissionOneSecondOverOneDay)
{
    EXPECT_EQ(
        lateDays("2026-01-11 12:00:01",
                 "2026-01-10 12:00:00"),
        2
    );
}

TEST(LateDaysTests, SubmissionExactlyThreeDaysLate)
{
    EXPECT_EQ(
        lateDays("2026-01-13 12:00:00",
                 "2026-01-10 12:00:00"),
        3
    );
}

TEST(LateDaysTests, SubmissionMoreThanThreeDaysLate)
{
    EXPECT_EQ(
        lateDays("2026-01-13 12:00:01",
                 "2026-01-10 12:00:00"),
        4
    );
}

TEST(LateDaysTests, InvalidSubmissionDate)
{
    EXPECT_EQ(
        lateDays("invalid-date",
                 "2026-01-10 12:00:00"),
        0
    );
}

// ==========================================
// PASSWORD HASHING UNIT TESTS
// ==========================================

TEST(PasswordHasherTests, CorrectPasswordIsAccepted)
{
    const auto result = PasswordHasher::create("CampusTest123!");

    EXPECT_TRUE(
        PasswordHasher::verify(
            "CampusTest123!",
            result.first,
            result.second
        )
    );
}

TEST(PasswordHasherTests, IncorrectPasswordIsRejected)
{
    const auto result = PasswordHasher::create("CampusTest123!");

    EXPECT_FALSE(
        PasswordHasher::verify(
            "WrongPassword123!",
            result.first,
            result.second
        )
    );
}

TEST(PasswordHasherTests, DifferentSaltsAreGenerated)
{
    const auto first = PasswordHasher::create("CampusTest123!");
    const auto second = PasswordHasher::create("CampusTest123!");

    EXPECT_NE(first.first, second.first);
    EXPECT_NE(first.second, second.second);
}

TEST(PasswordHasherTests, MalformedSaltIsRejected)
{
    EXPECT_FALSE(
        PasswordHasher::verify(
            "CampusTest123!",
            "invalid-salt",
            "invalid-hash"
        )
    );
}



// ==========================================
// PHASE 5: DATABASE INTEGRATION TESTS
// ==========================================

namespace {

// Creates a separate temporary directory for each integration test.
// The real Campus LMS database is never modified.
class TemporaryDatabaseDirectory {
public:
    TemporaryDatabaseDirectory() {
        const auto timestamp =
            std::chrono::steady_clock::now().time_since_epoch().count();

        path_ = fs::temp_directory_path() /
            ("CampusLMS_Test_" + std::to_string(timestamp));

        fs::create_directories(path_);
    }

    ~TemporaryDatabaseDirectory() {
        std::error_code error;
        fs::remove_all(path_, error);
    }

    fs::path databasePath() const {
        return path_ / "test_database.db";
    }

    fs::path backupPath() const {
        return path_ / "backup_database.db";
    }

private:
    fs::path path_;
};

} // namespace

TEST(DatabaseIntegrationTests, CreatesRequiredTablesAndEnablesForeignKeys) {
    TemporaryDatabaseDirectory temporary;
    Database database(temporary.databasePath());

    auto tables = database.prepare(
        "SELECT COUNT(*) FROM sqlite_master "
        "WHERE type='table' AND name IN "
        "('users','courses','assignments','submissions','audit_logs');"
    );

    ASSERT_EQ(tables.step(), SQLITE_ROW);
    EXPECT_EQ(tables.intColumn(0), 5);

    auto foreignKeys = database.prepare("PRAGMA foreign_keys;");

    ASSERT_EQ(foreignKeys.step(), SQLITE_ROW);
    EXPECT_EQ(foreignKeys.intColumn(0), 1);
}

TEST(DatabaseIntegrationTests, RejectsDuplicateUsernamesIgnoringCase) {
    TemporaryDatabaseDirectory temporary;
    Database database(temporary.databasePath());

    database.exec(
        "INSERT INTO users(username,password_hash,salt,role) "
        "VALUES('CampusStudent','test_hash','test_salt','Student');"
    );

    EXPECT_THROW(
        database.exec(
            "INSERT INTO users(username,password_hash,salt,role) "
            "VALUES('campusstudent','another_hash','another_salt','Student');"
        ),
        std::runtime_error
    );
}

TEST(DatabaseIntegrationTests, RejectsEnrollmentWithNonexistentForeignKeys) {
    TemporaryDatabaseDirectory temporary;
    Database database(temporary.databasePath());

    EXPECT_THROW(
        database.exec(
            "INSERT INTO enrollments(student_id,course_id) "
            "VALUES(999,999);"
        ),
        std::runtime_error
    );
}

TEST(DatabaseIntegrationTests, CreatesAndRestoresDatabaseBackup) {
    TemporaryDatabaseDirectory temporary;
    Database database(temporary.databasePath());

    database.exec(
        "INSERT INTO departments(department_name) "
        "VALUES('Integration Testing');"
    );

    database.backupTo(temporary.backupPath());

    Database backup(temporary.backupPath());

    auto result = backup.prepare(
        "SELECT COUNT(*) FROM departments "
        "WHERE department_name='Integration Testing';"
    );

    ASSERT_EQ(result.step(), SQLITE_ROW);
    EXPECT_EQ(result.intColumn(0), 1);
}
