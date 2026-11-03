#ifndef HEAD_OF_DEPARTMENT_H
#define HEAD_OF_DEPARTMENT_H

#include "DatabaseManager.h"

#include <sqlite3.h>
#include <string>
#include <vector>
#include <optional>
#include <stdexcept>

// Represents a mark being reviewed or awaiting release
struct DepartmentMarkRecord {
    int submissionId;
    int assignmentId;
    int studentId;
    std::string studentUsername;
    std::string courseTitle;
    double lecturerMark;
    double maxMark;
    std::optional<double> moderatedMark;
    std::string feedback;
    std::string status;
};

class HeadOfDepartmentRepository {
private:
    DatabaseManager& dbManager;

    // Verify that the user has the HeadOfDepartment role
    bool isHeadOfDepartment(sqlite3* db, int hodId) {
        const char* sql =
            "SELECT id FROM users "
            "WHERE id = ? AND role = 'HeadOfDepartment';";

        sqlite3_stmt* stmt = nullptr;

        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Could not verify Head of Department.");
        }

        sqlite3_bind_int(stmt, 1, hodId);

        int result = sqlite3_step(stmt);

        sqlite3_finalize(stmt);

        if (result == SQLITE_ROW) {
            return true;
        }

        if (result == SQLITE_DONE) {
            return false;
        }

        throw std::runtime_error("Error verifying Head of Department.");
    }

public:
    explicit HeadOfDepartmentRepository(DatabaseManager& manager)
        : dbManager(manager) {}

    // Retrieve marks awaiting moderation
    std::vector<DepartmentMarkRecord> getMarksForReview(int hodId) {
        sqlite3* db = dbManager.getConnection();

        if (!db) {
            throw std::runtime_error("Database connection unavailable.");
        }

        if (!isHeadOfDepartment(db, hodId)) {
            throw std::runtime_error("Access denied. Head of Department only.");
        }

        const char* sql =
            "SELECT s.submissionid, s.assignment_id, s.student_id, "
            "u.username, c.title, s.mark, a.max_mark, "
            "s.moderated_mark, COALESCE(s.feedback, ''), s.status "
            "FROM submissions s "
            "JOIN users u ON s.student_id = u.id "
            "JOIN assignments a ON s.assignment_id = a.assignmentid "
            "JOIN courses c ON a.course_id = c.courseid "
            "WHERE s.mark IS NOT NULL "
            "AND s.moderated_mark IS NULL "
            "AND s.status <> 'Released' "
            "ORDER BY c.title, u.username;";

        sqlite3_stmt* stmt = nullptr;

        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Could not retrieve marks for review.");
        }

        std::vector<DepartmentMarkRecord> records;

        int result;

        while ((result = sqlite3_step(stmt)) == SQLITE_ROW) {
            DepartmentMarkRecord record{};

            record.submissionId = sqlite3_column_int(stmt, 0);
            record.assignmentId = sqlite3_column_int(stmt, 1);
            record.studentId = sqlite3_column_int(stmt, 2);

            const unsigned char* username = sqlite3_column_text(stmt, 3);
            record.studentUsername = username
                ? reinterpret_cast<const char*>(username) : "";

            const unsigned char* course = sqlite3_column_text(stmt, 4);
            record.courseTitle = course
                ? reinterpret_cast<const char*>(course) : "";

            record.lecturerMark = sqlite3_column_double(stmt, 5);
            record.maxMark = sqlite3_column_double(stmt, 6);

            if (sqlite3_column_type(stmt, 7) != SQLITE_NULL) {
                record.moderatedMark = sqlite3_column_double(stmt, 7);
            }

            const unsigned char* feedback = sqlite3_column_text(stmt, 8);
            record.feedback = feedback
                ? reinterpret_cast<const char*>(feedback) : "";

            const unsigned char* status = sqlite3_column_text(stmt, 9);
            record.status = status
                ? reinterpret_cast<const char*>(status) : "";

            records.push_back(record);
        }

        sqlite3_finalize(stmt);

        if (result != SQLITE_DONE) {
            throw std::runtime_error("Error reading marks for review.");
        }

        return records;
    }

    // Review and moderate a lecturer's mark
    bool moderateMark(
        int submissionId,
        int hodId,
        double moderatedMark
    ) {
        sqlite3* db = dbManager.getConnection();

        if (!db) {
            throw std::runtime_error("Database connection unavailable.");
        }

        if (!isHeadOfDepartment(db, hodId)) {
            throw std::runtime_error("Access denied. Head of Department only.");
        }

        if (moderatedMark < 0) {
            return false;
        }

        const char* sql =
            "UPDATE submissions "
            "SET moderated_mark = ? "
            "WHERE submissionid = ? "
            "AND mark IS NOT NULL "
            "AND status <> 'Released' "
            "AND EXISTS ("
            "SELECT 1 FROM assignments a "
            "WHERE a.assignmentid = submissions.assignment_id "
            "AND ? <= a.max_mark"
            ");";

        sqlite3_stmt* stmt = nullptr;

        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Could not prepare mark moderation.");
        }

        sqlite3_bind_double(stmt, 1, moderatedMark);
        sqlite3_bind_int(stmt, 2, submissionId);
        sqlite3_bind_double(stmt, 3, moderatedMark);

        int result = sqlite3_step(stmt);

        sqlite3_finalize(stmt);

        if (result != SQLITE_DONE) {
            throw std::runtime_error("Failed to moderate mark.");
        }

        return sqlite3_changes(db) > 0;
    }

    // Retrieve moderated marks awaiting release
    std::vector<DepartmentMarkRecord> getApprovedMarksForRelease(int hodId) {
        sqlite3* db = dbManager.getConnection();

        if (!db) {
            throw std::runtime_error("Database connection unavailable.");
        }

        if (!isHeadOfDepartment(db, hodId)) {
            throw std::runtime_error("Access denied. Head of Department only.");
        }

        const char* sql =
            "SELECT s.submissionid, s.assignment_id, s.student_id, "
            "u.username, c.title, s.mark, a.max_mark, "
            "s.moderated_mark, COALESCE(s.feedback, ''), s.status "
            "FROM submissions s "
            "JOIN users u ON s.student_id = u.id "
            "JOIN assignments a ON s.assignment_id = a.assignmentid "
            "JOIN courses c ON a.course_id = c.courseid "
            "WHERE s.moderated_mark IS NOT NULL "
            "AND s.status <> 'Released' "
            "ORDER BY c.title, u.username;";

        sqlite3_stmt* stmt = nullptr;

        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Could not retrieve approved marks.");
        }

        std::vector<DepartmentMarkRecord> records;

        int result;

        while ((result = sqlite3_step(stmt)) == SQLITE_ROW) {
            DepartmentMarkRecord record{};

            record.submissionId = sqlite3_column_int(stmt, 0);
            record.assignmentId = sqlite3_column_int(stmt, 1);
            record.studentId = sqlite3_column_int(stmt, 2);

            const unsigned char* username = sqlite3_column_text(stmt, 3);
            record.studentUsername = username
                ? reinterpret_cast<const char*>(username) : "";

            const unsigned char* course = sqlite3_column_text(stmt, 4);
            record.courseTitle = course
                ? reinterpret_cast<const char*>(course) : "";

            record.lecturerMark = sqlite3_column_double(stmt, 5);
            record.maxMark = sqlite3_column_double(stmt, 6);

            if (sqlite3_column_type(stmt, 7) != SQLITE_NULL) {
                record.moderatedMark = sqlite3_column_double(stmt, 7);
            }

            const unsigned char* feedback = sqlite3_column_text(stmt, 8);
            record.feedback = feedback
                ? reinterpret_cast<const char*>(feedback) : "";

            const unsigned char* status = sqlite3_column_text(stmt, 9);
            record.status = status
                ? reinterpret_cast<const char*>(status) : "";

            records.push_back(record);
        }

        sqlite3_finalize(stmt);

        if (result != SQLITE_DONE) {
            throw std::runtime_error("Error retrieving approved marks.");
        }

        return records;
    }

    // Release an approved mark to the student
    bool releaseApprovedMark(int submissionId, int hodId) {
        sqlite3* db = dbManager.getConnection();

        if (!db) {
            throw std::runtime_error("Database connection unavailable.");
        }

        if (!isHeadOfDepartment(db, hodId)) {
            throw std::runtime_error("Access denied. Head of Department only.");
        }

        const char* sql =
            "UPDATE submissions "
            "SET status = 'Released' "
            "WHERE submissionid = ? "
            "AND moderated_mark IS NOT NULL "
            "AND status <> 'Released';";

        sqlite3_stmt* stmt = nullptr;

        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Could not prepare mark release.");
        }

        sqlite3_bind_int(stmt, 1, submissionId);

        int result = sqlite3_step(stmt);

        sqlite3_finalize(stmt);

        if (result != SQLITE_DONE) {
            throw std::runtime_error("Failed to release approved mark.");
        }

        return sqlite3_changes(db) > 0;
    }
};

#endif
