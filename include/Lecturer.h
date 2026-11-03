#ifndef LECTURER_H
#define LECTURER_H

#include "DatabaseManager.h"

#include <sqlite3.h>
#include <string>
#include <vector>
#include <optional>
#include <stdexcept>

// Represents a student submission
struct LecturerSubmission {
    int submissionId;
    int assignmentId;
    int studentId;
    std::string filePath;
    std::string submissionTime;
    std::optional<double> mark;
    std::string feedback;
};

// Lecturer repository
class LecturerRepository {
private:
    DatabaseManager& dbManager;

public:
    explicit LecturerRepository(DatabaseManager& manager)
        : dbManager(manager) {}

    // Create an assignment for a course assigned to the lecturer
    bool createAssignment(
        int courseId,
        int lecturerId,
        const std::string& deadline,
        double maxMark
    ) {
        sqlite3* db = dbManager.getConnection();

        if (!db) {
            throw std::runtime_error("Database connection unavailable.");
        }

        if (maxMark <= 0) {
            return false;
        }

        const char* sql =
            "INSERT INTO assignments (course_id, deadline, max_mark) "
            "SELECT courseid, ?, ? FROM courses "
            "WHERE courseid = ? AND lecturer_id = ?;";

        sqlite3_stmt* stmt = nullptr;

        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Could not prepare assignment creation.");
        }

        sqlite3_bind_text(stmt, 1, deadline.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_double(stmt, 2, maxMark);
        sqlite3_bind_int(stmt, 3, courseId);
        sqlite3_bind_int(stmt, 4, lecturerId);

        int result = sqlite3_step(stmt);

        sqlite3_finalize(stmt);

        if (result != SQLITE_DONE) {
            throw std::runtime_error("Failed to create assignment.");
        }

        return sqlite3_changes(db) > 0;
    }

    // Extend the deadline of an assignment
    bool extendDeadline(
        int assignmentId,
        int lecturerId,
        const std::string& newDeadline
    ) {
        sqlite3* db = dbManager.getConnection();

        if (!db) {
            throw std::runtime_error("Database connection unavailable.");
        }

        const char* sql =
            "UPDATE assignments "
            "SET deadline = ? "
            "WHERE assignmentid = ? "
            "AND EXISTS ("
            "SELECT 1 FROM courses "
            "WHERE courses.courseid = assignments.course_id "
            "AND courses.lecturer_id = ?"
            ");";

        sqlite3_stmt* stmt = nullptr;

        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Could not prepare deadline update.");
        }

        sqlite3_bind_text(stmt, 1, newDeadline.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, assignmentId);
        sqlite3_bind_int(stmt, 3, lecturerId);

        int result = sqlite3_step(stmt);

        sqlite3_finalize(stmt);

        if (result != SQLITE_DONE) {
            throw std::runtime_error("Failed to extend assignment deadline.");
        }

        return sqlite3_changes(db) > 0;
    }

    // Retrieve submissions for an assignment belonging to the lecturer
    std::vector<LecturerSubmission> getSubmissionsToMark(
        int assignmentId,
        int lecturerId
    ) {
        sqlite3* db = dbManager.getConnection();

        if (!db) {
            throw std::runtime_error("Database connection unavailable.");
        }

        const char* sql =
            "SELECT s.submissionid, s.assignment_id, s.student_id, "
            "s.file_path, s.submission_time, s.mark, "
            "COALESCE(s.feedback, '') "
            "FROM submissions s "
            "JOIN assignments a ON s.assignment_id = a.assignmentid "
            "JOIN courses c ON a.course_id = c.courseid "
            "WHERE a.assignmentid = ? AND c.lecturer_id = ? "
            "ORDER BY s.submission_time;";

        sqlite3_stmt* stmt = nullptr;

        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Could not retrieve submissions.");
        }

        sqlite3_bind_int(stmt, 1, assignmentId);
        sqlite3_bind_int(stmt, 2, lecturerId);

        std::vector<LecturerSubmission> submissions;

        int result;

        while ((result = sqlite3_step(stmt)) == SQLITE_ROW) {
            LecturerSubmission submission;

            submission.submissionId = sqlite3_column_int(stmt, 0);
            submission.assignmentId = sqlite3_column_int(stmt, 1);
            submission.studentId = sqlite3_column_int(stmt, 2);

            const unsigned char* filePath = sqlite3_column_text(stmt, 3);
            submission.filePath = filePath
                ? reinterpret_cast<const char*>(filePath) : "";

            const unsigned char* submissionTime = sqlite3_column_text(stmt, 4);
            submission.submissionTime = submissionTime
                ? reinterpret_cast<const char*>(submissionTime) : "";

            if (sqlite3_column_type(stmt, 5) != SQLITE_NULL) {
                submission.mark = sqlite3_column_double(stmt, 5);
            }

            const unsigned char* feedback = sqlite3_column_text(stmt, 6);
            submission.feedback = feedback
                ? reinterpret_cast<const char*>(feedback) : "";

            submissions.push_back(submission);
        }

        sqlite3_finalize(stmt);

        if (result != SQLITE_DONE) {
            throw std::runtime_error("Error reading submissions.");
        }

        return submissions;
    }

    // Mark a submission and provide feedback
    bool markSubmission(
        int submissionId,
        int lecturerId,
        double mark,
        const std::string& feedback
    ) {
        sqlite3* db = dbManager.getConnection();

        if (!db) {
            throw std::runtime_error("Database connection unavailable.");
        }

        if (mark < 0) {
            return false;
        }

        const char* sql =
            "UPDATE submissions "
            "SET mark = ?, feedback = ? "
            "WHERE submissionid = ? "
            "AND EXISTS ("
            "SELECT 1 FROM assignments a "
            "JOIN courses c ON a.course_id = c.courseid "
            "WHERE a.assignmentid = submissions.assignment_id "
            "AND c.lecturer_id = ? "
            "AND ? <= a.max_mark"
            ");";

        sqlite3_stmt* stmt = nullptr;

        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Could not prepare submission marking.");
        }

        sqlite3_bind_double(stmt, 1, mark);
        sqlite3_bind_text(stmt, 2, feedback.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 3, submissionId);
        sqlite3_bind_int(stmt, 4, lecturerId);
        sqlite3_bind_double(stmt, 5, mark);

        int result = sqlite3_step(stmt);

        sqlite3_finalize(stmt);

        if (result != SQLITE_DONE) {
            throw std::runtime_error("Failed to mark submission.");
        }

        return sqlite3_changes(db) > 0;
    }
};

#endif
