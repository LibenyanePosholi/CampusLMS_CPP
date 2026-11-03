#ifndef STUDENT_H
#define STUDENT_H

#include "DatabaseManager.h"

#include <sqlite3.h>
#include <string>
#include <vector>
#include <stdexcept>

// Represents a course in which a student is enrolled
struct StudentCourse {
    int courseId;
    std::string courseTitle;
};

// Represents an assignment available to a student
struct StudentAssignment {
    int assignmentId;
    int courseId;
    std::string courseTitle;
    std::string deadline;
    double maxMark;
};

// Represents a released student result
struct StudentResult {
    int submissionId;
    int assignmentId;
    std::string courseTitle;
    double moderatedMark;
    std::string feedback;
};

// Student repository
class StudentRepository {
private:
    DatabaseManager& dbManager;

    // Verify that the account belongs to a Student
    bool isStudent(sqlite3* db, int studentId) {
        const char* sql =
            "SELECT id FROM users "
            "WHERE id = ? AND role = 'Student';";

        sqlite3_stmt* stmt = nullptr;

        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Could not verify student.");
        }

        sqlite3_bind_int(stmt, 1, studentId);

        int result = sqlite3_step(stmt);

        sqlite3_finalize(stmt);

        if (result == SQLITE_ROW) {
            return true;
        }

        if (result == SQLITE_DONE) {
            return false;
        }

        throw std::runtime_error("Error verifying student.");
    }

public:
    explicit StudentRepository(DatabaseManager& manager)
        : dbManager(manager) {}

    // 1. View all courses in which the student is enrolled
    std::vector<StudentCourse> getEnrolledCourses(int studentId) {
        sqlite3* db = dbManager.getConnection();

        if (!db) {
            throw std::runtime_error("Database connection unavailable.");
        }

        if (!isStudent(db, studentId)) {
            throw std::runtime_error("Access denied. Student account required.");
        }

        const char* sql =
            "SELECT c.courseid, c.title "
            "FROM enrollments e "
            "JOIN courses c ON e.course_id = c.courseid "
            "WHERE e.student_id = ? "
            "ORDER BY c.title;";

        sqlite3_stmt* stmt = nullptr;

        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Could not retrieve enrolled courses.");
        }

        sqlite3_bind_int(stmt, 1, studentId);

        std::vector<StudentCourse> courses;

        int result;

        while ((result = sqlite3_step(stmt)) == SQLITE_ROW) {
            StudentCourse course;

            course.courseId = sqlite3_column_int(stmt, 0);

            const unsigned char* title = sqlite3_column_text(stmt, 1);
            course.courseTitle = title
                ? reinterpret_cast<const char*>(title) : "";

            courses.push_back(course);
        }

        sqlite3_finalize(stmt);

        if (result != SQLITE_DONE) {
            throw std::runtime_error("Error retrieving enrolled courses.");
        }

        return courses;
    }

    // 2. View assignments for all courses in which the student is enrolled
    std::vector<StudentAssignment> getAssignments(int studentId) {
        sqlite3* db = dbManager.getConnection();

        if (!db) {
            throw std::runtime_error("Database connection unavailable.");
        }

        if (!isStudent(db, studentId)) {
            throw std::runtime_error("Access denied. Student account required.");
        }

        const char* sql =
            "SELECT a.assignmentid, c.courseid, c.title, "
            "a.deadline, a.max_mark "
            "FROM assignments a "
            "JOIN courses c ON a.course_id = c.courseid "
            "JOIN enrollments e ON e.course_id = c.courseid "
            "WHERE e.student_id = ? "
            "ORDER BY a.deadline;";

        sqlite3_stmt* stmt = nullptr;

        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Could not retrieve assignments.");
        }

        sqlite3_bind_int(stmt, 1, studentId);

        std::vector<StudentAssignment> assignments;

        int result;

        while ((result = sqlite3_step(stmt)) == SQLITE_ROW) {
            StudentAssignment assignment;

            assignment.assignmentId = sqlite3_column_int(stmt, 0);
            assignment.courseId = sqlite3_column_int(stmt, 1);

            const unsigned char* title = sqlite3_column_text(stmt, 2);
            assignment.courseTitle = title
                ? reinterpret_cast<const char*>(title) : "";

            const unsigned char* deadline = sqlite3_column_text(stmt, 3);
            assignment.deadline = deadline
                ? reinterpret_cast<const char*>(deadline) : "";

            assignment.maxMark = sqlite3_column_double(stmt, 4);

            assignments.push_back(assignment);
        }

        sqlite3_finalize(stmt);

        if (result != SQLITE_DONE) {
            throw std::runtime_error("Error retrieving assignments.");
        }

        return assignments;
    }

    // 3. Submit an assignment or resubmit it before the deadline
    bool submitAssignment(
        int studentId,
        int assignmentId,
        const std::string& filePath
    ) {
        sqlite3* db = dbManager.getConnection();

        if (!db) {
            throw std::runtime_error("Database connection unavailable.");
        }

        if (!isStudent(db, studentId)) {
            throw std::runtime_error("Access denied. Student account required.");
        }

        if (filePath.empty()) {
            return false;
        }

        // Check that the student is enrolled in the course
        // and that the assignment deadline has not passed.
        const char* checkSql =
            "SELECT a.assignmentid "
            "FROM assignments a "
            "JOIN enrollments e ON e.course_id = a.course_id "
            "WHERE a.assignmentid = ? "
            "AND e.student_id = ? "
            "AND datetime(a.deadline) >= CURRENT_TIMESTAMP;";

        sqlite3_stmt* checkStmt = nullptr;

        if (sqlite3_prepare_v2(db, checkSql, -1, &checkStmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Could not verify assignment deadline.");
        }

        sqlite3_bind_int(checkStmt, 1, assignmentId);
        sqlite3_bind_int(checkStmt, 2, studentId);

        int checkResult = sqlite3_step(checkStmt);

        sqlite3_finalize(checkStmt);

        if (checkResult == SQLITE_DONE) {
            return false;
        }

        if (checkResult != SQLITE_ROW) {
            throw std::runtime_error("Error checking assignment deadline.");
        }

        // Check whether the student has submitted this assignment before.
        const char* existingSql =
            "SELECT submissionid, status "
            "FROM submissions "
            "WHERE assignment_id = ? AND student_id = ? "
            "ORDER BY submissionid DESC LIMIT 1;";

        sqlite3_stmt* existingStmt = nullptr;

        if (sqlite3_prepare_v2(db, existingSql, -1, &existingStmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Could not check existing submission.");
        }

        sqlite3_bind_int(existingStmt, 1, assignmentId);
        sqlite3_bind_int(existingStmt, 2, studentId);

        int existingResult = sqlite3_step(existingStmt);

        if (existingResult == SQLITE_ROW) {
            int submissionId = sqlite3_column_int(existingStmt, 0);

            const unsigned char* statusText =
                sqlite3_column_text(existingStmt, 1);

            std::string status = statusText
                ? reinterpret_cast<const char*>(statusText) : "";

            sqlite3_finalize(existingStmt);

            // Do not allow a released result to be overwritten.
            if (status == "Released") {
                return false;
            }

            // Update the existing submission (resubmission).
            const char* updateSql =
                "UPDATE submissions "
                "SET file_path = ?, "
                "submission_time = CURRENT_TIMESTAMP, "
                "mark = NULL, "
                "moderated_mark = NULL, "
                "feedback = NULL, "
                "status = 'Submitted' "
                "WHERE submissionid = ?;";

            sqlite3_stmt* updateStmt = nullptr;

            if (sqlite3_prepare_v2(db, updateSql, -1, &updateStmt, nullptr) != SQLITE_OK) {
                throw std::runtime_error("Could not prepare resubmission.");
            }

            sqlite3_bind_text(
                updateStmt, 1, filePath.c_str(), -1, SQLITE_TRANSIENT
            );

            sqlite3_bind_int(updateStmt, 2, submissionId);

            int result = sqlite3_step(updateStmt);

            sqlite3_finalize(updateStmt);

            if (result != SQLITE_DONE) {
                throw std::runtime_error("Failed to resubmit assignment.");
            }

            return sqlite3_changes(db) > 0;
        }

        sqlite3_finalize(existingStmt);

        if (existingResult != SQLITE_DONE) {
            throw std::runtime_error("Error checking existing submission.");
        }

        // No previous submission: create a new submission.
        const char* insertSql =
            "INSERT INTO submissions "
            "(assignment_id, student_id, file_path, submission_time, status) "
            "VALUES (?, ?, ?, CURRENT_TIMESTAMP, 'Submitted');";

        sqlite3_stmt* insertStmt = nullptr;

        if (sqlite3_prepare_v2(db, insertSql, -1, &insertStmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Could not prepare assignment submission.");
        }

        sqlite3_bind_int(insertStmt, 1, assignmentId);
        sqlite3_bind_int(insertStmt, 2, studentId);

        sqlite3_bind_text(
            insertStmt, 3, filePath.c_str(), -1, SQLITE_TRANSIENT
        );

        int result = sqlite3_step(insertStmt);

        sqlite3_finalize(insertStmt);

        if (result != SQLITE_DONE) {
            throw std::runtime_error("Failed to submit assignment.");
        }

        return sqlite3_changes(db) > 0;
    }

    // 4. View marks and feedback released by the Head of Department
    std::vector<StudentResult> getReleasedMarks(int studentId) {
        sqlite3* db = dbManager.getConnection();

        if (!db) {
            throw std::runtime_error("Database connection unavailable.");
        }

        if (!isStudent(db, studentId)) {
            throw std::runtime_error("Access denied. Student account required.");
        }

        const char* sql =
            "SELECT s.submissionid, s.assignment_id, "
            "c.title, s.moderated_mark, "
            "COALESCE(s.feedback, '') "
            "FROM submissions s "
            "JOIN assignments a ON s.assignment_id = a.assignmentid "
            "JOIN courses c ON a.course_id = c.courseid "
            "WHERE s.student_id = ? "
            "AND s.status = 'Released' "
            "AND s.moderated_mark IS NOT NULL "
            "ORDER BY c.title, a.assignmentid;";

        sqlite3_stmt* stmt = nullptr;

        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Could not retrieve released marks.");
        }

        sqlite3_bind_int(stmt, 1, studentId);

        std::vector<StudentResult> results;

        int result;

        while ((result = sqlite3_step(stmt)) == SQLITE_ROW) {
            StudentResult studentResult;

            studentResult.submissionId = sqlite3_column_int(stmt, 0);
            studentResult.assignmentId = sqlite3_column_int(stmt, 1);

            const unsigned char* title = sqlite3_column_text(stmt, 2);
            studentResult.courseTitle = title
                ? reinterpret_cast<const char*>(title) : "";

            studentResult.moderatedMark = sqlite3_column_double(stmt, 3);

            const unsigned char* feedback = sqlite3_column_text(stmt, 4);
            studentResult.feedback = feedback
                ? reinterpret_cast<const char*>(feedback) : "";

            results.push_back(studentResult);
        }

        sqlite3_finalize(stmt);

        if (result != SQLITE_DONE) {
            throw std::runtime_error("Error retrieving released marks.");
        }

        return results;
    }
};

#endif

