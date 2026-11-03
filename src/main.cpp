#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <ctime>

#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#else
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif

namespace fs = std::filesystem;

namespace {
constexpr int kPbkdf2Iterations = 600000;
constexpr int kSaltBytes = 16;
constexpr int kHashBytes = 32;

std::string trim(const std::string& value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::string toHex(const unsigned char* data, std::size_t length) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(length * 2);
    for (std::size_t i = 0; i < length; ++i) {
        result.push_back(digits[(data[i] >> 4U) & 0x0FU]);
        result.push_back(digits[data[i] & 0x0FU]);
    }
    return result;
}

std::vector<unsigned char> fromHex(const std::string& value) {
    if (value.size() % 2 != 0) throw std::runtime_error("Invalid hexadecimal value.");
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<unsigned char> result(value.size() / 2);
    for (std::size_t i = 0; i < result.size(); ++i) {
        const int hi = nibble(value[i * 2]);
        const int lo = nibble(value[i * 2 + 1]);
        if (hi < 0 || lo < 0) throw std::runtime_error("Invalid hexadecimal value.");
        result[i] = static_cast<unsigned char>((hi << 4) | lo);
    }
    return result;
}

class PasswordHasher {
public:
    static std::pair<std::string, std::string> create(const std::string& password) {
        std::array<unsigned char, kSaltBytes> salt{};
        std::array<unsigned char, kHashBytes> hash{};
        randomBytes(salt.data(), salt.size());
        derive(password, salt.data(), salt.size(), hash.data(), hash.size());
        return {toHex(salt.data(), salt.size()), toHex(hash.data(), hash.size())};
    }

    static bool verify(const std::string& password, const std::string& saltHex,
                       const std::string& expectedHex) {
        try {
            const auto salt = fromHex(saltHex);
            const auto expected = fromHex(expectedHex);
            if (salt.size() != kSaltBytes || expected.size() != kHashBytes) return false;
            std::array<unsigned char, kHashBytes> actual{};
            derive(password, salt.data(), salt.size(), actual.data(), actual.size());
            unsigned char difference = 0;
            for (std::size_t i = 0; i < actual.size(); ++i) {
                difference = static_cast<unsigned char>(difference | (actual[i] ^ expected[i]));
            }
            return difference == 0;
        } catch (...) {
            return false;
        }
    }

private:
    static void randomBytes(unsigned char* output, std::size_t length) {
#ifdef _WIN32
        if (length > static_cast<std::size_t>(std::numeric_limits<ULONG>::max()) ||
            BCryptGenRandom(nullptr, output, static_cast<ULONG>(length),
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
            throw std::runtime_error("Could not generate a secure password salt.");
        }
#else
        if (length > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
            RAND_bytes(output, static_cast<int>(length)) != 1) {
            throw std::runtime_error("Could not generate a secure password salt.");
        }
#endif
    }

    static void derive(const std::string& password, const unsigned char* salt,
                       std::size_t saltLength, unsigned char* output,
                       std::size_t outputLength) {
#ifdef _WIN32
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        if (status < 0) throw std::runtime_error("Could not open the SHA-256 provider.");
        status = BCryptDeriveKeyPBKDF2(
            algorithm,
            reinterpret_cast<PUCHAR>(const_cast<char*>(password.data())),
            static_cast<ULONG>(password.size()),
            const_cast<PUCHAR>(salt), static_cast<ULONG>(saltLength),
            static_cast<ULONGLONG>(kPbkdf2Iterations), output,
            static_cast<ULONG>(outputLength), 0);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        if (status < 0) throw std::runtime_error("Password hashing failed.");
#else
        if (password.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
            saltLength > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
            outputLength > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
            throw std::runtime_error("Password is too long.");
        }
        if (PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
                              salt, static_cast<int>(saltLength), kPbkdf2Iterations,
                              EVP_sha256(), static_cast<int>(outputLength), output) != 1) {
            throw std::runtime_error("Password hashing failed.");
        }
#endif
    }
};

class Statement {
public:
    explicit Statement(sqlite3_stmt* statement) : statement_(statement) {}
    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;
    Statement(Statement&& other) noexcept : statement_(other.statement_) {
        other.statement_ = nullptr;
    }
    ~Statement() { if (statement_) sqlite3_finalize(statement_); }

    void bind(int index, int value) {
        check(sqlite3_bind_int(statement_, index, value));
    }
    void bind(int index, double value) {
        check(sqlite3_bind_double(statement_, index, value));
    }
    void bind(int index, const std::string& value) {
        check(sqlite3_bind_text(statement_, index, value.c_str(),
                                static_cast<int>(value.size()), SQLITE_TRANSIENT));
    }
    void bindNull(int index) { check(sqlite3_bind_null(statement_, index)); }
    int step() { return sqlite3_step(statement_); }
    int intColumn(int column) const { return sqlite3_column_int(statement_, column); }
    double doubleColumn(int column) const { return sqlite3_column_double(statement_, column); }
    bool isNull(int column) const { return sqlite3_column_type(statement_, column) == SQLITE_NULL; }
    std::string textColumn(int column) const {
        const auto* text = sqlite3_column_text(statement_, column);
        return text ? reinterpret_cast<const char*>(text) : std::string{};
    }
private:
    sqlite3_stmt* statement_{};
    void check(int result) {
        if (result != SQLITE_OK) {
            throw std::runtime_error("SQLite bind error: " +
                std::string(sqlite3_errstr(result)));
        }
    }
};

class Database {
public:
    explicit Database(const fs::path& path) {
        fs::create_directories(path.parent_path());
        const int result = sqlite3_open_v2(path.string().c_str(), &db_,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr);
        if (result != SQLITE_OK) {
            const std::string message = db_ ? sqlite3_errmsg(db_) : sqlite3_errstr(result);
            if (db_) sqlite3_close(db_);
            db_ = nullptr;
            throw std::runtime_error("Could not open the local database: " + message);
        }
        sqlite3_busy_timeout(db_, 5000);
        exec("PRAGMA foreign_keys = ON;");
        exec("PRAGMA journal_mode = WAL;");
        exec("PRAGMA synchronous = NORMAL;");
        createSchema();
    }
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;
    ~Database() { if (db_) sqlite3_close(db_); }

    Statement prepare(const std::string& sql) const {
        sqlite3_stmt* statement = nullptr;
        const int result = sqlite3_prepare_v2(db_, sql.c_str(), -1, &statement, nullptr);
        if (result != SQLITE_OK) {
            throw std::runtime_error("SQLite prepare error: " + std::string(sqlite3_errmsg(db_)));
        }
        return Statement(statement);
    }

    void exec(const std::string& sql) const {
        char* error = nullptr;
        const int result = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &error);
        if (result != SQLITE_OK) {
            const std::string message = error ? error : sqlite3_errmsg(db_);
            sqlite3_free(error);
            throw std::runtime_error("SQLite error: " + message);
        }
    }

    int changes() const { return sqlite3_changes(db_); }
    sqlite3* handle() const { return db_; }

    void backupTo(const fs::path& destination) const {
        fs::create_directories(destination.parent_path());
        sqlite3* target = nullptr;
        const int openResult = sqlite3_open_v2(destination.string().c_str(), &target,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
        if (openResult != SQLITE_OK) {
            const std::string message = target ? sqlite3_errmsg(target) : sqlite3_errstr(openResult);
            if (target) sqlite3_close(target);
            throw std::runtime_error("Could not create backup database: " + message);
        }
        sqlite3_backup* backup = sqlite3_backup_init(target, "main", db_, "main");
        if (!backup) {
            const std::string message = sqlite3_errmsg(target);
            sqlite3_close(target);
            throw std::runtime_error("Could not start database backup: " + message);
        }
        int result = SQLITE_OK;
        do {
            result = sqlite3_backup_step(backup, 128);
            if (result == SQLITE_BUSY || result == SQLITE_LOCKED) sqlite3_sleep(100);
        } while (result == SQLITE_OK || result == SQLITE_BUSY || result == SQLITE_LOCKED);
        const int finishResult = sqlite3_backup_finish(backup);
        const int closeResult = sqlite3_close(target);
        if (result != SQLITE_DONE || finishResult != SQLITE_OK || closeResult != SQLITE_OK) {
            throw std::runtime_error("Database backup did not complete successfully.");
        }
    }

private:
    sqlite3* db_{};

    void createSchema() {
        exec(R"SQL(
            CREATE TABLE IF NOT EXISTS departments (
                department_id INTEGER PRIMARY KEY AUTOINCREMENT,
                department_name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                description TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN
                    ('Administrator','Lecturer','HeadOfDepartment','Student')),
                department_id INTEGER,
                active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(department_id) REFERENCES departments(department_id)
                    ON DELETE SET NULL
            );
            CREATE TABLE IF NOT EXISTS courses (
                courseid INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                department_id INTEGER NOT NULL,
                lecturer_id INTEGER,
                FOREIGN KEY(department_id) REFERENCES departments(department_id),
                FOREIGN KEY(lecturer_id) REFERENCES users(id) ON DELETE SET NULL
            );
            CREATE TABLE IF NOT EXISTS enrollments (
                enrollment_id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL,
                course_id INTEGER NOT NULL,
                enrollment_date TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(student_id, course_id),
                FOREIGN KEY(student_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(course_id) REFERENCES courses(courseid) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS assignments (
                assignmentid INTEGER PRIMARY KEY AUTOINCREMENT,
                course_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                deadline TEXT NOT NULL,
                max_mark REAL NOT NULL CHECK(max_mark > 0),
                FOREIGN KEY(course_id) REFERENCES courses(courseid) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS assignment_extensions (
                extension_id INTEGER PRIMARY KEY AUTOINCREMENT,
                assignment_id INTEGER NOT NULL,
                student_id INTEGER NOT NULL,
                new_deadline TEXT NOT NULL,
                reason TEXT NOT NULL,
                granted_by INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(assignment_id, student_id),
                FOREIGN KEY(assignment_id) REFERENCES assignments(assignmentid) ON DELETE CASCADE,
                FOREIGN KEY(student_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(granted_by) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS submissions (
                submissionid INTEGER PRIMARY KEY AUTOINCREMENT,
                assignment_id INTEGER NOT NULL,
                student_id INTEGER NOT NULL,
                file_path TEXT NOT NULL,
                submission_time TEXT NOT NULL,
                mark REAL CHECK(mark IS NULL OR mark >= 0),
                moderated_mark REAL CHECK(moderated_mark IS NULL OR moderated_mark >= 0),
                feedback TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL CHECK(status IN
                    ('Submitted','Late','Marked','Moderated','Released')),
                UNIQUE(assignment_id, student_id),
                FOREIGN KEY(assignment_id) REFERENCES assignments(assignmentid) ON DELETE CASCADE,
                FOREIGN KEY(student_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS audit_logs (
                auditid INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT '',
                timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_courses_lecturer ON courses(lecturer_id);
            CREATE INDEX IF NOT EXISTS idx_enrol_student ON enrollments(student_id);
            CREATE INDEX IF NOT EXISTS idx_assignments_course ON assignments(course_id);
            CREATE INDEX IF NOT EXISTS idx_submissions_student ON submissions(student_id);
            CREATE INDEX IF NOT EXISTS idx_submissions_assignment ON submissions(assignment_id);
        )SQL");

        // Safe additive migrations for databases created by the earlier School LMS.
        ensureColumn("users", "department_id", "INTEGER REFERENCES departments(department_id) ON DELETE SET NULL");
        ensureColumn("users", "active", "INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1))");
        ensureColumn("users", "created_at", "TEXT NOT NULL DEFAULT ''");
        exec("UPDATE users SET created_at=CURRENT_TIMESTAMP WHERE created_at='';");
        ensureColumn("submissions", "feedback", "TEXT NOT NULL DEFAULT ''");
        ensureColumn("assignments", "title", "TEXT NOT NULL DEFAULT 'Assignment'");
        ensureColumn("assignments", "description", "TEXT NOT NULL DEFAULT ''");
        // Legacy schemas did not record a Head of Department's department.
        // Only auto-map when there is exactly one department; never guess across several.
        exec("UPDATE users SET department_id=(SELECT MIN(department_id) FROM departments) "
             "WHERE role='HeadOfDepartment' AND department_id IS NULL "
             "AND (SELECT COUNT(*) FROM departments)=1;");
    }

    void ensureColumn(const std::string& table, const std::string& column,
                      const std::string& definition) {
        auto query = prepare("PRAGMA table_info(" + table + ");");
        while (query.step() == SQLITE_ROW) {
            if (query.textColumn(1) == column) return;
        }
        exec("ALTER TABLE " + table + " ADD COLUMN " + column + " " + definition + ";");
    }
};

struct User {
    int id{};
    std::string username;
    std::string role;
    int departmentId{};
};

struct AssignmentRow {
    int id{};
    int courseId{};
    std::string courseTitle;
    std::string title;
    std::string deadline;
    double maxMark{};
};

struct SubmissionRow {
    int id{};
    int assignmentId{};
    int studentId{};
    std::string studentName;
    std::string courseTitle;
    std::string assignmentTitle;
    std::string filePath;
    std::string submittedAt;
    std::string effectiveDeadline;
    std::string status;
    double maxMark{};
    std::optional<double> mark;
    std::optional<double> moderatedMark;
    std::string feedback;
};

std::string roleName(const std::string& role) {
    if (role == "HeadOfDepartment") return "Head of Department";
    return role;
}

std::optional<std::time_t> parseDateTime(const std::string& input) {
    const std::string value = trim(input);
    std::tm time{};
    std::istringstream stream(value);
    const bool hasSeconds = value.size() == 19;
    stream >> std::get_time(&time, hasSeconds ? "%Y-%m-%d %H:%M:%S" : "%Y-%m-%d %H:%M");
    if (stream.fail()) return std::nullopt;
    stream >> std::ws;
    if (!stream.eof()) return std::nullopt;

    // Reject impossible calendar values rather than allowing mktime to normalise them.
    const int year = time.tm_year;
    const int month = time.tm_mon;
    const int day = time.tm_mday;
    const int hour = time.tm_hour;
    const int minute = time.tm_min;
    const int second = time.tm_sec;
    time.tm_isdst = -1;
    const std::time_t result = std::mktime(&time);
    if (result == static_cast<std::time_t>(-1)) return std::nullopt;
    std::tm checked{};
#ifdef _WIN32
    localtime_s(&checked, &result);
#else
    localtime_r(&result, &checked);
#endif
    if (checked.tm_year != year || checked.tm_mon != month || checked.tm_mday != day ||
        checked.tm_hour != hour || checked.tm_min != minute || checked.tm_sec != second)
        return std::nullopt;
    return result;
}

std::string formatDateTime(std::time_t value) {
    std::tm local{};
#ifdef _WIN32
    localtime_s(&local, &value);
#else
    localtime_r(&value, &local);
#endif
    std::ostringstream output;
    output << std::put_time(&local, "%Y-%m-%d %H:%M:%S");
    return output.str();
}

std::string nowDateTime() { return formatDateTime(std::time(nullptr)); }

int lateDays(const std::string& submittedAt, const std::string& deadline) {
    const auto submitted = parseDateTime(submittedAt);
    const auto due = parseDateTime(deadline);
    if (!submitted || !due || *submitted <= *due) return 0;
    const double secondsLate = std::difftime(*submitted, *due);
    return static_cast<int>(std::ceil(secondsLate / 86400.0));
}

class LmsApplication {
public:
    LmsApplication() : database_(fs::current_path() / "data" / "school_lms.db") {
        fs::create_directories(fs::current_path() / "data" / "uploads");
        seedDemoData();
    }

    void run() {
        std::cout << "\n===========================================\n"
                  << "       CAMPUS LMS - OFFLINE C++ EDITION\n"
                  << "===========================================\n"
                  << "All records are stored on this computer.\n";
        bool running = true;
        while (running) {
            std::cout << "\n1. Login\n2. Register as a student\n3. Exit\n";
            const int choice = askInt("Choose an option: ", 1, 3);
            if (choice == 1) login();
            else if (choice == 2) registerStudent();
            else running = false;
        }
        std::cout << "\nCampus LMS closed. Your local database has been saved.\n";
    }

private:
    Database database_;
    std::optional<User> currentUser_;

    static std::string ask(const std::string& prompt, bool allowEmpty = false) {
        for (;;) {
            std::cout << prompt;
            std::string value;
            if (!std::getline(std::cin, value)) return {};
            value = trim(value);
            if (allowEmpty || !value.empty()) return value;
            std::cout << "This field cannot be empty.\n";
        }
    }

    static std::string askPassword(const std::string& prompt) {
        std::cout << prompt;
        std::string value;
#ifdef _WIN32
        for (;;) {
            const int key = _getch();
            if (key == '\r') { std::cout << "\n"; break; }
            if (key == '\b') {
                if (!value.empty()) { value.pop_back(); std::cout << "\b \b"; }
            } else if (key == 0 || key == 224) {
                (void)_getch();
            } else if (key >= 32 && key <= 126) {
                value.push_back(static_cast<char>(key));
                std::cout << '*';
            }
        }
#else
        termios oldSettings{};
        const bool canHide = (tcgetattr(STDIN_FILENO, &oldSettings) == 0);
        if (canHide) {
            termios newSettings = oldSettings;
            newSettings.c_lflag = static_cast<tcflag_t>(newSettings.c_lflag & ~ECHO);
            (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &newSettings);
        }
        std::getline(std::cin, value);
        if (canHide) {
            (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldSettings);
            std::cout << "\n";
        }
#endif
        return trim(value);
    }

    static int askInt(const std::string& prompt, int minimum, int maximum) {
        for (;;) {
            const std::string value = ask(prompt);
            try {
                std::size_t used = 0;
                const long parsed = std::stol(value, &used);
                if (used == value.size() && parsed >= minimum && parsed <= maximum)
                    return static_cast<int>(parsed);
            } catch (...) {}
            std::cout << "Enter a whole number from " << minimum << " to " << maximum << ".\n";
        }
    }

    static double askDouble(const std::string& prompt, double minimum, double maximum) {
        for (;;) {
            const std::string value = ask(prompt);
            try {
                std::size_t used = 0;
                const double parsed = std::stod(value, &used);
                if (used == value.size() && std::isfinite(parsed) &&
                    parsed >= minimum && parsed <= maximum) return parsed;
            } catch (...) {}
            std::cout << "Enter a valid number from " << minimum << " to " << maximum << ".\n";
        }
    }

    static bool confirm(const std::string& prompt) {
        const std::string answer = ask(prompt + " (y/n): ");
        return answer == "y" || answer == "Y" || answer == "yes" || answer == "YES";
    }

    static void pause() {
        std::cout << "\nPress Enter to continue...";
        std::string ignored;
        std::getline(std::cin, ignored);
    }

    void seedDemoData() {
        auto count = database_.prepare("SELECT COUNT(*) FROM users;");
        if (count.step() != SQLITE_ROW || count.intColumn(0) != 0) return;

        database_.exec("BEGIN IMMEDIATE;");
        try {
            auto dept = database_.prepare(
                "INSERT INTO departments(department_name,description) VALUES(?,?);");
            dept.bind(1, "Computing");
            dept.bind(2, "Computing and software development programmes");
            if (dept.step() != SQLITE_DONE) throw std::runtime_error("Could not create demo department.");
            const int departmentId = static_cast<int>(sqlite3_last_insert_rowid(database_.handle()));

            createUserInternal("admin", "Admin123!", "Administrator", 0);
            createUserInternal("lecturer", "Lecturer123!", "Lecturer", 0);
            createUserInternal("hod", "Hod123!", "HeadOfDepartment", departmentId);
            createUserInternal("student", "Student123!", "Student", 0);

            auto course = database_.prepare(
                "INSERT INTO courses(title,department_id,lecturer_id) VALUES(?,?,?);");
            course.bind(1, "Introduction to Software Engineering");
            course.bind(2, departmentId);
            course.bind(3, 2);
            if (course.step() != SQLITE_DONE) throw std::runtime_error("Could not create demo course.");
            const int courseId = static_cast<int>(sqlite3_last_insert_rowid(database_.handle()));

            auto enrol = database_.prepare(
                "INSERT INTO enrollments(student_id,course_id) VALUES(?,?);");
            enrol.bind(1, 4);
            enrol.bind(2, courseId);
            if (enrol.step() != SQLITE_DONE) throw std::runtime_error("Could not enrol demo student.");

            const auto due = formatDateTime(std::time(nullptr) + 7 * 86400);
            auto assignment = database_.prepare(
                "INSERT INTO assignments(course_id,title,description,deadline,max_mark) "
                "VALUES(?,?,?,?,?);");
            assignment.bind(1, courseId);
            assignment.bind(2, "Software Engineering Fundamentals");
            assignment.bind(3, "Prepare a short report about software development life cycles.");
            assignment.bind(4, due);
            assignment.bind(5, 100.0);
            if (assignment.step() != SQLITE_DONE) throw std::runtime_error("Could not create demo assignment.");
            database_.exec("COMMIT;");

            std::cout << "\nA new local database was created with demonstration accounts.\n"
                      << "Change the demonstration passwords after signing in.\n";
        } catch (...) {
            database_.exec("ROLLBACK;");
            throw;
        }
    }

    void createUserInternal(const std::string& username, const std::string& password,
                            const std::string& role, int departmentId) {
        const auto credentials = PasswordHasher::create(password);
        auto insert = database_.prepare(
            "INSERT INTO users(username,password_hash,salt,role,department_id) VALUES(?,?,?,?,?);");
        insert.bind(1, username);
        insert.bind(2, credentials.second);
        insert.bind(3, credentials.first);
        insert.bind(4, role);
        if (departmentId > 0) insert.bind(5, departmentId); else insert.bindNull(5);
        if (insert.step() != SQLITE_DONE) throw std::runtime_error("Could not create user.");
    }

    std::optional<User> findUserByUsername(const std::string& username) {
        auto query = database_.prepare(
            "SELECT id,username,role,COALESCE(department_id,0),password_hash,salt,active "
            "FROM users WHERE username = ? COLLATE NOCASE;");
        query.bind(1, username);
        if (query.step() != SQLITE_ROW) return std::nullopt;
        return User{query.intColumn(0), query.textColumn(1), query.textColumn(2), query.intColumn(3)};
    }

    bool hasRole(int userId, const std::string& role) {
        auto query = database_.prepare("SELECT 1 FROM users WHERE id=? AND role=? AND active=1;");
        query.bind(1, userId);
        query.bind(2, role);
        return query.step() == SQLITE_ROW;
    }

    void audit(int actorId, const std::string& action, const std::string& reason = {}) {
        auto insert = database_.prepare(
            "INSERT INTO audit_logs(user_id,action,reason) VALUES(?,?,?);");
        insert.bind(1, actorId);
        insert.bind(2, action);
        insert.bind(3, reason);
        if (insert.step() != SQLITE_DONE) throw std::runtime_error("Could not record audit event.");
    }

    void login() {
        const std::string username = ask("Username: ");
        const std::string password = askPassword("Password: ");
        auto query = database_.prepare(
            "SELECT id,username,role,COALESCE(department_id,0),password_hash,salt,active "
            "FROM users WHERE username=? COLLATE NOCASE;");
        query.bind(1, username);
        if (query.step() != SQLITE_ROW || query.intColumn(6) != 1 ||
            !PasswordHasher::verify(password, query.textColumn(5), query.textColumn(4))) {
            std::cout << "Login failed. Check the username and password.\n";
            pause();
            return;
        }
        currentUser_ = User{query.intColumn(0), query.textColumn(1),
                            query.textColumn(2), query.intColumn(3)};
        std::cout << "\nWelcome, " << currentUser_->username << " ("
                  << roleName(currentUser_->role) << ").\n";
        if (currentUser_->role == "Administrator") administratorMenu();
        else if (currentUser_->role == "Lecturer") lecturerMenu();
        else if (currentUser_->role == "HeadOfDepartment") hodMenu();
        else if (currentUser_->role == "Student") studentMenu();
        currentUser_.reset();
    }

    void registerStudent() {
        std::cout << "\n--- STUDENT REGISTRATION ---\n";
        const std::string username = ask("Choose a username: ");
        const std::string password = askPassword("Choose a password (at least 8 characters): ");
        if (password.size() < 8) {
            std::cout << "Password must contain at least 8 characters.\n";
            pause();
            return;
        }
        try {
            createUserInternal(username, password, "Student", 0);
            std::cout << "Student account created. An Administrator must enrol the account in courses.\n";
        } catch (const std::exception& error) {
            std::cout << "Registration failed: " << error.what() << "\n";
        }
        pause();
    }

    void changePassword() {
        const std::string currentPassword = askPassword("Current password: ");
        auto query = database_.prepare("SELECT password_hash,salt FROM users WHERE id=?;");
        query.bind(1, currentUser_->id);
        if (query.step() != SQLITE_ROW ||
            !PasswordHasher::verify(currentPassword, query.textColumn(1), query.textColumn(0))) {
            std::cout << "Current password did not match.\n";
            pause();
            return;
        }
        const std::string newPassword = askPassword("New password (at least 8 characters): ");
        if (newPassword.size() < 8) {
            std::cout << "Password must contain at least 8 characters.\n";
            pause();
            return;
        }
        const auto credentials = PasswordHasher::create(newPassword);
        auto update = database_.prepare("UPDATE users SET password_hash=?,salt=? WHERE id=?;");
        update.bind(1, credentials.second);
        update.bind(2, credentials.first);
        update.bind(3, currentUser_->id);
        if (update.step() != SQLITE_DONE) throw std::runtime_error("Could not update password.");
        audit(currentUser_->id, "Changed account password");
        std::cout << "Password changed successfully.\n";
        pause();
    }

    void administratorMenu() {
        bool active = true;
        while (active) {
            std::cout << "\n========== ADMINISTRATOR DASHBOARD ==========\n"
                      << "1. View users\n2. Create user account\n3. Departments\n"
                      << "4. Courses\n5. Assign lecturer to course\n6. Enrol student\n"
                      << "7. View course enrolments\n8. View audit log\n"
                      << "9. Back up local data\n10. Change password\n"
                      << "11. Assign Head of Department to a department\n12. Logout\n";
            const int choice = askInt("Choose an option: ", 1, 12);
            try {
                switch (choice) {
                    case 1: viewUsers(); break;
                    case 2: createManagedUser(); break;
                    case 3: departmentMenu(); break;
                    case 4: courseMenu(); break;
                    case 5: assignLecturer(); break;
                    case 6: enrolStudent(); break;
                    case 7: viewEnrolments(); break;
                    case 8: viewAuditLog(); break;
                    case 9: backupData(); break;
                    case 10: changePassword(); break;
                    case 11: assignHeadOfDepartment(); break;
                    case 12: active = false; break;
                }
            } catch (const std::exception& error) {
                std::cout << "Operation failed: " << error.what() << "\n";
                pause();
            }
        }
    }

    void viewUsers() {
        auto query = database_.prepare(
            "SELECT id,username,role,COALESCE(department_name,'-'),active "
            "FROM users LEFT JOIN departments USING(department_id) ORDER BY id;");
        std::cout << "\nID | USERNAME | ROLE | DEPARTMENT | ACTIVE\n";
        std::cout << "-----------------------------------------------\n";
        while (query.step() == SQLITE_ROW) {
            std::cout << query.intColumn(0) << " | " << query.textColumn(1) << " | "
                      << roleName(query.textColumn(2)) << " | " << query.textColumn(3)
                      << " | " << (query.intColumn(4) ? "Yes" : "No") << "\n";
        }
        pause();
    }

    void createManagedUser() {
        std::cout << "\n--- CREATE USER ---\n1. Lecturer\n2. Head of Department\n3. Student\n";
        const int roleChoice = askInt("Role: ", 1, 3);
        const std::string role = roleChoice == 1 ? "Lecturer" :
            (roleChoice == 2 ? "HeadOfDepartment" : "Student");
        const std::string username = ask("Username: ");
        const std::string password = askPassword("Temporary password (at least 8 characters): ");
        if (password.size() < 8) throw std::runtime_error("Password must contain at least 8 characters.");
        int departmentId = 0;
        if (role == "HeadOfDepartment") {
            listDepartments();
            departmentId = askInt("Department ID for this Head of Department: ", 1, 1000000);
            auto check = database_.prepare("SELECT 1 FROM departments WHERE department_id=?;");
            check.bind(1, departmentId);
            if (check.step() != SQLITE_ROW) throw std::runtime_error("Department not found.");
        }
        createUserInternal(username, password, role, departmentId);
        audit(currentUser_->id, "Created user " + username, role);
        std::cout << "Account created. The user should change the temporary password after login.\n";
        pause();
    }

    void assignHeadOfDepartment() {
        auto hods = database_.prepare(
            "SELECT id,username,COALESCE(department_id,0) FROM users "
            "WHERE role='HeadOfDepartment' AND active=1 ORDER BY id;");
        std::cout << "\nHEADS OF DEPARTMENT\nID | USERNAME | CURRENT DEPARTMENT ID\n";
        while (hods.step() == SQLITE_ROW)
            std::cout << hods.intColumn(0) << " | " << hods.textColumn(1)
                      << " | " << hods.intColumn(2) << "\n";
        const int hodId = askInt("Head of Department user ID: ", 1, 1000000);
        auto verify = database_.prepare(
            "SELECT 1 FROM users WHERE id=? AND role='HeadOfDepartment' AND active=1;");
        verify.bind(1, hodId);
        if (verify.step() != SQLITE_ROW) throw std::runtime_error("User is not an active Head of Department.");
        listDepartments();
        const int departmentId = askInt("Department ID to assign: ", 1, 1000000);
        auto update = database_.prepare("UPDATE users SET department_id=? WHERE id=?;");
        update.bind(1, departmentId);
        update.bind(2, hodId);
        if (update.step() != SQLITE_DONE || database_.changes() != 1)
            throw std::runtime_error("Could not assign the department. Check the department ID.");
        auto departmentCheck = database_.prepare("SELECT 1 FROM departments WHERE department_id=?;");
        departmentCheck.bind(1, departmentId);
        if (departmentCheck.step() != SQLITE_ROW)
            throw std::runtime_error("Department not found; assignment was not valid.");
        audit(currentUser_->id, "Assigned Head of Department to department",
              "HoD user " + std::to_string(hodId) + "; department " + std::to_string(departmentId));
        std::cout << "Head of Department's department assignment saved.\n";
        pause();
    }

    void departmentMenu() {
        std::cout << "\n--- DEPARTMENTS ---\n1. View departments\n2. Add department\n";
        const int choice = askInt("Choose an option: ", 1, 2);
        if (choice == 1) listDepartments();
        else {
            const auto name = ask("Department name: ");
            const auto description = ask("Description: ", true);
            auto insert = database_.prepare(
                "INSERT INTO departments(department_name,description) VALUES(?,?);");
            insert.bind(1, name);
            insert.bind(2, description);
            if (insert.step() != SQLITE_DONE) throw std::runtime_error("Could not add department.");
            audit(currentUser_->id, "Added department " + name);
            std::cout << "Department added.\n";
        }
        pause();
    }

    void listDepartments() {
        auto query = database_.prepare("SELECT department_id,department_name,description FROM departments ORDER BY department_id;");
        std::cout << "\nID | DEPARTMENT | DESCRIPTION\n";
        while (query.step() == SQLITE_ROW) {
            std::cout << query.intColumn(0) << " | " << query.textColumn(1)
                      << " | " << query.textColumn(2) << "\n";
        }
    }

    void courseMenu() {
        std::cout << "\n--- COURSES ---\n1. View courses\n2. Add course\n";
        const int choice = askInt("Choose an option: ", 1, 2);
        if (choice == 1) listCourses();
        else {
            const auto title = ask("Course title: ");
            listDepartments();
            const int departmentId = askInt("Department ID: ", 1, 1000000);
            auto departmentCheck = database_.prepare("SELECT 1 FROM departments WHERE department_id=?;");
            departmentCheck.bind(1, departmentId);
            if (departmentCheck.step() != SQLITE_ROW) throw std::runtime_error("Department not found.");
            auto insert = database_.prepare("INSERT INTO courses(title,department_id) VALUES(?,?);");
            insert.bind(1, title);
            insert.bind(2, departmentId);
            if (insert.step() != SQLITE_DONE) throw std::runtime_error("Could not add course. Check the department ID.");
            audit(currentUser_->id, "Added course " + title);
            std::cout << "Course added.\n";
        }
        pause();
    }

    void listCourses() {
        auto query = database_.prepare(
            "SELECT c.courseid,c.title,d.department_name,COALESCE(u.username,'Unassigned') "
            "FROM courses c JOIN departments d ON d.department_id=c.department_id "
            "LEFT JOIN users u ON u.id=c.lecturer_id ORDER BY c.courseid;");
        std::cout << "\nID | COURSE | DEPARTMENT | LECTURER\n";
        while (query.step() == SQLITE_ROW) {
            std::cout << query.intColumn(0) << " | " << query.textColumn(1) << " | "
                      << query.textColumn(2) << " | " << query.textColumn(3) << "\n";
        }
    }

    void assignLecturer() {
        listCourses();
        const int courseId = askInt("Course ID: ", 1, 1000000);
        auto lecturers = database_.prepare("SELECT id,username FROM users WHERE role='Lecturer' AND active=1 ORDER BY id;");
        std::cout << "\nLECTURERS\n";
        while (lecturers.step() == SQLITE_ROW)
            std::cout << lecturers.intColumn(0) << " | " << lecturers.textColumn(1) << "\n";
        const int lecturerId = askInt("Lecturer user ID: ", 1, 1000000);
        auto verify = database_.prepare("SELECT 1 FROM users WHERE id=? AND role='Lecturer' AND active=1;");
        verify.bind(1, lecturerId);
        if (verify.step() != SQLITE_ROW) throw std::runtime_error("Selected user is not an active Lecturer.");
        auto update = database_.prepare("UPDATE courses SET lecturer_id=? WHERE courseid=?;");
        update.bind(1, lecturerId);
        update.bind(2, courseId);
        if (update.step() != SQLITE_DONE || database_.changes() != 1)
            throw std::runtime_error("Could not assign lecturer. Check both IDs.");
        audit(currentUser_->id, "Assigned lecturer " + std::to_string(lecturerId) +
              " to course " + std::to_string(courseId));
        std::cout << "Lecturer assigned.\n";
        pause();
    }

    void enrolStudent() {
        auto students = database_.prepare("SELECT id,username FROM users WHERE role='Student' AND active=1 ORDER BY id;");
        std::cout << "\nSTUDENTS\n";
        while (students.step() == SQLITE_ROW)
            std::cout << students.intColumn(0) << " | " << students.textColumn(1) << "\n";
        const int studentId = askInt("Student user ID: ", 1, 1000000);
        auto studentCheck = database_.prepare(
            "SELECT 1 FROM users WHERE id=? AND role='Student' AND active=1;");
        studentCheck.bind(1, studentId);
        if (studentCheck.step() != SQLITE_ROW) throw std::runtime_error("Selected user is not an active Student.");
        listCourses();
        const int courseId = askInt("Course ID: ", 1, 1000000);
        auto courseCheck = database_.prepare("SELECT 1 FROM courses WHERE courseid=?;");
        courseCheck.bind(1, courseId);
        if (courseCheck.step() != SQLITE_ROW) throw std::runtime_error("Course not found.");
        auto insert = database_.prepare("INSERT INTO enrollments(student_id,course_id) VALUES(?,?);");
        insert.bind(1, studentId);
        insert.bind(2, courseId);
        if (insert.step() != SQLITE_DONE) throw std::runtime_error("Enrolment failed. Check IDs or existing enrolment.");
        audit(currentUser_->id, "Enrolled student " + std::to_string(studentId) +
              " in course " + std::to_string(courseId));
        std::cout << "Student enrolled.\n";
        pause();
    }

    void viewEnrolments() {
        listCourses();
        const int courseId = askInt("Course ID to inspect: ", 1, 1000000);
        auto query = database_.prepare(
            "SELECT u.id,u.username,e.enrollment_date FROM enrollments e "
            "JOIN users u ON u.id=e.student_id WHERE e.course_id=? ORDER BY u.username;");
        query.bind(1, courseId);
        std::cout << "\nENROLLED STUDENTS\n";
        while (query.step() == SQLITE_ROW)
            std::cout << query.intColumn(0) << " | " << query.textColumn(1)
                      << " | " << query.textColumn(2) << "\n";
        pause();
    }

    void viewAuditLog() {
        auto query = database_.prepare(
            "SELECT a.timestamp,u.username,a.action,a.reason FROM audit_logs a "
            "JOIN users u ON u.id=a.user_id ORDER BY a.auditid DESC LIMIT 100;");
        std::cout << "\nRECENT AUDIT EVENTS (up to 100)\n";
        while (query.step() == SQLITE_ROW)
            std::cout << query.textColumn(0) << " | " << query.textColumn(1)
                      << " | " << query.textColumn(2) << " | " << query.textColumn(3) << "\n";
        pause();
    }

    void lecturerMenu() {
        bool active = true;
        while (active) {
            std::cout << "\n============== LECTURER DASHBOARD ==============\n"
                      << "1. View assigned courses and assignments\n"
                      << "2. Create assignment\n3. View and mark submissions\n"
                      << "4. Grant individual deadline extension\n"
                      << "5. Change password\n6. Logout\n";
            const int choice = askInt("Choose an option: ", 1, 6);
            try {
                switch (choice) {
                    case 1: lecturerCourses(); break;
                    case 2: createAssignment(); break;
                    case 3: markSubmissions(); break;
                    case 4: grantExtension(); break;
                    case 5: changePassword(); break;
                    case 6: active = false; break;
                }
            } catch (const std::exception& error) {
                std::cout << "Operation failed: " << error.what() << "\n";
                pause();
            }
        }
    }

    void lecturerCourses() {
        auto query = database_.prepare(
            "SELECT c.courseid,c.title,d.department_name FROM courses c "
            "JOIN departments d ON d.department_id=c.department_id WHERE c.lecturer_id=?;");
        query.bind(1, currentUser_->id);
        std::cout << "\nASSIGNED COURSES\n";
        while (query.step() == SQLITE_ROW)
            std::cout << query.intColumn(0) << " | " << query.textColumn(1)
                      << " | " << query.textColumn(2) << "\n";
        auto assignments = database_.prepare(
            "SELECT a.assignmentid,a.title,c.title,a.deadline,a.max_mark "
            "FROM assignments a JOIN courses c ON c.courseid=a.course_id "
            "WHERE c.lecturer_id=? ORDER BY a.assignmentid;");
        assignments.bind(1, currentUser_->id);
        std::cout << "\nASSIGNMENTS\n";
        while (assignments.step() == SQLITE_ROW)
            std::cout << "#" << assignments.intColumn(0) << " | " << assignments.textColumn(1)
                      << " | " << assignments.textColumn(2) << " | due "
                      << assignments.textColumn(3) << " | max " << assignments.doubleColumn(4) << "\n";
        pause();
    }

    void createAssignment() {
        lecturerCourses();
        const int courseId = askInt("Course ID: ", 1, 1000000);
        requireLecturerOwnsCourse(courseId);
        const std::string title = ask("Assignment title: ");
        const std::string description = ask("Description: ", true);
        const std::string deadlineInput = ask("Deadline (YYYY-MM-DD HH:MM): ");
        const auto deadline = parseDateTime(deadlineInput);
        if (!deadline) throw std::runtime_error("Deadline format is invalid.");
        const std::string deadlineValue = formatDateTime(*deadline);
        const double maxMark = askDouble("Maximum mark: ", 0.01, 1000000.0);
        auto insert = database_.prepare(
            "INSERT INTO assignments(course_id,title,description,deadline,max_mark) VALUES(?,?,?,?,?);");
        insert.bind(1, courseId);
        insert.bind(2, title);
        insert.bind(3, description);
        insert.bind(4, deadlineValue);
        insert.bind(5, maxMark);
        if (insert.step() != SQLITE_DONE) throw std::runtime_error("Could not create assignment.");
        audit(currentUser_->id, "Created assignment " + title, "Course " + std::to_string(courseId));
        std::cout << "Assignment created.\n";
        pause();
    }

    void requireLecturerOwnsCourse(int courseId) {
        auto query = database_.prepare("SELECT 1 FROM courses WHERE courseid=? AND lecturer_id=?;");
        query.bind(1, courseId);
        query.bind(2, currentUser_->id);
        if (query.step() != SQLITE_ROW) throw std::runtime_error("This course is not assigned to your account.");
    }

    std::vector<SubmissionRow> lecturerSubmissions(bool onlyMarked = false) {
        const std::string condition = onlyMarked ? "AND s.status='Marked'" : "AND s.status IN ('Submitted','Late')";
        auto query = database_.prepare(
            "SELECT s.submissionid,s.assignment_id,s.student_id,u.username,c.title,a.title,"
            "s.file_path,s.submission_time,COALESCE(x.new_deadline,a.deadline),s.status,"
            "a.max_mark,s.mark,s.moderated_mark,s.feedback "
            "FROM submissions s JOIN users u ON u.id=s.student_id "
            "JOIN assignments a ON a.assignmentid=s.assignment_id "
            "JOIN courses c ON c.courseid=a.course_id "
            "LEFT JOIN assignment_extensions x ON x.assignment_id=a.assignmentid AND x.student_id=s.student_id "
            "WHERE c.lecturer_id=? " + condition + " ORDER BY s.submission_time;");
        query.bind(1, currentUser_->id);
        std::vector<SubmissionRow> rows;
        while (query.step() == SQLITE_ROW) {
            SubmissionRow row;
            row.id = query.intColumn(0); row.assignmentId = query.intColumn(1);
            row.studentId = query.intColumn(2); row.studentName = query.textColumn(3);
            row.courseTitle = query.textColumn(4); row.assignmentTitle = query.textColumn(5);
            row.filePath = query.textColumn(6); row.submittedAt = query.textColumn(7);
            row.effectiveDeadline = query.textColumn(8); row.status = query.textColumn(9);
            row.maxMark = query.doubleColumn(10);
            if (!query.isNull(11)) row.mark = query.doubleColumn(11);
            if (!query.isNull(12)) row.moderatedMark = query.doubleColumn(12);
            row.feedback = query.textColumn(13);
            rows.push_back(std::move(row));
        }
        return rows;
    }

    void markSubmissions() {
        const auto rows = lecturerSubmissions();
        if (rows.empty()) {
            std::cout << "\nThere are no submissions waiting to be marked.\n";
            pause(); return;
        }
        printSubmissionRows(rows);
        const int submissionId = askInt("Submission ID to mark: ", 1, 1000000);
        const auto found = std::find_if(rows.begin(), rows.end(), [submissionId](const auto& row) {
            return row.id == submissionId;
        });
        if (found == rows.end()) throw std::runtime_error("Submission not found in your assigned courses.");
        const double enteredMark = askDouble("Mark awarded before late penalty: ", 0.0, found->maxMark);
        const std::string feedback = ask("Feedback for the student: ", true);
        const int daysLate = lateDays(found->submittedAt, found->effectiveDeadline);
        double finalMark = enteredMark;
        double deduction = 0.0;
        if (daysLate > 3) finalMark = 0.0;
        else if (daysLate > 0) {
            deduction = found->maxMark * 0.10 * static_cast<double>(daysLate);
            finalMark = std::max(0.0, enteredMark - deduction);
        }
        std::cout << "Late days counted: " << daysLate << "\n"
                  << "Late deduction: " << deduction << "\n"
                  << "Final mark to store: " << finalMark << " / " << found->maxMark << "\n";
        if (!confirm("Save this mark and feedback?")) return;
        auto update = database_.prepare(
            "UPDATE submissions SET mark=?,feedback=?,status='Marked' "
            "WHERE submissionid=? AND status IN ('Submitted','Late');");
        update.bind(1, finalMark); update.bind(2, feedback); update.bind(3, submissionId);
        if (update.step() != SQLITE_DONE || database_.changes() != 1)
            throw std::runtime_error("The submission could not be marked. It may have changed already.");
        std::ostringstream reason;
        reason << "Submission " << submissionId << "; entered mark " << enteredMark
               << "; late days " << daysLate << "; deduction " << deduction
               << "; final mark " << finalMark;
        audit(currentUser_->id, "Marked submission", reason.str());
        std::cout << "Submission marked. It is now waiting for HoD moderation.\n";
        pause();
    }

    void grantExtension() {
        lecturerCourses();
        const int assignmentId = askInt("Assignment ID: ", 1, 1000000);
        auto assignment = database_.prepare(
            "SELECT a.deadline,a.course_id FROM assignments a WHERE a.assignmentid=?;");
        assignment.bind(1, assignmentId);
        if (assignment.step() != SQLITE_ROW) throw std::runtime_error("Assignment not found.");
        const int courseId = assignment.intColumn(1);
        requireLecturerOwnsCourse(courseId);
        auto students = database_.prepare(
            "SELECT u.id,u.username FROM enrollments e JOIN users u ON u.id=e.student_id "
            "WHERE e.course_id=? AND u.role='Student' ORDER BY u.username;");
        students.bind(1, courseId);
        std::cout << "\nENROLLED STUDENTS\n";
        while (students.step() == SQLITE_ROW)
            std::cout << students.intColumn(0) << " | " << students.textColumn(1) << "\n";
        const int studentId = askInt("Student ID: ", 1, 1000000);
        auto studentCheck = database_.prepare(
            "SELECT 1 FROM users WHERE id=? AND role='Student' AND active=1;");
        studentCheck.bind(1, studentId);
        if (studentCheck.step() != SQLITE_ROW) throw std::runtime_error("Selected user is not an active Student.");
        auto enrolled = database_.prepare("SELECT 1 FROM enrollments WHERE course_id=? AND student_id=?;");
        enrolled.bind(1, courseId); enrolled.bind(2, studentId);
        if (enrolled.step() != SQLITE_ROW) throw std::runtime_error("Student is not enrolled in this course.");
        auto currentDeadlineQuery = database_.prepare(
            "SELECT COALESCE(x.new_deadline,a.deadline) FROM assignments a "
            "LEFT JOIN assignment_extensions x ON x.assignment_id=a.assignmentid "
            "AND x.student_id=? WHERE a.assignmentid=?;");
        currentDeadlineQuery.bind(1, studentId);
        currentDeadlineQuery.bind(2, assignmentId);
        if (currentDeadlineQuery.step() != SQLITE_ROW)
            throw std::runtime_error("Could not read the student's current deadline.");
        const std::string oldDeadline = currentDeadlineQuery.textColumn(0);
        const std::string extensionInput = ask("New individual deadline (YYYY-MM-DD HH:MM): ");
        const auto extension = parseDateTime(extensionInput);
        const auto original = parseDateTime(oldDeadline);
        if (!extension || !original || *extension <= *original)
            throw std::runtime_error("The extension must be later than the current deadline.");
        const std::string reason = ask("Reason for extension: ");
        auto upsert = database_.prepare(
            "INSERT INTO assignment_extensions(assignment_id,student_id,new_deadline,reason,granted_by) "
            "VALUES(?,?,?,?,?) ON CONFLICT(assignment_id,student_id) DO UPDATE SET "
            "new_deadline=excluded.new_deadline,reason=excluded.reason,granted_by=excluded.granted_by,"
            "created_at=CURRENT_TIMESTAMP;");
        upsert.bind(1, assignmentId); upsert.bind(2, studentId);
        upsert.bind(3, formatDateTime(*extension)); upsert.bind(4, reason);
        upsert.bind(5, currentUser_->id);
        if (upsert.step() != SQLITE_DONE) throw std::runtime_error("Could not save extension.");
        audit(currentUser_->id, "Granted individual deadline extension",
              "Assignment " + std::to_string(assignmentId) + "; student " +
              std::to_string(studentId) + "; new deadline " + formatDateTime(*extension) +
              "; reason: " + reason);
        std::cout << "Individual deadline extension saved.\n";
        pause();
    }

    static void printSubmissionRows(const std::vector<SubmissionRow>& rows) {
        std::cout << "\nID | STUDENT | COURSE | ASSIGNMENT | SUBMITTED | STATUS\n";
        for (const auto& row : rows) {
            std::cout << row.id << " | " << row.studentName << " | " << row.courseTitle
                      << " | " << row.assignmentTitle << " | " << row.submittedAt
                      << " | " << row.status << "\n"
                      << "    File: " << row.filePath << "\n";
        }
    }

    void hodMenu() {
        bool active = true;
        while (active) {
            std::cout << "\n======== HEAD OF DEPARTMENT DASHBOARD ========\n"
                      << "1. View marks awaiting moderation\n2. Moderate a mark\n"
                      << "3. View moderated marks awaiting release\n4. Release a moderated mark\n"
                      << "5. Change password\n6. Logout\n";
            const int choice = askInt("Choose an option: ", 1, 6);
            try {
                switch (choice) {
                    case 1: hodReviewQueue(); break;
                    case 2: moderateMark(); break;
                    case 3: hodReleaseQueue(); break;
                    case 4: releaseMark(); break;
                    case 5: changePassword(); break;
                    case 6: active = false; break;
                }
            } catch (const std::exception& error) {
                std::cout << "Operation failed: " << error.what() << "\n";
                pause();
            }
        }
    }

    std::vector<SubmissionRow> hodRows(const std::string& status) {
        auto query = database_.prepare(
            "SELECT s.submissionid,s.assignment_id,s.student_id,u.username,c.title,a.title,"
            "s.file_path,s.submission_time,COALESCE(x.new_deadline,a.deadline),s.status,"
            "a.max_mark,s.mark,s.moderated_mark,s.feedback "
            "FROM submissions s JOIN users u ON u.id=s.student_id "
            "JOIN assignments a ON a.assignmentid=s.assignment_id "
            "JOIN courses c ON c.courseid=a.course_id "
            "JOIN departments d ON d.department_id=c.department_id "
            "LEFT JOIN assignment_extensions x ON x.assignment_id=a.assignmentid AND x.student_id=s.student_id "
            "WHERE d.department_id=? AND s.status=? ORDER BY s.submission_time;");
        query.bind(1, currentUser_->departmentId);
        query.bind(2, status);
        std::vector<SubmissionRow> rows;
        while (query.step() == SQLITE_ROW) {
            SubmissionRow row;
            row.id=query.intColumn(0); row.assignmentId=query.intColumn(1); row.studentId=query.intColumn(2);
            row.studentName=query.textColumn(3); row.courseTitle=query.textColumn(4);
            row.assignmentTitle=query.textColumn(5); row.filePath=query.textColumn(6);
            row.submittedAt=query.textColumn(7); row.effectiveDeadline=query.textColumn(8);
            row.status=query.textColumn(9); row.maxMark=query.doubleColumn(10);
            if (!query.isNull(11)) row.mark=query.doubleColumn(11);
            if (!query.isNull(12)) row.moderatedMark=query.doubleColumn(12);
            row.feedback=query.textColumn(13); rows.push_back(std::move(row));
        }
        return rows;
    }

    void hodReviewQueue() {
        const auto rows = hodRows("Marked");
        if (rows.empty()) std::cout << "\nNo marks are waiting for moderation in this department.\n";
        else printModerationRows(rows);
        pause();
    }

    void moderateMark() {
        const auto rows = hodRows("Marked");
        if (rows.empty()) throw std::runtime_error("There are no marks to moderate.");
        printModerationRows(rows);
        const int id = askInt("Submission ID to moderate: ", 1, 1000000);
        const auto found = std::find_if(rows.begin(), rows.end(), [id](const auto& r){ return r.id == id; });
        if (found == rows.end() || !found->mark) throw std::runtime_error("Submission not in your department's moderation queue.");
        const double moderated = askDouble("Moderated mark: ", 0.0, found->maxMark);
        const std::string reason = ask("Moderation reason: ");
        auto update = database_.prepare(
            "UPDATE submissions SET moderated_mark=?,status='Moderated' "
            "WHERE submissionid=? AND status='Marked' AND mark IS NOT NULL;");
        update.bind(1, moderated); update.bind(2, id);
        if (update.step() != SQLITE_DONE || database_.changes() != 1)
            throw std::runtime_error("Moderation could not be saved.");
        audit(currentUser_->id, "Moderated submission " + std::to_string(id), reason);
        std::cout << "Moderated mark saved. It is awaiting release.\n";
        pause();
    }

    void printModerationRows(const std::vector<SubmissionRow>& rows) {
        std::cout << "\nID | STUDENT | COURSE | ASSIGNMENT | LECTURER MARK | MAX\n";
        for (const auto& row : rows) {
            std::cout << row.id << " | " << row.studentName << " | " << row.courseTitle
                      << " | " << row.assignmentTitle << " | "
                      << (row.mark ? std::to_string(*row.mark) : "-")
                      << " | " << row.maxMark << "\n";
        }
    }

    void hodReleaseQueue() {
        const auto rows = hodRows("Moderated");
        if (rows.empty()) std::cout << "\nNo moderated marks are awaiting release.\n";
        else {
            std::cout << "\nID | STUDENT | COURSE | ASSIGNMENT | MODERATED MARK\n";
            for (const auto& row : rows)
                std::cout << row.id << " | " << row.studentName << " | " << row.courseTitle
                          << " | " << row.assignmentTitle << " | "
                          << (row.moderatedMark ? std::to_string(*row.moderatedMark) : "-") << "\n";
        }
        pause();
    }

    void releaseMark() {
        const auto rows = hodRows("Moderated");
        if (rows.empty()) throw std::runtime_error("There are no moderated marks awaiting release.");
        std::cout << "\nID | STUDENT | COURSE | ASSIGNMENT | MODERATED MARK\n";
        for (const auto& row : rows)
            std::cout << row.id << " | " << row.studentName << " | " << row.courseTitle
                      << " | " << row.assignmentTitle << " | "
                      << (row.moderatedMark ? std::to_string(*row.moderatedMark) : "-") << "\n";
        const int id = askInt("Submission ID to release: ", 1, 1000000);
        const auto found = std::find_if(rows.begin(), rows.end(), [id](const auto& r){ return r.id == id; });
        if (found == rows.end() || !found->moderatedMark) throw std::runtime_error("Submission not available for release.");
        if (!confirm("Release this mark to the student?")) return;
        auto update = database_.prepare(
            "UPDATE submissions SET status='Released' WHERE submissionid=? AND status='Moderated' "
            "AND moderated_mark IS NOT NULL;");
        update.bind(1, id);
        if (update.step() != SQLITE_DONE || database_.changes() != 1)
            throw std::runtime_error("Mark could not be released.");
        audit(currentUser_->id, "Released mark for submission " + std::to_string(id));
        std::cout << "Mark released. The student can now view it.\n";
        pause();
    }

    void studentMenu() {
        bool active = true;
        while (active) {
            std::cout << "\n================ STUDENT DASHBOARD ================\n"
                      << "1. View enrolled courses\n2. View assignments\n"
                      << "3. Submit or resubmit assignment\n4. View released marks and feedback\n"
                      << "5. Change password\n6. Logout\n";
            const int choice = askInt("Choose an option: ", 1, 6);
            try {
                switch (choice) {
                    case 1: studentCourses(); break;
                    case 2: studentAssignments(); break;
                    case 3: submitAssignment(); break;
                    case 4: studentResults(); break;
                    case 5: changePassword(); break;
                    case 6: active = false; break;
                }
            } catch (const std::exception& error) {
                std::cout << "Operation failed: " << error.what() << "\n";
                pause();
            }
        }
    }

    void studentCourses() {
        auto query = database_.prepare(
            "SELECT c.courseid,c.title,d.department_name FROM enrollments e "
            "JOIN courses c ON c.courseid=e.course_id JOIN departments d ON d.department_id=c.department_id "
            "WHERE e.student_id=? ORDER BY c.title;");
        query.bind(1, currentUser_->id);
        std::cout << "\nYOUR ENROLLED COURSES\n";
        while (query.step() == SQLITE_ROW)
            std::cout << query.intColumn(0) << " | " << query.textColumn(1)
                      << " | " << query.textColumn(2) << "\n";
        pause();
    }

    std::vector<AssignmentRow> studentAssignmentRows() {
        auto query = database_.prepare(
            "SELECT a.assignmentid,c.courseid,c.title,a.title,COALESCE(x.new_deadline,a.deadline),a.max_mark "
            "FROM enrollments e JOIN courses c ON c.courseid=e.course_id "
            "JOIN assignments a ON a.course_id=c.courseid "
            "LEFT JOIN assignment_extensions x ON x.assignment_id=a.assignmentid AND x.student_id=e.student_id "
            "WHERE e.student_id=? ORDER BY a.deadline;");
        query.bind(1, currentUser_->id);
        std::vector<AssignmentRow> rows;
        while (query.step() == SQLITE_ROW) {
            rows.push_back(AssignmentRow{query.intColumn(0), query.intColumn(1),
                query.textColumn(2), query.textColumn(3), query.textColumn(4), query.doubleColumn(5)});
        }
        return rows;
    }

    void studentAssignments() {
        const auto rows = studentAssignmentRows();
        std::cout << "\nASSIGNMENTS AVAILABLE TO YOU\n";
        for (const auto& row : rows)
            std::cout << "#" << row.id << " | " << row.title << " | " << row.courseTitle
                      << " | deadline " << row.deadline << " | max " << row.maxMark << "\n";
        if (rows.empty()) std::cout << "No assignments are currently available.\n";
        pause();
    }

    void submitAssignment() {
        const auto rows = studentAssignmentRows();
        if (rows.empty()) throw std::runtime_error("There are no assignments in your enrolled courses.");
        for (const auto& row : rows)
            std::cout << "#" << row.id << " | " << row.title << " | " << row.courseTitle
                      << " | deadline " << row.deadline << "\n";
        const int assignmentId = askInt("Assignment ID: ", 1, 1000000);
        const auto found = std::find_if(rows.begin(), rows.end(), [assignmentId](const auto& row){
            return row.id == assignmentId;
        });
        if (found == rows.end()) throw std::runtime_error("Assignment is not available to your account.");
        auto existing = database_.prepare(
            "SELECT submissionid,status FROM submissions WHERE assignment_id=? AND student_id=?;");
        existing.bind(1, assignmentId); existing.bind(2, currentUser_->id);
        int existingId = 0;
        if (existing.step() == SQLITE_ROW) {
            existingId = existing.intColumn(0);
            const std::string existingStatus = existing.textColumn(1);
            if (existingStatus != "Submitted" && existingStatus != "Late")
                throw std::runtime_error("A submission that has been marked or moderated cannot be changed.");
            std::cout << "An earlier unmarked submission exists; this will replace its stored file.\n";
            if (!confirm("Continue with resubmission?")) return;
        }
        const std::string sourceText = ask("Full path to the file to submit: ");
        const fs::path source = fs::path(sourceText);
        if (!fs::exists(source) || !fs::is_regular_file(source))
            throw std::runtime_error("The specified file does not exist or is not a regular file.");
        const std::string submittedAt = nowDateTime();
        const int days = lateDays(submittedAt, found->deadline);
        const std::string status = days > 0 ? "Late" : "Submitted";
        const auto stamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        const std::string safeName = source.filename().string();
        const fs::path uploadDirectory = fs::current_path() / "data" / "uploads";
        fs::create_directories(uploadDirectory);
        const fs::path destination = uploadDirectory /
            ("student" + std::to_string(currentUser_->id) + "_assignment" +
             std::to_string(assignmentId) + "_" + std::to_string(stamp) + "_" + safeName);
        fs::copy_file(source, destination, fs::copy_options::none);
        const std::string storedPath = fs::relative(destination, fs::current_path()).string();
        try {
            if (existingId > 0) {
                auto update = database_.prepare(
                    "UPDATE submissions SET file_path=?,submission_time=?,mark=NULL,moderated_mark=NULL,"
                    "feedback='',status=? WHERE submissionid=?;");
                update.bind(1, storedPath); update.bind(2, submittedAt);
                update.bind(3, status); update.bind(4, existingId);
                if (update.step() != SQLITE_DONE) throw std::runtime_error("Could not save resubmission.");
            } else {
                auto insert = database_.prepare(
                    "INSERT INTO submissions(assignment_id,student_id,file_path,submission_time,status) "
                    "VALUES(?,?,?,?,?);");
                insert.bind(1, assignmentId); insert.bind(2, currentUser_->id);
                insert.bind(3, storedPath); insert.bind(4, submittedAt); insert.bind(5, status);
                if (insert.step() != SQLITE_DONE) throw std::runtime_error("Could not save submission.");
            }
            audit(currentUser_->id, existingId > 0 ? "Resubmitted assignment" : "Submitted assignment",
                  "Assignment " + std::to_string(assignmentId) + "; stored file " + storedPath);
        } catch (...) {
            std::error_code ignored;
            fs::remove(destination, ignored);
            throw;
        }
        std::cout << "Submission saved locally. Status: " << status << "\n"
                  << "Stored file: " << storedPath << "\n";
        pause();
    }

    void studentResults() {
        auto query = database_.prepare(
            "SELECT s.submissionid,a.title,c.title,s.mark,s.moderated_mark,s.feedback,s.submission_time "
            "FROM submissions s JOIN assignments a ON a.assignmentid=s.assignment_id "
            "JOIN courses c ON c.courseid=a.course_id "
            "WHERE s.student_id=? AND s.status='Released' ORDER BY s.submission_time DESC;");
        query.bind(1, currentUser_->id);
        std::cout << "\nRELEASED RESULTS\n";
        bool any = false;
        while (query.step() == SQLITE_ROW) {
            any = true;
            std::cout << "Submission #" << query.intColumn(0) << " | " << query.textColumn(1)
                      << " | " << query.textColumn(2) << "\n"
                      << "Lecturer mark: " << (query.isNull(3) ? "-" : std::to_string(query.doubleColumn(3)))
                      << " | Moderated mark: " << (query.isNull(4) ? "-" : std::to_string(query.doubleColumn(4)))
                      << "\nFeedback: " << query.textColumn(5)
                      << "\nSubmitted: " << query.textColumn(6) << "\n\n";
        }
        if (!any) std::cout << "No results have been released yet.\n";
        pause();
    }

    void backupData() {
        const std::string label = ask("Backup filename (without extension): ");
        std::string safe = label;
        for (char& ch : safe) {
            if (!(std::isalnum(static_cast<unsigned char>(ch)) || ch == '-' || ch == '_')) ch = '_';
        }
        if (safe.empty()) throw std::runtime_error("Backup filename is invalid.");
        const fs::path backupDirectory = fs::current_path() / "data" / "backups";
        fs::create_directories(backupDirectory);
        const fs::path databaseBackup = backupDirectory / (safe + ".db");
        const fs::path uploadsBackup = backupDirectory / (safe + ".uploads");
        if (fs::exists(databaseBackup) || fs::exists(uploadsBackup))
            throw std::runtime_error("A backup with that name already exists.");
        database_.backupTo(databaseBackup);
        try {
            const fs::path uploads = fs::current_path() / "data" / "uploads";
            if (fs::exists(uploads)) fs::copy(uploads, uploadsBackup, fs::copy_options::recursive);
            else fs::create_directories(uploadsBackup);
        } catch (...) {
            std::error_code ignored;
            fs::remove(databaseBackup, ignored);
            fs::remove_all(uploadsBackup, ignored);
            throw;
        }
        audit(currentUser_->id, "Created local backup", databaseBackup.string());
        std::cout << "Backup created:\n" << databaseBackup << "\n" << uploadsBackup << "\n";
        pause();
    }
};

} // namespace

int main() {
    try {
        LmsApplication application;
        application.run();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "\nA serious error occurred: " << error.what() << "\n";
        std::cerr << "The application has stopped. Check the local data folder and try again.\n";
        return 1;
    }
}
