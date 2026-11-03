# Campus LMS — Offline C++ Edition

Campus LMS is an offline, Windows-friendly C++17 console application backed by SQLite. It does not need a web server, internet connection, cloud account, or browser. Records and submitted files remain in the local `data` folder.

## Included workflows

- Separate Administrator, Lecturer, Head of Department, and Student dashboards.
- Secure password storage using PBKDF2-HMAC-SHA256 with random salts (Windows CNG/BCrypt or OpenSSL on other platforms).
- Student self-registration. Administrator-created accounts for Lecturer and Head of Department roles.
- Department and course creation, lecturer assignment, and student enrolment.
- Assignment creation with a title, description, deadline, and maximum mark.
- Individual student deadline extensions, with a reason and the granting lecturer recorded.
- Assignment submission and resubmission. The selected file is copied into `data/uploads`; a local path is stored in SQLite.
- Late-work deduction: 10% of the assignment maximum mark per started 24-hour period late, for up to three days. More than three days late receives zero. The deduction is applied when the Lecturer marks the work.
- Lecturer marking and feedback, Head of Department moderation, and controlled result release.
- Department-scoped moderation for Heads of Department.
- Audit history and a database-plus-uploads backup.

## First run demonstration accounts

A new database is seeded only when there are no users in it. The demonstration accounts are:

| Role | Username | Initial password |
|---|---|---|
| Administrator | `admin` | `Admin123!` |
| Lecturer | `lecturer` | `Lecturer123!` |
| Head of Department | `hod` | `Hod123!` |
| Student | `student` | `Student123!` |

**Change these passwords after first login.** The accounts are demonstration credentials, not suitable for a deployed institution. Later student accounts can self-register; privileged accounts are created by the Administrator.

The first-run data includes a Computing department, one course assigned to the Lecturer, a student enrolment, and one sample assignment with a deadline seven days after the database is first created.

## Build on Windows (Visual Studio / MSVC)

Requirements:

- CMake 3.20 or later.
- Visual Studio 2022 or another C++17-capable MSVC toolchain.
- SQLite development files.

The earlier School LMS project used the SQLite amalgamation in a folder named `SQLite 3`. To reuse it, copy that `SQLite 3` folder (containing both `sqlite3.c` and `sqlite3.h`) into this project folder. CMake detects it automatically and compiles `sqlite3.c` into the application.

Alternatively, install SQLite development files so CMake can find the `SQLite3` package.

Then double-click `build.bat`. Once the build completes, double-click `start.bat`.

You can also build in PowerShell from this folder:

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
.\build\Release\CampusLMS.exe
```

## Build on Linux (for development/testing)

Requirements: CMake, a C++17 compiler, SQLite development headers/library, and OpenSSL development headers/library.

```bash
cmake -S . -B build
cmake --build build
./build/CampusLMS
```

## Local files

- `data/school_lms.db` — SQLite database.
- `data/uploads/` — copies of submitted files.
- `data/backups/<name>.db` — SQLite-consistent database backup.
- `data/backups/<name>.uploads/` — matching backup of submitted files.

Keep the `.db` backup and its matching `.uploads` folder together. To restore, close Campus LMS, preserve the current `data` folder, then replace `data/school_lms.db` and `data/uploads` with the matching backup files/folder.

## Important notes

- This version is an offline application for one computer/local user environment. It is not a networked multi-user server; multiple computers do not automatically share the database.
- Submission files are copied into the local uploads folder. The source file is not deleted.
- The program stores a file path, not the contents of a PDF/Word document in a database blob.
- The app does not yet provide a graphical Windows interface. It uses a guided console menu so that the core workflows can be tested without adding a third-party GUI toolkit.
- The late penalty policy is implemented as a started 24-hour period (rounded up). Confirm that this exact interpretation matches the institution's assessment policy before using it for real grading.
- No generated software should be treated as institution-ready until the institution reviews its policies, permissions, backup practices, privacy controls, and deployment security.

## Existing School LMS databases

The app uses `data/school_lms.db` by default. To migrate an existing database, place a copy at that path before launching. The application performs additive migrations for the feedback, assignment-title/description, user department, and active-account columns it needs. Always make a separate backup before migrating a real database.


### Legacy account compatibility

Accounts created by the earlier School LMS password hasher (PBKDF2-HMAC-SHA256 with 600,000 iterations, a 16-byte salt, and a 32-byte hash represented as hexadecimal) can use the same password in this version. Placeholder seed values such as the literal strings `password` and `salt` are not valid PBKDF2 credentials and cannot be authenticated; create a new account or replace that account's password through an authorised account-recovery process before using it.

## Suggested first-run test

1. Build with `build.bat`, then launch with `start.bat`.
2. Sign in as `admin` and view the users, departments, and courses.
3. Sign in as `lecturer` and create an assignment for the demo course.
4. Sign in as `student` and submit a local test file.
5. Sign in as `lecturer`, mark the submission, and enter feedback.
6. Sign in as `hod`, moderate the mark and release it.
7. Sign in as `student` and confirm the released result and feedback are visible.
8. Sign in as `admin` and create a backup. Check both the `.db` file and matching `.uploads` directory.

For a late-penalty test, create an assignment with a deadline in the past before submitting. A submission more than 24 hours late is charged for two started 24-hour periods, because the rule rounds each started period up.

## Migrating the earlier School LMS database

1. Close the old application and make a separate copy of its `lms.db` file.
2. Create the `data` folder in this project if it does not exist.
3. Copy the old database to `data/school_lms.db`.
4. Launch Campus LMS. It adds the columns and extension table it needs.
5. Confirm users, courses, enrolments, and assignment records before entering new data.

Do not point the new application at the only copy of a database. The migration is additive, but the original file should remain untouched as a fallback. Where the legacy database has multiple departments, use the Administrator menu option to assign each Head of Department to the correct department. If the legacy database contains only one department, the migration associates unassigned Heads of Department with that department automatically.

The application uses the original School LMS PBKDF2 settings for existing secure password hashes. Placeholder values from an SQL seed script (for example, literal `password` and `salt`) are not valid user credentials and cannot be verified.
