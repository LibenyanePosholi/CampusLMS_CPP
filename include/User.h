#ifndef USER_H
#define USER_H

#include <string>

enum class UserRole {
    Administrator,
    Lecturer,
    HeadOfDepartment,
    Student
};

class User {
private:
    int id;
    std::string username;
    UserRole role;

public:
    User(int userId, const std::string& userName, UserRole userRole)
        : id(userId), username(userName), role(userRole) {}

    virtual ~User() = default;

    int getId() const {
        return id;
    }

    const std::string& getUsername() const {
        return username;
    }

    UserRole getRole() const {
        return role;
    }

    virtual std::string getRoleName() const {
        switch (role) {
            case UserRole::Administrator:
                return "Administrator";
            case UserRole::Lecturer:
                return "Lecturer";
            case UserRole::HeadOfDepartment:
                return "Head of Department";
            case UserRole::Student:
                return "Student";
        }

        return "Unknown";
    }
};


class Administrator : public User {
public:
    Administrator(int id, const std::string& username)
        : User(id, username, UserRole::Administrator) {}
};

class Lecturer : public User {
public:
    Lecturer(int id, const std::string& username)
        : User(id, username, UserRole::Lecturer) {}
};

class HeadOfDepartment : public User {
public:
    HeadOfDepartment(int id, const std::string& username)
        : User(id, username, UserRole::HeadOfDepartment) {}
};

class Student : public User {
public:
    Student(int id, const std::string& username)
        : User(id, username, UserRole::Student) {}
};


#endif
