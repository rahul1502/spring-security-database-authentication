package com.example.security.security;

public enum ApplicationUserPermission {

    STUDENT_READ("student:read"),
    STUDENT_WRITE("student:write"),
    COURSE_READ("course:read"),
    COURSE_WRITE("course:write");

    private final String permission;

    // Constructor
    ApplicationUserPermission(String permission) {
        this.permission = permission;
    }

    // Getter
    public String getPermission() {
        return permission;
    }
}
