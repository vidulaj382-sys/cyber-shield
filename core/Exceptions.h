#pragma once
// Unit IV: custom exception hierarchy used by the whole core.
#include <stdexcept>
#include <string>

namespace cyber {

// Base class for every error raised by the core logic.
class CyberException : public std::runtime_error {
public:
    explicit CyberException(const std::string& msg) : std::runtime_error(msg) {}
};

class AuthException : public CyberException {
public:
    explicit AuthException(const std::string& msg)
        : CyberException("Login failed: " + msg) {}
};

class AccessDeniedException : public CyberException {
public:
    explicit AccessDeniedException(const std::string& action)
        : CyberException("Access denied: your role cannot " + action) {}
};

class ValidationException : public CyberException {
public:
    explicit ValidationException(const std::string& msg)
        : CyberException("Invalid input: " + msg) {}
};

class NotFoundException : public CyberException {
public:
    explicit NotFoundException(const std::string& what)
        : CyberException("Not found: " + what) {}
};

// Raised when a threat detector cannot do its job (missing detector, huge input).
class ThreatException : public CyberException {
public:
    explicit ThreatException(const std::string& msg)
        : CyberException("Threat engine: " + msg) {}
};

// Raised when someone touches the Safe Box while it is locked.
class VaultLockedException : public CyberException {
public:
    VaultLockedException()
        : CyberException("Your Safe Box is locked. Unlock it with your secret password first.") {}
};

class FileException : public CyberException {
public:
    FileException(const std::string& file, const std::string& msg)
        : CyberException("File error [" + file + "]: " + msg), fileName(file) {}
    const std::string& file() const { return fileName; }

private:
    std::string fileName;
};

} // namespace cyber
