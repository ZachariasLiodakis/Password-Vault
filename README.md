<div align="center">

<table>
  <tr>
    <td>
      <img src="Password Vault.png" alt="Password Vault" height="150" />
    </td>
    <td style="vertical-align: middle;">
      <h2 style="font-size: 0em; margin: 0;">Password Vault</h2>
    </td>
  </tr>
</table>

</div>

# 

A simple and secure command-line password manager implemented in Java. The application securely stores site credentials encrypted with AES-GCM and protects the data with a master password.

## Features

- Create a new encrypted vault secured by a master password.
- Load an existing vault by entering the correct master password.
- Add new site entries with username and password.
- Generate strong random passwords.
- List stored sites.
- Retrieve stored usernames and passwords.
- Secure encryption with AES-256-GCM and password-based key derivation (PBKDF2 with HMAC-SHA256).
- Limits incorrect master password attempts for security.

## Requirements

- Java 11 or higher
- Maven (for build and dependency management)
- [Gson library](https://github.com/google/gson) (for JSON serialization/deserialization)

## Setup & Running

1. Clone or download the repository.

2. Compile and run the `PasswordVault` class from a terminal.

   ```bash
   cd /path/to/repo-folder
   mvn clean package
   java -jar target/PasswordVault-1.0-SNAPSHOT-jar-with-dependencies.jar
