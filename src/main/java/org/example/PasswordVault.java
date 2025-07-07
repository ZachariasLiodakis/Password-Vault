package org.example;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.lang.reflect.Type;
import java.nio.file.*;
import java.security.*;
import java.security.spec.KeySpec;
import java.util.*;

public class PasswordVault {
    // Filename for storing the encrypted vault
    private static final String VAULT_FILE = "vault.enc";
    // Salt length for key derivation (in bytes)
    private static final int SALT_LENGTH = 16;
    // IV (Initialization Vector) length for AES-GCM mode (12 bytes is standard)
    private static final int IV_LENGTH = 12;
    // Number of iterations for PBKDF2 key derivation
    private static final int ITERATIONS = 65536;
    // Length of the AES key in bits (256 bits = 32 bytes)
    private static final int KEY_LENGTH = 256;

    // Gson instance for JSON serialization/deserialization
    private final Gson gson = new Gson();
    // Secret key used for encryption and decryption
    private SecretKey secretKey;
    // Map storing the vault entries: site -> {username, password}
    private Map<String, Map<String, String>> vault = new HashMap<>();

    public static void main() throws Exception {
        new PasswordVault().run();
    }

    public void run() throws Exception {
        // Get the console object to read input securely (especially passwords)
        Console console = System.console();
        if (console == null) {
            throw new RuntimeException("Please run from a terminal");
        }

        byte[] salt;
        // Check if the vault file already exists
        boolean vaultExists = Files.exists(Path.of(VAULT_FILE));
        int attempts = 0;
        final int MAX_ATTEMPTS = 3;

        if (vaultExists) {
            // If vault exists, read the salt from file
            salt = Files.readAllBytes(Path.of("vault.salt"));

            // Prompt the user for master password with limited attempts
            while (true) {
                String input = console.readLine("Enter master password (or type 'exit' to quit): ");
                if (input.equalsIgnoreCase("exit")) {
                    System.out.println("Exiting...");
                    return;
                }

                char[] masterPassword = input.toCharArray();
                // Derive the secret key using PBKDF2 with the provided password and salt
                this.secretKey = deriveKey(masterPassword, salt);

                try {
                    // Attempt to load and decrypt the vault using this key
                    loadVault();
                    break; // Success, exit loop
                } catch (AEADBadTagException e) {
                    // AEADBadTagException occurs if decryption/authentication fails (wrong password)
                    attempts++;
                    System.out.println("Incorrect password. Attempts remaining: " + (MAX_ATTEMPTS - attempts));
                    if (attempts >= MAX_ATTEMPTS) {
                        System.out.println("Too many failed attempts. Exiting.");
                        return;
                    }
                }
            }
        } else {
            // Vault doesn't exist: generate a new random salt and save it
            salt = generateRandomBytes(SALT_LENGTH);
            Files.write(Path.of("vault.salt"), salt);

            // Ask the user to set a new master password
            String input = console.readLine("Set a new master password (or type 'exit' to quit): ");
            if (input.equalsIgnoreCase("exit")) {
                System.out.println("Exiting...");
                return;
            }

            char[] masterPassword = input.toCharArray();
            // Derive the secret key with the new password
            this.secretKey = deriveKey(masterPassword, salt);
            System.out.println("New vault created.");
        }

        // Launch the main menu loop for further user interaction
        mainMenu(console);
    }

    private void mainMenu(Console console) throws Exception {
        while (true) {
            System.out.println("\n1. Add entry\n2. List entries\n3. Get password\n4. Generate password\n5. Exit");
            String choice = console.readLine("> ");

            // Switch-case based on user's choice, Java 14+ style with arrows
            switch (choice) {
                case "1" -> addEntry(console);        // Add a new site entry
                case "2" -> listEntries();            // List stored sites
                case "3" -> getPassword(console);     // Retrieve username & password for a site
                case "4" -> generatePassword(console);// Generate a random password
                case "5" -> {                        // Save vault and exit
                    saveVault();
                    return;
                }
                default -> System.out.println("Invalid option.");
            }
        }
    }

    private void addEntry(Console console) {
        // Read site, username, and optionally generate or input password
        String site = console.readLine("Site: ");
        String username = console.readLine("Username: ");
        String choice = console.readLine("Generate password? (y/n): ");
        String password;

        if (choice.equalsIgnoreCase("y")) {
            int length = Integer.parseInt(console.readLine("Enter password length: "));
            password = generateRandomPassword(length);
            System.out.println("Generated password: " + password);
        } else {
            char[] pwd = console.readPassword("Password: ");
            password = new String(pwd);
        }

        // Store the new entry in the vault map
        vault.put(site, Map.of("username", username, "password", password));
        System.out.println("Entry added.");
    }

    private void generatePassword(Console console) {
        // Ask user desired password length, generate, and display it
        int length = Integer.parseInt(console.readLine("Enter desired password length: "));
        String password = generateRandomPassword(length);
        System.out.println("Generated password: " + password);
    }

    private String generateRandomPassword(int length) {
        // Characters used for password generation
        String upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String lower = "abcdefghijklmnopqrstuvwxyz";
        String digits = "0123456789";
        String symbols = "!@#$%^&*()-_=+[]{};:,.<>?/";
        String all = upper + lower + digits + symbols;

        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            // Append a random character from all allowed chars
            sb.append(all.charAt(random.nextInt(all.length())));
        }
        return sb.toString();
    }

    private void listEntries() {
        // List all stored sites
        System.out.println("Stored sites:");
        for (String site : vault.keySet()) {
            System.out.println(" - " + site);
        }
    }

    private void getPassword(Console console) {
        // Retrieve username and password for a given site
        String site = console.readLine("Site to retrieve: ");
        Map<String, String> entry = vault.get(site);
        if (entry != null) {
            System.out.printf("Username: %s\nPassword: %s\n", entry.get("username"), entry.get("password"));
        } else {
            System.out.println("Not found.");
        }
    }

    private void saveVault() throws Exception {
        // Serialize the vault map to JSON
        String json = gson.toJson(vault);
        // Base64 encode the JSON string bytes before encryption
        String encoded = Base64.getEncoder().encodeToString(json.getBytes());
        // Generate a new random IV for AES-GCM
        byte[] iv = generateRandomBytes(IV_LENGTH);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        // Initialize cipher for encryption with the secret key and IV
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
        // Encrypt the encoded JSON bytes
        byte[] ciphertext = cipher.doFinal(encoded.getBytes());

        // Concatenate IV and ciphertext in a byte array output stream
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(iv);
        outputStream.write(ciphertext);

        // Write the encrypted data to the vault file
        Files.write(Path.of(VAULT_FILE), outputStream.toByteArray());
    }

    private void loadVault() throws Exception {
        // Read all bytes from the vault file
        byte[] fileBytes = Files.readAllBytes(Path.of(VAULT_FILE));
        // Extract the IV from the beginning of the file
        byte[] iv = Arrays.copyOfRange(fileBytes, 0, IV_LENGTH);
        // Extract the ciphertext after the IV
        byte[] ciphertext = Arrays.copyOfRange(fileBytes, IV_LENGTH, fileBytes.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        // Initialize cipher for decryption with the secret key and extracted IV
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));
        // Decrypt ciphertext to get the encoded JSON bytes
        byte[] decrypted = cipher.doFinal(ciphertext);

        // Decode the Base64 string to get the original JSON string
        String decoded = new String(Base64.getDecoder().decode(new String(decrypted)));
        // Deserialize the JSON string back into the vault map
        Type type = new TypeToken<Map<String, Map<String, String>>>() {}.getType();
        vault = gson.fromJson(decoded, type);
    }

    private SecretKey deriveKey(char[] password, byte[] salt) throws Exception {
        // Use PBKDF2 with HMAC-SHA256 to derive a secure AES key from the password and salt
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }

    private byte[] generateRandomBytes(int length) throws Exception {
        // Generate a cryptographically secure random byte array of specified length
        byte[] bytes = new byte[length];
        SecureRandom.getInstanceStrong().nextBytes(bytes);
        return bytes;
    }
}
