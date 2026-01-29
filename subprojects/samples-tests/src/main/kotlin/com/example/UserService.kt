package com.example

import java.sql.Connection
import java.sql.DriverManager
import java.sql.ResultSet
import java.io.File
import java.io.ObjectInputStream
import java.io.FileInputStream
import java.io.BufferedReader
import java.io.InputStreamReader
import javax.script.ScriptEngineManager

/**
 * User service for managing user authentication and data access.
 */
class UserService {
    
    // VULNERABILITY: Hardcoded credentials - CWE-798
    private val DB_USERNAME = "admin"
    private val DB_PASSWORD = "SuperSecret123!"
    private val DB_URL = "jdbc:mysql://localhost:3306/users"
    private val API_KEY = "sk-proj-abc123xyz789secretkey"
    private val AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    private val PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy\n-----END RSA PRIVATE KEY-----"
    
    /**
     * Authenticate a user by username and password.
     * VULNERABILITY: SQL Injection - CWE-89
     */
    fun authenticateUser(username: String, password: String): Boolean {
        val connection = getConnection()
        
        // SQL Injection vulnerability - user input directly concatenated
        val query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'"
        
        val statement = connection.createStatement()
        val resultSet = statement.executeQuery(query)
        
        return resultSet.next()
    }
    
    /**
     * Get user details by ID.
     * VULNERABILITY: SQL Injection - CWE-89
     */
    fun getUserById(userId: String): Map<String, Any>? {
        val connection = getConnection()
        
        // Another SQL Injection vulnerability
        val query = "SELECT id, username, email, role FROM users WHERE id = $userId"
        
        val statement = connection.createStatement()
        val resultSet = statement.executeQuery(query)
        
        if (resultSet.next()) {
            return mapOf(
                "id" to resultSet.getInt("id"),
                "username" to resultSet.getString("username"),
                "email" to resultSet.getString("email"),
                "role" to resultSet.getString("role")
            )
        }
        return null
    }
    
    /**
     * Search users by name.
     * VULNERABILITY: SQL Injection - CWE-89
     */
    fun searchUsers(searchTerm: String): List<Map<String, Any>> {
        val connection = getConnection()
        
        // SQL Injection through LIKE clause
        val query = "SELECT * FROM users WHERE username LIKE '%$searchTerm%' OR email LIKE '%$searchTerm%'"
        
        val statement = connection.createStatement()
        val resultSet = statement.executeQuery(query)
        
        val users = mutableListOf<Map<String, Any>>()
        while (resultSet.next()) {
            users.add(mapOf(
                "id" to resultSet.getInt("id"),
                "username" to resultSet.getString("username"),
                "email" to resultSet.getString("email")
            ))
        }
        return users
    }
    
    /**
     * Delete user by ID.
     * VULNERABILITY: SQL Injection - CWE-89
     */
    fun deleteUser(userId: String): Boolean {
        val connection = getConnection()
        
        // SQL Injection in DELETE statement
        val query = "DELETE FROM users WHERE id = $userId"
        
        val statement = connection.createStatement()
        return statement.executeUpdate(query) > 0
    }
    
    /**
     * Execute arbitrary query for reporting.
     * VULNERABILITY: SQL Injection - CWE-89 (most severe - arbitrary SQL execution)
     */
    fun executeReportQuery(reportQuery: String): ResultSet {
        val connection = getConnection()
        
        // Directly executing user-provided query - critical vulnerability
        val statement = connection.createStatement()
        return statement.executeQuery(reportQuery)
    }
    
    /**
     * Update user password.
     * VULNERABILITY: Weak cryptographic storage - password stored in plain text
     */
    fun updatePassword(userId: Int, newPassword: String): Boolean {
        val connection = getConnection()
        
        // Password stored in plain text - no hashing
        val query = "UPDATE users SET password = '$newPassword' WHERE id = $userId"
        
        val statement = connection.createStatement()
        return statement.executeUpdate(query) > 0
    }
    
    private fun getConnection(): Connection {
        // Using hardcoded credentials
        return DriverManager.getConnection(DB_URL, DB_USERNAME, DB_PASSWORD)
    }
    
    /**
     * Log sensitive information.
     * VULNERABILITY: Information Exposure - CWE-532
     */
    fun logUserActivity(username: String, password: String, action: String) {
        // Logging sensitive credentials
        println("User activity: username=$username, password=$password, action=$action")
    }
    
    /**
     * Execute system command for file operations.
     * CRITICAL VULNERABILITY: Command Injection - CWE-78
     */
    fun executeCommand(userInput: String): String {
        // Critical: User input directly passed to shell command
        val process = Runtime.getRuntime().exec("sh -c $userInput")
        val reader = BufferedReader(InputStreamReader(process.inputStream))
        return reader.readText()
    }
    
    /**
     * Execute system command with ProcessBuilder.
     * CRITICAL VULNERABILITY: Command Injection - CWE-78
     */
    fun runSystemCommand(command: String, args: String): String {
        // Critical: User-controlled command execution
        val processBuilder = ProcessBuilder(command, "-c", args)
        val process = processBuilder.start()
        val reader = BufferedReader(InputStreamReader(process.inputStream))
        return reader.readText()
    }
    
    /**
     * Read file from user-specified path.
     * CRITICAL VULNERABILITY: Path Traversal - CWE-22
     */
    fun readUserFile(fileName: String): String {
        // Critical: No validation - allows ../../etc/passwd attacks
        val file = File("/app/uploads/$fileName")
        return file.readText()
    }
    
    /**
     * Download and save file.
     * CRITICAL VULNERABILITY: Path Traversal - CWE-22
     */
    fun saveUploadedFile(fileName: String, content: ByteArray) {
        // Critical: Unsanitized filename allows directory traversal
        val file = File("/app/uploads/$fileName")
        file.writeBytes(content)
    }
    
    /**
     * Deserialize user data from file.
     * CRITICAL VULNERABILITY: Unsafe Deserialization - CWE-502
     */
    fun deserializeUserData(filePath: String): Any {
        // Critical: Deserializing untrusted data can lead to RCE
        val fileInputStream = FileInputStream(filePath)
        val objectInputStream = ObjectInputStream(fileInputStream)
        return objectInputStream.readObject()
    }
    
    /**
     * Load and deserialize object from user input.
     * CRITICAL VULNERABILITY: Unsafe Deserialization - CWE-502
     */
    fun loadSerializedObject(userProvidedPath: String): Any {
        // Critical: User controls the path to serialized object
        val file = File(userProvidedPath)
        val ois = ObjectInputStream(FileInputStream(file))
        val obj = ois.readObject()
        ois.close()
        return obj
    }
    
    /**
     * Execute dynamic script.
     * CRITICAL VULNERABILITY: Code Injection - CWE-94
     */
    fun executeScript(scriptCode: String): Any? {
        // Critical: Executing user-provided code
        val engine = ScriptEngineManager().getEngineByName("JavaScript")
        return engine.eval(scriptCode)
    }
    
    /**
     * Evaluate dynamic expression.
     * CRITICAL VULNERABILITY: Code Injection - CWE-94
     */
    fun evaluateExpression(expression: String): Any? {
        // Critical: User-controlled code execution
        val scriptEngine = ScriptEngineManager().getEngineByName("groovy")
        return scriptEngine?.eval(expression)
    }
    
    /**
     * Create temporary file with user-controlled name.
     * CRITICAL VULNERABILITY: Insecure Temporary File - CWE-377
     */
    fun createTempFile(fileName: String): File {
        // Critical: Predictable temporary file name
        val tempFile = File("/tmp/$fileName")
        tempFile.createNewFile()
        return tempFile
    }
    
    /**
     * Redirect to user-specified URL.
     * CRITICAL VULNERABILITY: Open Redirect - CWE-601
     */
    fun getRedirectUrl(targetUrl: String): String {
        // Critical: Unvalidated redirect URL
        return "Location: $targetUrl"
    }
    
    /**
     * Render HTML with user input.
     * CRITICAL VULNERABILITY: Cross-Site Scripting (XSS) - CWE-79
     */
    fun renderUserProfile(username: String, bio: String): String {
        // Critical: Unescaped user input in HTML
        return """
            <html>
                <body>
                    <h1>Welcome, $username!</h1>
                    <p>Bio: $bio</p>
                </body>
            </html>
        """.trimIndent()
    }
    
    /**
     * Build XML with user input.
     * CRITICAL VULNERABILITY: XML Injection - CWE-91
     */
    fun buildUserXml(userId: String, userData: String): String {
        // Critical: User input directly embedded in XML
        return """
            <?xml version="1.0"?>
            <user>
                <id>$userId</id>
                <data>$userData</data>
            </user>
        """.trimIndent()
    }
}
