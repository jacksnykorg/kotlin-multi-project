package com.example

import java.io.File
import java.io.FileInputStream
import java.io.ObjectInputStream
import java.sql.DriverManager
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * Vulnerable controller for security testing/demo purposes.
 * Contains intentional critical security vulnerabilities.
 */
class VulnerableController {

    /**
     * SQL Injection - CWE-89 (Critical)
     * User input flows directly into SQL query
     */
    fun login(request: HttpServletRequest, response: HttpServletResponse): String {
        val username = request.getParameter("username")
        val password = request.getParameter("password")
        
        val connection = DriverManager.getConnection("jdbc:mysql://localhost/db", "root", "pass")
        val statement = connection.createStatement()
        
        // CRITICAL: SQL Injection - unsanitized user input in query
        val query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
        val rs = statement.executeQuery(query)
        
        return if (rs.next()) "Login successful" else "Login failed"
    }

    /**
     * SQL Injection - CWE-89 (Critical)
     * User input in DELETE statement
     */
    fun deleteUser(request: HttpServletRequest): Int {
        val userId = request.getParameter("id")
        val connection = DriverManager.getConnection("jdbc:mysql://localhost/db", "root", "pass")
        val statement = connection.createStatement()
        
        // CRITICAL: SQL Injection in DELETE
        return statement.executeUpdate("DELETE FROM users WHERE id = " + userId)
    }

    /**
     * Reflected XSS - CWE-79 (Critical)
     * User input reflected directly in HTML response
     */
    fun search(request: HttpServletRequest, response: HttpServletResponse) {
        val query = request.getParameter("q")
        
        response.contentType = "text/html"
        val writer = response.writer
        
        // CRITICAL: XSS - unsanitized user input in HTML output
        writer.println("<html><body>")
        writer.println("<h1>Search Results for: " + query + "</h1>")
        writer.println("</body></html>")
    }

    /**
     * Stored XSS - CWE-79 (Critical)
     * User input stored and rendered without escaping
     */
    fun displayProfile(request: HttpServletRequest, response: HttpServletResponse) {
        val bio = request.getParameter("bio")
        val name = request.getParameter("name")
        
        response.contentType = "text/html"
        val writer = response.writer
        
        // CRITICAL: XSS - user input directly in HTML
        writer.println("<html><body>")
        writer.println("<h1>Welcome, " + name + "</h1>")
        writer.println("<div class='bio'>" + bio + "</div>")
        writer.println("</body></html>")
    }

    /**
     * Command Injection - CWE-78 (Critical)
     * User input passed directly to shell command
     */
    fun ping(request: HttpServletRequest): String {
        val host = request.getParameter("host")
        
        // CRITICAL: Command Injection - user input in shell command
        val process = Runtime.getRuntime().exec("ping -c 1 " + host)
        return process.inputStream.bufferedReader().readText()
    }

    /**
     * Command Injection - CWE-78 (Critical)
     * User input in ProcessBuilder
     */
    fun runDiagnostics(request: HttpServletRequest): String {
        val command = request.getParameter("cmd")
        
        // CRITICAL: Command Injection via ProcessBuilder
        val pb = ProcessBuilder("/bin/sh", "-c", command)
        val process = pb.start()
        return process.inputStream.bufferedReader().readText()
    }

    /**
     * Path Traversal - CWE-22 (Critical)
     * User input used to construct file path
     */
    fun downloadFile(request: HttpServletRequest, response: HttpServletResponse) {
        val filename = request.getParameter("file")
        
        // CRITICAL: Path Traversal - user controls file path
        val file = File("/var/www/uploads/" + filename)
        val content = file.readBytes()
        
        response.outputStream.write(content)
    }

    /**
     * Path Traversal - CWE-22 (Critical)  
     * User input in file read operation
     */
    fun readConfig(request: HttpServletRequest): String {
        val configName = request.getParameter("config")
        
        // CRITICAL: Path Traversal - attacker can read any file
        val file = File("/etc/app/configs/" + configName)
        return file.readText()
    }

    /**
     * Unsafe Deserialization - CWE-502 (Critical)
     * Deserializing user-controlled data
     */
    fun loadUserSession(request: HttpServletRequest): Any {
        val sessionFile = request.getParameter("session")
        
        // CRITICAL: Unsafe Deserialization - RCE possible
        val fis = FileInputStream(sessionFile)
        val ois = ObjectInputStream(fis)
        return ois.readObject()
    }

    /**
     * Open Redirect - CWE-601 (High)
     * User input used directly in redirect
     */
    fun redirect(request: HttpServletRequest, response: HttpServletResponse) {
        val url = request.getParameter("url")
        
        // CRITICAL: Open Redirect - phishing attacks possible
        response.sendRedirect(url)
    }

    /**
     * LDAP Injection - CWE-90 (Critical)
     * User input in LDAP query
     */
    fun findUser(request: HttpServletRequest): String {
        val username = request.getParameter("user")
        
        // CRITICAL: LDAP Injection
        val filter = "(&(uid=" + username + ")(objectClass=person))"
        return "LDAP filter: $filter"
    }

    /**
     * XPath Injection - CWE-643 (Critical)
     * User input in XPath query
     */
    fun queryXml(request: HttpServletRequest): String {
        val id = request.getParameter("id")
        
        // CRITICAL: XPath Injection
        val xpath = "//users/user[@id='" + id + "']/name"
        return "XPath: $xpath"
    }

    /**
     * Header Injection - CWE-113 (High)
     * User input in HTTP header
     */
    fun setCustomHeader(request: HttpServletRequest, response: HttpServletResponse) {
        val headerValue = request.getParameter("value")
        
        // CRITICAL: HTTP Response Splitting / Header Injection
        response.setHeader("X-Custom-Header", headerValue)
    }

    /**
     * Log Injection - CWE-117 (Medium)
     * User input in log output
     */
    fun logAction(request: HttpServletRequest) {
        val action = request.getParameter("action")
        val user = request.getParameter("user")
        
        // Log Injection - log forging possible
        println("User $user performed action: $action")
    }

    /**
     * Server-Side Request Forgery (SSRF) - CWE-918 (Critical)
     * User input used to make server-side HTTP request
     */
    fun fetchUrl(request: HttpServletRequest): String {
        val targetUrl = request.getParameter("url")
        
        // CRITICAL: SSRF - attacker can access internal services
        val url = java.net.URL(targetUrl)
        return url.readText()
    }

    /**
     * XML External Entity (XXE) - CWE-611 (Critical)
     * Parsing XML with external entities enabled
     */
    fun parseXml(request: HttpServletRequest): String {
        val xmlData = request.getParameter("xml")
        
        // CRITICAL: XXE - external entity processing
        val factory = javax.xml.parsers.DocumentBuilderFactory.newInstance()
        val builder = factory.newDocumentBuilder()
        val inputSource = org.xml.sax.InputSource(java.io.StringReader(xmlData))
        val doc = builder.parse(inputSource)
        
        return doc.documentElement.textContent
    }

    // ==================== ADDITIONAL CRITICAL VULNERABILITIES ====================

    /**
     * Second-Order SQL Injection - CWE-89 (Critical)
     * SQL injection via stored data
     */
    fun getUserProfile(request: HttpServletRequest): String {
        val userId = request.getParameter("userId")
        val connection = DriverManager.getConnection("jdbc:mysql://localhost/db", "admin", "admin123")
        val stmt = connection.createStatement()
        
        // CRITICAL: SQL Injection with ORDER BY
        val orderBy = request.getParameter("sort")
        val query = "SELECT * FROM users WHERE id = '$userId' ORDER BY $orderBy"
        val rs = stmt.executeQuery(query)
        
        return rs.toString()
    }

    /**
     * Blind SQL Injection - CWE-89 (Critical)
     * Time-based blind SQL injection
     */
    fun checkUserExists(request: HttpServletRequest): Boolean {
        val email = request.getParameter("email")
        val connection = DriverManager.getConnection("jdbc:mysql://localhost/db", "admin", "admin123")
        val stmt = connection.createStatement()
        
        // CRITICAL: Blind SQL Injection
        val query = "SELECT COUNT(*) FROM users WHERE email = '" + email + "'"
        val rs = stmt.executeQuery(query)
        rs.next()
        return rs.getInt(1) > 0
    }

    /**
     * SQL Injection in INSERT - CWE-89 (Critical)
     */
    fun registerUser(request: HttpServletRequest): Boolean {
        val username = request.getParameter("username")
        val email = request.getParameter("email")
        val password = request.getParameter("password")
        
        val connection = DriverManager.getConnection("jdbc:mysql://localhost/db", "admin", "admin123")
        val stmt = connection.createStatement()
        
        // CRITICAL: SQL Injection in INSERT statement
        val query = "INSERT INTO users (username, email, password) VALUES ('$username', '$email', '$password')"
        return stmt.executeUpdate(query) > 0
    }

    /**
     * SQL Injection in UPDATE - CWE-89 (Critical)
     */
    fun updateProfile(request: HttpServletRequest): Boolean {
        val userId = request.getParameter("userId")
        val bio = request.getParameter("bio")
        
        val connection = DriverManager.getConnection("jdbc:mysql://localhost/db", "admin", "admin123")
        val stmt = connection.createStatement()
        
        // CRITICAL: SQL Injection in UPDATE statement
        val query = "UPDATE users SET bio = '$bio' WHERE id = $userId"
        return stmt.executeUpdate(query) > 0
    }

    /**
     * Stored XSS via Database - CWE-79 (Critical)
     */
    fun displayComments(request: HttpServletRequest, response: HttpServletResponse) {
        val postId = request.getParameter("postId")
        val connection = DriverManager.getConnection("jdbc:mysql://localhost/db", "admin", "admin123")
        val stmt = connection.createStatement()
        
        val rs = stmt.executeQuery("SELECT comment_text FROM comments WHERE post_id = $postId")
        
        response.contentType = "text/html"
        val writer = response.writer
        writer.println("<html><body><h1>Comments</h1>")
        
        while (rs.next()) {
            val comment = rs.getString("comment_text")
            // CRITICAL: Stored XSS - displaying unsanitized database content
            writer.println("<div class='comment'>" + comment + "</div>")
        }
        writer.println("</body></html>")
    }

    /**
     * DOM-based XSS - CWE-79 (Critical)
     */
    fun generateScript(request: HttpServletRequest, response: HttpServletResponse) {
        val callback = request.getParameter("callback")
        val data = request.getParameter("data")
        
        response.contentType = "application/javascript"
        val writer = response.writer
        
        // CRITICAL: XSS in JavaScript context
        writer.println("$callback({ \"data\": \"$data\" });")
    }

    /**
     * Template Injection - CWE-94 (Critical)
     */
    fun renderTemplate(request: HttpServletRequest, response: HttpServletResponse) {
        val template = request.getParameter("template")
        val name = request.getParameter("name")
        
        response.contentType = "text/html"
        val writer = response.writer
        
        // CRITICAL: Server-side template injection
        val html = template.replace("{{name}}", name)
        writer.println(html)
    }

    /**
     * Arbitrary File Write - CWE-22 (Critical)
     */
    fun uploadFile(request: HttpServletRequest): String {
        val filename = request.getParameter("filename")
        val content = request.getParameter("content")
        
        // CRITICAL: Arbitrary file write with path traversal
        val file = File("/var/www/uploads/$filename")
        file.writeText(content)
        
        return "File uploaded: $filename"
    }

    /**
     * Arbitrary File Delete - CWE-22 (Critical)
     */
    fun deleteFile(request: HttpServletRequest): Boolean {
        val filename = request.getParameter("filename")
        
        // CRITICAL: Arbitrary file deletion
        val file = File("/var/www/uploads/$filename")
        return file.delete()
    }

    /**
     * Remote Code Execution via eval - CWE-94 (Critical)
     */
    fun executeExpression(request: HttpServletRequest): Any? {
        val expression = request.getParameter("expr")
        
        // CRITICAL: Code injection via script engine
        val engine = javax.script.ScriptEngineManager().getEngineByName("JavaScript")
        return engine.eval(expression)
    }

    /**
     * Insecure Object Binding - CWE-915 (Critical)
     * Mass assignment vulnerability
     */
    fun updateUser(request: HttpServletRequest): String {
        val userId = request.getParameter("userId")
        val role = request.getParameter("role")  // Should not be user-controllable
        val isAdmin = request.getParameter("isAdmin")  // Privilege escalation
        
        val connection = DriverManager.getConnection("jdbc:mysql://localhost/db", "admin", "admin123")
        val stmt = connection.createStatement()
        
        // CRITICAL: Mass assignment allowing privilege escalation
        val query = "UPDATE users SET role = '$role', is_admin = '$isAdmin' WHERE id = $userId"
        stmt.executeUpdate(query)
        
        return "User updated"
    }

    /**
     * LDAP Injection - CWE-90 (Critical)
     */
    fun authenticateLdap(request: HttpServletRequest): Boolean {
        val username = request.getParameter("username")
        val password = request.getParameter("password")
        
        // CRITICAL: LDAP Injection
        val filter = "(&(uid=$username)(userPassword=$password))"
        
        val env = java.util.Hashtable<String, String>()
        env["java.naming.factory.initial"] = "com.sun.jndi.ldap.LdapCtxFactory"
        env["java.naming.provider.url"] = "ldap://localhost:389"
        
        return filter.isNotEmpty()
    }

    /**
     * NoSQL Injection - CWE-943 (Critical)
     */
    fun findDocument(request: HttpServletRequest): String {
        val query = request.getParameter("query")
        
        // CRITICAL: NoSQL Injection - MongoDB style
        val mongoQuery = "{ \"name\": \"$query\" }"
        return "Executing: $mongoQuery"
    }

    /**
     * XML Injection - CWE-91 (Critical)
     */
    fun createXmlDocument(request: HttpServletRequest): String {
        val name = request.getParameter("name")
        val email = request.getParameter("email")
        
        // CRITICAL: XML Injection
        return """
            <?xml version="1.0"?>
            <user>
                <name>$name</name>
                <email>$email</email>
            </user>
        """.trimIndent()
    }

    /**
     * Regex Denial of Service (ReDoS) - CWE-1333 (High)
     */
    fun validateInput(request: HttpServletRequest): Boolean {
        val input = request.getParameter("input")
        
        // CRITICAL: ReDoS - evil regex with catastrophic backtracking
        val pattern = "(a+)+$".toRegex()
        return pattern.matches(input)
    }

    /**
     * Insecure Cryptography - CWE-327 (High)
     */
    fun encryptData(request: HttpServletRequest): ByteArray {
        val data = request.getParameter("data")
        
        // CRITICAL: Using weak/broken encryption (DES)
        val cipher = javax.crypto.Cipher.getInstance("DES/ECB/PKCS5Padding")
        val key = javax.crypto.spec.SecretKeySpec("12345678".toByteArray(), "DES")
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key)
        
        return cipher.doFinal(data.toByteArray())
    }

    /**
     * Insecure Random - CWE-330 (High)
     */
    fun generateToken(request: HttpServletRequest): String {
        // CRITICAL: Using insecure random for security token
        val random = java.util.Random()
        val token = StringBuilder()
        repeat(32) {
            token.append(random.nextInt(16).toString(16))
        }
        return token.toString()
    }

    /**
     * Cleartext Transmission - CWE-319 (High)
     */
    fun sendSensitiveData(request: HttpServletRequest): String {
        val creditCard = request.getParameter("cc")
        val ssn = request.getParameter("ssn")
        
        // CRITICAL: Transmitting sensitive data over HTTP
        val url = java.net.URL("http://api.example.com/process?cc=$creditCard&ssn=$ssn")
        return url.readText()
    }

    /**
     * Hardcoded IV - CWE-329 (High)
     */
    fun encryptWithIV(request: HttpServletRequest): ByteArray {
        val data = request.getParameter("data")
        
        // CRITICAL: Hardcoded IV makes encryption predictable
        val iv = "1234567890123456".toByteArray()
        val ivSpec = javax.crypto.spec.IvParameterSpec(iv)
        
        val cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding")
        val key = javax.crypto.spec.SecretKeySpec("0123456789abcdef".toByteArray(), "AES")
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key, ivSpec)
        
        return cipher.doFinal(data.toByteArray())
    }
}
