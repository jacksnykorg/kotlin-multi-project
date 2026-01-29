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
}
