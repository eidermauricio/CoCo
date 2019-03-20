#### Rule 1: HTTP request redirections should not be open to forging attacks
##### Quality Category: Vulnerability
User provided data, such as URL parameters, POST data payloads, or cookies, should always be considered untrusted and tainted. Applications performing HTTP redirects based on tainted data could enable an attacker to redirect users to a malicious site to, for example, steal login credentials.

This problem could be mitigated in any of the following ways:

 Validate the user provided data based on a whitelist and reject input not matching.
 Redesign the application to not perform redirects based on user provided data.
**Noncompliant Code Example**
```java
protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
  String location = req.getParameter("url");
  resp.sendRedirect(location); // Noncompliant
}


```
**Compliant Solution**
```java
protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
  String location = req.getParameter("url");

  // Match the incoming URL against a whitelist
  if (!urlWhiteList.contains(location))
    throw new IOException();

  resp.sendRedirect(location);
}


*See*

OWASP Top 10 2017 - Category A5 - Broken Access Control
MITRE, CWE-601 - URL Redirection to Untrusted Site ('Open Redirect')
SANS Top 25 - Risky Resource Management
#### Rule 2: Endpoints should not be vulnerable to reflected cross-site scripting (XSS) attacks
##### Quality Category: Vulnerability
User provided data, such as URL parameters, POST data payloads, or cookies, should always be considered untrusted and tainted. Endpoints reflecting back tainted data could allow attackers to inject code that would eventually be executed in the user's browser. This could enable a wide range of serious attacks like accessing/modifying sensitive information or impersonating other users.

Typically, the solution is one of the following:

 Validate user provided data based on a whitelist and reject input that's not whitelisted.
 Sanitize user provided data from any characters that can be used for malicious purposes.
 Encode user provided data being reflected as output. Adjust the encoding to the output context so that, for example, HTML encoding is used for HTML content, HTML attribute encoding is used for attribute values, and JavaScript encoding is used for server-generated JavaScript.

When sanitizing or encoding data, it is recommended to only use libraries specifically designed for security purposes. Also, make sure that the library you are using is being actively maintained and is kept up-to-date with the latest discovered vulnerabilities.

**Noncompliant Code Example**
```java
protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
  String name = req.getParameter("name");
  PrintWriter out = resp.getWriter();
  out.write("Hello " + name); // Noncompliant
}


```
**Compliant Solution**
```java
protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
  String name = req.getParameter("name");
  String encodedName = org.owasp.encoder.Encode.forHtml(name);
  PrintWriter out = resp.getWriter();
  out.write("Hello " + encodedName);
}


*See*

OWASP Cheat Sheet - XSS Prevention Cheat Sheet
OWASP Top 10 2017 - Category A7 - Cross-Site Scripting (XSS)
MITRE, CWE-79 - Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
MITRE, CWE-80 - Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
MITRE, CWE-81 - Improper Neutralization of Script in an Error Message Web Page
MITRE, CWE-82 - Improper Neutralization of Script in Attributes of IMG Tags in a Web Page
MITRE, CWE-83 - Improper Neutralization of Script in Attributes in a Web Page
MITRE, CWE-84 - Improper Neutralization of Encoded URI Schemes in a Web Page
MITRE, CWE-85 - Doubled Character XSS Manipulations
MITRE, CWE-86 - Improper Neutralization of Invalid Characters in Identifiers in Web Pages
MITRE, CWE-87 - Improper Neutralization of Alternate XSS Syntax
SANS Top 25 - Insecure Interaction Between Components
#### Rule 3: LDAP deserialization should be disabled
##### Quality Category: Vulnerability
JNDI supports the deserialization of objects from LDAP directories, which is fundamentally insecure and can lead to remote code execution.

This rule raises an issue when an LDAP search query is executed with SearchControls configured to allow deserialization.

**Noncompliant Code Example**
```java
DirContext ctx = new InitialDirContext();
// ...
ctx.search(query, filter,
        new SearchControls(scope, countLimit, timeLimit, attributes,
            true, // Noncompliant; allows deserialization
            deref));


```
**Compliant Solution**
```java
DirContext ctx = new InitialDirContext();
// ...
ctx.search(query, filter,
        new SearchControls(scope, countLimit, timeLimit, attributes,
            false,
            deref));


*See*

MITRE, CWE-502 - Deserialization of Untrusted Data
 OWASP Top 10 2017 Category A8 - Insecure Deserialization
BlackHat presentation
 Derived from FindSecBugs rule LDAP_ENTRY_POISONING
#### Rule 4: Cryptographic keys should not be too short
##### Quality Category: Vulnerability
When generating cryptographic keys (or key pairs), it is important to use a key length that provides enough entropy against brute-force attacks. For the Blowfish algorithm the key should be at least 128 bits long, while for the RSA algorithm it should be at least 2048 bits long.

This rule raises an issue when a Blowfish key generator or RSA key-pair generator is initialized with too small a length parameter.

**Noncompliant Code Example**
```java
KeyGenerator keyGen = KeyGenerator.getInstance("Blowfish");
keyGen.init(64); // Noncompliant

KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
keyPairGen.initialize(512); // Noncompliant


```
**Compliant Solution**
```java
KeyGenerator keyGen = KeyGenerator.getInstance("Blowfish");
keyGen.init(128);

KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
keyPairGen.initialize(2048);


*See*

MITRE, CWE-326 - Inadequate Encryption Strength
 OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
 Derived from FindSecBugs rule BLOWFISH_KEY_SIZE
 Derived from FindSecBugs rule RSA_KEY_SIZE
#### Rule 5: "@RequestMapping" methods should specify HTTP method
##### Quality Category: Vulnerability
A @RequestMapping method handles all matching requests by default. That means that a method you intended only to be POST-ed to could also be called by a GET, thereby allowing hackers to call the method inappropriately. For example a "transferFunds" method might be invoked like so: <img src="http://bank.com/actions/transferFunds?reciepientRouting=000000&receipientAccount=11111111&amount=200.00" width="1" height="1"/>

For that reason, you should always explicitly list the single HTTP method with which you expect your @RequestMapping Java method to be called. This rule raises an issue when method is missing.

**Noncompliant Code Example**
```java
@RequestMapping("/greet")  // Noncompliant
public String greet(String greetee) {


```
**Compliant Solution**
```java
  @RequestMapping("/greet", method = GET)
  public String greet(String greetee) {


*See*

MITRE, CWE-352 - Cross-Site Request Forgery (CSRF)
 OWASP Top 10 2017 Category A6 - Security Misconfiguration
OWASP: Cross-Site Request Forgery
SANS Top 25 - Insecure Interaction Between Components
Spring Security Official Documentation: Use proper HTTP verbs (CSRF protection)
#### Rule 6: "@RequestMapping" methods should be "public"
##### Quality Category:
A method with a @RequestMapping annotation part of a class annotated with @Controller (directly or indirectly through a meta annotation - @RestController from Spring Boot is a good example) will be called to handle matching web requests. That will happen even if the method is private, because Spring invokes such methods via reflection, without checking visibility.

So marking a sensitive method private may seem like a good way to control how such code is called. Unfortunately, not all Spring frameworks ignore visibility in this way. For instance, if you've tried to control web access to your sensitive, private, @RequestMapping method by marking it @Secured ... it will still be called, whether or not the user is authorized to access it. That's because AOP proxies are not applied to non-public methods.

In addition to @RequestMapping, this rule also considers the annotations introduced in Spring Framework 4.3: @GetMapping, @PostMapping, @PutMapping, @DeleteMapping, @PatchMapping.

**Noncompliant Code Example**
```java
@RequestMapping("/greet", method = GET)
private String greet(String greetee) {  // Noncompliant


```
**Compliant Solution**
```java
@RequestMapping("/greet", method = GET)
public String greet(String greetee) {


*See*

 OWASP Top 10 2017 Category A6 - Security Misconfiguration
#### Rule 7: SQL queries should not be vulnerable to injection attacks
##### Quality Category: Vulnerability
User provided data, such as URL parameters, should always be considered untrusted and tainted. Constructing SQL queries directly from tainted data enables attackers to inject specially crafted values that change the initial meaning of the query itself. Successful SQL injection attacks can read, modify, or delete sensitive information from the database and sometimes even shut it down or execute arbitrary operating system commands.

Typically, the solution is to rely on prepared statements rather than string concatenation to inject tainted data into SQL queries, which ensures that they will be properly escaped.

**Noncompliant Code Example**
```java
public boolean authenticate(javax.servlet.http.HttpServletRequest request, java.sql.Connection connection) throws SQLException {
  String user = request.getParameter("user");
  String pass = request.getParameter("pass");

  String query = "SELECT * FROM users WHERE user = '" + user + "' AND pass = '" + pass + "'"; // Unsafe

  // If the special value "foo' OR 1=1 --" is passed as either the user or pass, authentication is bypassed
  // Indeed, if it is passed as a user, the query becomes:
  // SELECT * FROM users WHERE user = 'foo' OR 1=1 --' AND pass = '...'
  // As '--' is the comment till end of line syntax in SQL, this is equivalent to:
  // SELECT * FROM users WHERE user = 'foo' OR 1=1
  // which is equivalent to:
  // SELECT * FROM users WHERE 1=1
  // which is equivalent to:
  // SELECT * FROM users

  java.sql.Statement statement = connection.createStatement();
  java.sql.ResultSet resultSet = statement.executeQuery(query); // Noncompliant
  return resultSet.next();
}


```
**Compliant Solution**
```java
public boolean authenticate(javax.servlet.http.HttpServletRequest request, java.sql.Connection connection) throws SQLException {
  String user = request.getParameter("user");
  String pass = request.getParameter("pass");

  String query = "SELECT * FROM users WHERE user = ? AND pass = ?"; // Safe even if authenticate() method is still vulnerable to brute-force attack in this specific case

  java.sql.PreparedStatement statement = connection.prepareStatement(query);
  statement.setString(1, user); // Will be properly escaped
  statement.setString(2, pass);
  java.sql.ResultSet resultSet = statement.executeQuery();
  return resultSet.next();
}


*See*

MITRE, CWE-89 - Improper Neutralization of Special Elements used in an SQL Command
MITRE, CWE-564 - SQL Injection: Hibernate
MITRE, CWE-20 - Improper Input Validation
MITRE, CWE-943 - Improper Neutralization of Special Elements in Data Query Logic
CERT, IDS00-J. - Prevent SQL injection
 OWASP Top 10 2017 Category A1 - Injection
SANS Top 25 - Insecure Interaction Between Components
#### Rule 8: "HostnameVerifier.verify" should not always return true
##### Quality Category: Vulnerability
To prevent URL spoofing, HostnameVerifier.verify() methods should do more than simply return true. Doing so may get you quickly past an exception, but that comes at the cost of opening a security hole in your application.

**Noncompliant Code Example**
```java
SSLContext sslcontext = SSLContext.getInstance( "TLS" );
sslcontext.init(null, new TrustManager[]{new X509TrustManager() {
  public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
  public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
  public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }

}}, new java.security.SecureRandom());

Client client = ClientBuilder.newBuilder().sslContext(sslcontext).hostnameVerifier(new HostnameVerifier() {
  @Override
  public boolean verify(String requestedHost, SSLSession remoteServerSession) {
    return true;  // Noncompliant
  }
}).build();


```
**Compliant Solution**
```java
SSLContext sslcontext = SSLContext.getInstance( "TLSv1.2" );
sslcontext.init(null, new TrustManager[]{new X509TrustManager() {
  @Override
  public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
  @Override
  public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
  @Override
  public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }

}}, new java.security.SecureRandom());

Client client = ClientBuilder.newBuilder().sslContext(sslcontext).hostnameVerifier(new HostnameVerifier() {
  @Override
  public boolean verify(String requestedHost, SSLSession remoteServerSession) {
    return requestedHost.equalsIgnoreCase(remoteServerSession.getPeerHost()); // Compliant
  }
}).build();


*See*

MITRE, CWE-295 - Improper Certificate Validation
 OWASP Top 10 2017 Category A6 - Security Misconfiguration
 Derived from FindSecBugs rule WEAK_HOSTNAME_VERIFIER
#### Rule 9: Struts validation forms should have unique names
##### Quality Category: Vulnerability
According to the Common Weakness Enumeration,

If two validation forms have the same name, the Struts Validator arbitrarily chooses one of the forms to use for input validation and discards the other. This decision might not correspond to the programmer's expectations...

In such a case, it is likely that the two forms should be combined. At the very least, one should be removed.

**Noncompliant Code Example**
```java
<form-validation>
  <formset>
    <form name="BookForm"> ... </form>
    <form name="BookForm"> ... </form>  <!-- Noncompliant -->
  </formset>
</form-validation>


```
**Compliant Solution**
```java
<form-validation>
  <formset>
    <form name="BookForm"> ... </form>
  </formset>
</form-validation>


*See*

MITRE, CWE-102 - Struts: Duplicate Validation Forms
OWASP, Improper Data Validation - Struts: Duplicate Validation Forms
#### Rule 10: Default EJB interceptors should be declared in "ejb-jar.xml"
##### Quality Category: Vulnerability
Default interceptors, such as application security interceptors, must be listed in the ejb-jar.xml file, or they will not be treated as default.

This rule applies to projects that contain JEE Beans (any one of javax.ejb.Singleton, MessageDriven, Stateless or Stateful).

**Noncompliant Code Example**
```java
// file: ejb-interceptors.xml
<assembly-descriptor>
 <interceptor-binding> <!-- should be declared in ejb-jar.xml -->
      <ejb-name>*</ejb-name>
      <interceptor-class>com.myco.ImportantInterceptor</interceptor-class><!-- Noncompliant; will NOT be treated as default -->
   </interceptor-binding>
</assembly-descriptor>


```
**Compliant Solution**
```java
// file: ejb-jar.xml
<assembly-descriptor>
 <interceptor-binding>
      <ejb-name>*</ejb-name>
      <interceptor-class>com.myco.ImportantInterceptor</interceptor-class>
   </interceptor-binding>
</assembly-descriptor>


*See*

 OWASP Top 10 2017 Category A6 - Security Misconfiguration
#### Rule 11: Untrusted XML should be parsed with a local, static DTD
##### Quality Category: Vulnerability
Allowing external entities in untrusted documents to be processed could lay your systems bare to attackers. Imagine if these entities were parsed:

<!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
<!ENTITY xxe SYSTEM "http://www.attacker.com/text.txt" >]><foo>&xxe;</foo>


If you must parse untrusted XML, the best way to protect yourself is to use a local, static DTD during parsing and igore any DTD's included in included in the document.

This rule raises an issue when any of the following are used without first disabling external entity processing: javax.xml.validation.Validator, JAXP's DocumentBuilderFactory, SAXParserFactory, Xerces 1 and Xerces 2 StAX's XMLInputFactory and XMLReaderFactory.

To disable external entity processing for XMLInputFactory, configure one of the properties XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES or XMLInputFactory.SUPPORT_DTD to false.

To disable external entity processing for SAXParserFactory, XMLReader or DocumentBuilderFactory configure one of the properties XMLConstants.FEATURE_SECURE_PROCESSING or "http://apache.org/xml/features/disallow-doctype-decl" to true.

To disable external entity processing for Validator , configure both properties XMLConstants.ACCESS_EXTERNAL_DTD, XMLConstants.ACCESS_EXTERNAL_SCHEMA to the empty string "".

**Noncompliant Code Example**
```java
/* Load XML stream and display content */
String maliciousSample = "xxe.xml";
XMLInputFactory factory = XMLInputFactory.newInstance();

try (FileInputStream fis = new FileInputStream(malicousSample)) {
  // Load XML stream
  XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(fis);  // Noncompliant; reader is vulnerable

  //...


```
**Compliant Solution**
```java
/* Load XML stream and display content */
String maliciousSample = "xxe.xml";
XMLInputFactory factory = XMLInputFactory.newInstance();

// disable external entities
factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.FALSE);
factory.setProperty(XMLInputFactory.SUPPORT_DTD, Boolean.FALSE);

try (FileInputStream fis = new FileInputStream(malicousSample)) {
    // Load XML stream
    XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(fis);


*See*

MITRE, CWE-611 - Information Exposure Through XML External Entity Reference
MITRE, CWE-827 - Improper Control of Document Type Definition
 OWASP Top 10 2017 Category A1 - Injection
 OWASP Top 10 2017 Category A4 - XML External Entities (XXE)
OWASP XXE Prevention Cheat Sheet
 Derived from FindSecBugs rule XXE_XMLSTREAMREADER
 Derived from FindSecBugs rule XXE_SAXPARSER
 Derived from FindSecBugs rule XXE_XMLREADER
 Derived from FindSecBugs rule XXE_DOCUMENT
#### Rule 12: Regular expressions should not be vulnerable to Denial of Service attacks
##### Quality Category: Vulnerability
Evaluating regular expressions against input strings can be an extremely CPU-intensive task. For example, a specially crafted regular expression such as (a+)++ will take several seconds to evaluate the input string, aaaaaaaaaaaaaaaaaaaaaaaaaaaaa!. The problem is that every additional "a" added to the input doubles the time required to evaluate the regex. However, the equivalent regular expression, a (without grouping), is efficiently evaluated in milliseconds and scales linearly with the input size.

Evaluating user-provided strings as regular expressions opens the door for Denial Of Service attacks. In the context of a web application, attackers can force the web server to spend all of its resources evaluating regular expressions thereby making the service inaccessible to genuine users.

**Noncompliant Code Example**
```java
public boolean validate(javax.servlet.http.HttpServletRequest request) {
  String regex = request.getParameter("regex");
  String input = request.getParameter("input");

  // Enables attackers to force the web server to evaluate
  // regex such as "(a+)+" on inputs such as "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"

  input.matches(regex);  // Noncompliant
}


```
**Compliant Solution**
```java
public boolean validate(javax.servlet.http.HttpServletRequest request) {
  String input = request.getParameter("input");

  input.matches("a+");  // Compliant - use a safe hardcoded regex
}


*See*

OWASP Regular expression Denial of Service - ReDoS
 OWASP Top 10 2017 Category A1 - Injection
#### Rule 13: Neither DES (Data Encryption Standard) nor DESede (3DES) should be used
##### Quality Category: Vulnerability
According to the US National Institute of Standards and Technology (NIST), the Data Encryption Standard (DES) is no longer considered secure:

Adopted in 1977 for federal agencies to use in protecting sensitive, unclassified information, the DES is being withdrawn because it no longer provides the security that is needed to protect federal government information.

Federal agencies are encouraged to use the Advanced Encryption Standard, a faster and stronger algorithm approved as FIPS 197 in 2001.

For similar reasons, RC2 should also be avoided.

**Noncompliant Code Example**
```java
Cipher c = Cipher.getInstance("DESede/ECB/PKCS5Padding");


```
**Compliant Solution**
```java
Cipher c = Cipher.getInstance("AES/GCM/NoPadding");


*See*

MITRE, CWE-326 - Inadequate Encryption Strength
MITRE, CWE-327 - Use of a Broken or Risky Cryptographic Algorithm
 OWASP Top 10 2017 Category A6 - Security Misconfiguration
CERT, MSC61-J. - Do not use insecure or weak cryptographic algorithms
SANS Top 25 - Porous Defenses
 Derived from FindSecBugs rule DES / DESede Unsafe
#### Rule 14: "javax.crypto.NullCipher" should not be used for anything other than testing
##### Quality Category: Vulnerability
By contract, the NullCipher class provides an "identity cipher" one that does not transform or encrypt the plaintext in any way. As a consequence, the ciphertext is identical to the plaintext. So this class should be used for testing, and never in production code.

**Noncompliant Code Example**
```java
NullCipher nc = new NullCipher();


*See*

CWE-327 - Use of a Broken or Risky Cryptographic Algorithm
 OWASP Top 10 2017 Category A6 - Security Misconfiguration
SANS Top 25 - Porous Defenses
#### Rule 15: Databases should be password-protected
##### Quality Category: Vulnerability
Failure to password-protect a database is so careless or naive as to be almost negligent. Databases should always be password protected, but the use of a database connection with an empty password is a clear indication of a database that is not protected.

This rule flags database connections with empty passwords.

**Noncompliant Code Example**
```java
Connection conn = DriverManager.getConnection("jdbc:derby:memory:myDB;create=true", "AppLogin", "");
Connection conn2 = DriverManager.getConnection("jdbc:derby:memory:myDB;create=true?user=user&password=");


```
**Compliant Solution**
```java
DriverManager.getConnection("jdbc:derby:memory:myDB;create=true?user=user&password=password");

DriverManager.getConnection("jdbc:mysql://address=(host=myhost1)(port=1111)(key1=value1)(user=sandy)(password=secret),address=(host=myhost2)(port=2222)(key2=value2)(user=sandy)(password=secret)/db");

DriverManager.getConnection("jdbc:mysql://sandy:secret@[myhost1:1111,myhost2:2222]/db");

String url = "jdbc:postgresql://localhost/test";
Properties props = new Properties();
props.setProperty("user", "fred");
props.setProperty("password", "secret");
DriverManager.getConnection(url, props);


*See*

 OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
#### Rule 16: XPath expressions should not be vulnerable to injection attacks
##### Quality Category: Vulnerability
User provided data, such as URL parameters, should always be considered untrusted and tainted. Constructing XPath expressions directly from tainted data enables attackers to inject specially crafted values that changes the initial meaning of the expression itself. Successful XPath injection attacks can read sensitive information from XML documents.

**Noncompliant Code Example**
```java
public boolean authenticate(javax.servlet.http.HttpServletRequest request, javax.xml.xpath.XPath xpath, org.w3c.dom.Document doc) throws XPathExpressionException {
  String user = request.getParameter("user");
  String pass = request.getParameter("pass");

  String expression = "/users/user[@name='" + user + "' and @pass='" + pass + "']"; // Unsafe

  // An attacker can bypass authentication by setting user to this special value
  user = "' or 1=1 or ''='";

  return (boolean)xpath.evaluate(expression, doc, XPathConstants.BOOLEAN); // Noncompliant
}


```
**Compliant Solution**
```java
public boolean authenticate(javax.servlet.http.HttpServletRequest request, javax.xml.xpath.XPath xpath, org.w3c.dom.Document doc) throws XPathExpressionException {
  String user = request.getParameter("user");
  String pass = request.getParameter("pass");

  String expression = "/users/user[@name=$user and @pass=$pass]";

  xpath.setXPathVariableResolver(v -> {
    switch (v.getLocalPart()) {
      case "user":
        return user;
      case "pass":
        return pass;
      default:
        throw new IllegalArgumentException();
    }
  });

  return (boolean)xpath.evaluate(expression, doc, XPathConstants.BOOLEAN);
}


*See*

MITRE, CWE-643 - Improper Neutralization of Data within XPath Expressions
 OWASP Top 10 2017 Category A1 - Injection
CERT, IDS53-J. - Prevent XPath Injection
#### Rule 17: I/O function calls should not be vulnerable to path injection attacks
##### Quality Category: Vulnerability
User provided data, such as URL parameters, POST data payloads, or cookies, should always be considered untrusted and tainted. Constructing file system paths directly from tainted data could enable an attacker to inject specially crafted values, such as '../', that change the initial path and, when accessed, resolve to a path on the filesystem where the user should normally not have access.

A successful attack might give an attacker the ability to read, modify, or delete sensitive information from the file system and sometimes even execute arbitrary operating system commands. This is often referred to as a "path traversal" or "directory traversal" attack.

The mitigation strategy should be based on the whitelisting of allowed paths or characters.

**Noncompliant Code Example**
```java
public boolean authenticate(javax.servlet.http.HttpServletRequest request) {
  String user = request.getParameter("user");

  // If the special value "../bin" is passed as user, authentication is bypassed
  // Indeed, if it passed as a user, the path becomes:
  // /bin
  // which exists on most Linux / BSD / Mac OS distributions

  return Files.exists(Paths.get("/home/", user)); // Noncompliant
}


```
**Compliant Solution**
```java
public boolean authenticate(javax.servlet.http.HttpServletRequest request) {
  String user = request.getParameter("user");

  // Restrict the username to letters and digits only
  if (!user.matches("[a-zA-Z0-9]++")) {
    return false;
  }

  return Files.exists(Paths.get("/home/", user));
}


*See*

MITRE, CWE-22 - Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
MITRE, CWE-23 - Relative Path Traversal
MITRE, CWE-36 - Absolute Path Traversal
MITRE, CWE-99 - Improper Control of Resource Identifiers ('Resource Injection')
MITRE, CWE-641 - Improper Restriction of Names for Files and Other Resources
 OWASP Top 10 2017 Category A5 - Broken Access Control
SANS Top 25 - Risky Resource Management
#### Rule 18: LDAP queries should not be vulnerable to injection attacks
##### Quality Category: Vulnerability
User provided data such as URL parameters should always be considered as untrusted and tainted. Constructing LDAP names or search filters directly from tainted data enables attackers to inject specially crafted values that changes the initial meaning of the name or filter itself. Successful LDAP injections attacks can read, modify or delete sensitive information from the directory service.

Within LDAP names, the special characters ' ', '#', '"', '+', ',', ';', '<', '>', '\' and null must be escaped according to RFC 4514, for example by replacing them with the backslash character '\' followed by the two hex digits corresponding to the ASCII code of the character to be escaped. Similarly, LDAP search filters must escape a different set of special characters (including but not limited to '*', '(', ')', '\' and null) according to RFC 4515.

**Noncompliant Code Example**
```java
public boolean authenticate(javax.servlet.http.HttpServletRequest request, DirContext ctx) throws NamingException {
  String user = request.getParameter("user");
  String pass = request.getParameter("pass");

  String filter = "(&(uid=" + user + ")(userPassword=" + pass + "))"; // Unsafe

  // If the special value "*)(uid=*))(|(uid=*" is passed as user, authentication is bypassed
  // Indeed, if it is passed as a user, the filter becomes:
  // (&(uid=*)(uid=*))(|(uid=*)(userPassword=...))
  // as uid=* match all users, it is equivalent to:
  // (|(uid=*)(userPassword=...))
  // again, as uid=* match all users, the filter becomes useless

  NamingEnumeration<SearchResult> results = ctx.search("ou=system", filter, new SearchControls()); // Noncompliant
  return results.hasMore();
}


```
**Compliant Solution**
```java
public boolean authenticate(javax.servlet.http.HttpServletRequest request, DirContext ctx) throws NamingException {
  String user = request.getParameter("user");
  String pass = request.getParameter("pass");

  String filter = "(&(uid={0})(userPassword={1}))"; // Safe

  NamingEnumeration<SearchResult> results = ctx.search("ou=system", filter, new String[]{user, pass}, new SearchControls());
  return results.hasMore();
}


*See*

RFC 4514 - LDAP: String Representation of Distinguished Names
RFC 4515 - LDAP: String Representation of Search Filters
MITRE CWE-90 - Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')
 OWASP Top 10 2017 Category A1 - Injection
CERT, IDS54-J. - Prevent LDAP injection
#### Rule 19: OS commands should not be vulnerable to injection attacks
##### Quality Category: Vulnerability
Applications that execute operating system commands or execute commands that interact with the underlying system should neutralize any externally-provided values used in those commands. Failure to do so could allow an attacker to include input that executes unintended commands or exposes sensitive data.

The mitigation strategy should be based on whitelisting of allowed characters or commands.

**Noncompliant Code Example**
```java
public void run(javax.servlet.http.HttpServletRequest request) throws IOException {
  String binary = request.getParameter("binary");

  // If the value "/sbin/shutdown" is passed as binary and the web server is running as root,
  // then the machine running the web server will be shut down and become unavailable for future requests

  Runtime.getRuntime().exec(binary); // Noncompliant
}


```
**Compliant Solution**
```java
public void run(javax.servlet.http.HttpServletRequest request) throws IOException {
  String binary = request.getParameter("binary");

  // Restrict to binaries within the current working directory whose name only contains letters
  if (!binary.matches("[a-zA-Z]++")) {
    throw new IllegalArgumentException();
  }

  Runtime.getRuntime().exec(binary);
}


*See*

MITRE, CWE-78 - Improper Neutralization of Special Elements used in an OS Command
MITRE, CWE-88 - Argument Injection or Modification
 OWASP Top 10 2017 Category A1 - Injection
SANS Top 25 - Insecure Interaction Between Components
#### Rule 20: Credentials should not be hard-coded
##### Quality Category: Vulnerability
Because it is easy to extract strings from a compiled application, credentials should never be hard-coded. Do so, and they're almost guaranteed to end up in the hands of an attacker. This is particularly true for applications that are distributed.

Credentials should be stored outside of the code in a strongly-protected encrypted configuration file or database.

It's recommended to customize the configuration of this rule with additional credential words such as "oauthToken", "secret", ...

**Noncompliant Code Example**
```java
Connection conn = null;
try {
  conn = DriverManager.getConnection("jdbc:mysql://localhost/test?" +
        "user=steve&password=blue"); // Noncompliant
  String uname = "steve";
  String password = "blue";
  conn = DriverManager.getConnection("jdbc:mysql://localhost/test?" +
        "user=" + uname + "&password=" + password); // Noncompliant

  java.net.PasswordAuthentication pa = new java.net.PasswordAuthentication("userName", "1234".toCharArray());  // Noncompliant


```
**Compliant Solution**
```java
Connection conn = null;
try {
  String uname = getEncryptedUser();
  String password = getEncryptedPass();
  conn = DriverManager.getConnection("jdbc:mysql://localhost/test?" +
        "user=" + uname + "&password=" + password);


*See*

MITRE, CWE-798 - Use of Hard-coded Credentials
MITRE, CWE-259 - Use of Hard-coded Password
CERT, MSC03-J. - Never hard code sensitive information
 OWASP Top 10 2017 Category A2 - Broken Authentication
SANS Top 25 - Porous Defenses
 Derived from FindSecBugs rule Hard Coded Password
#### Rule 21: "@SpringBootApplication" and "@ComponentScan" should not be used in the default package
##### Quality Category: Bug
@ComponentScan is used to determine which Spring Beans are available in the application context. The packages to scan can be configured thanks to the basePackageClasses or basePackages (or its alias value) parameters. If neither parameter is configured, @ComponentScan will consider only the package of the class annotated with it. When @ComponentScan is used on a class belonging to the default package, the entire classpath will be scanned.

This will slow-down the start-up of the application and it is likely the application will fail to start with an BeanDefinitionStoreException because you ended up scanning the Spring Framework package itself.

This rule raises an issue when:

- @ComponentScan, @SpringBootApplication and @ServletComponentScan are used on a class belonging to the default package

- @ComponentScan is explicitly configured with the default package

**Noncompliant Code Example**
```java
import org.springframework.boot.SpringApplication;

@SpringBootApplication // Noncompliant; RootBootApp is declared in the default package
public class RootBootApp {
...
}

@ComponentScan("")
public class Application {
...
}


```
**Compliant Solution**
```java
package hello;

import org.springframework.boot.SpringApplication;

@SpringBootApplication // Compliant; RootBootApp belongs to the "hello" package
public class RootBootApp {
...
}
```
#### Rule 22: "@Controller" classes that use "@SessionAttributes" must call "setComplete" on their "SessionStatus" objects
##### Quality Category: Bug
A Spring @Controller that uses @SessionAttributes is designed to handle a stateful / multi-post form. Such @Controllers use the specified @SessionAttributes to store data on the server between requests. That data should be cleaned up when the session is over, but unless setComplete() is called on the SessionStatus object from a @RequestMapping method, neither Spring nor the JVM will know it's time to do that. Note that the SessionStatus object must be passed to that method as a parameter.

**Noncompliant Code Example**
```java
@Controller
@SessionAttributes("hello")  // Noncompliant; this doesn't get cleaned up
public class HelloWorld {

  @RequestMapping("/greet", method = GET)
  public String greet(String greetee) {

    return "Hello " + greetee;
  }
}


```
**Compliant Solution**
```java
@Controller
@SessionAttributes("hello")
public class HelloWorld {

  @RequestMapping("/greet", method = GET)
  public String greet(String greetee) {

    return "Hello " + greetee;
  }

  @RequestMapping("/goodbye", method = POST)
  public String goodbye(SessionStatus status) {
    //...
    status.setComplete();
  }

}
```
#### Rule 23: "wait" should not be called when multiple locks are held
##### Quality Category: Bug
When two locks are held simultaneously, a wait call only releases one of them. The other will be held until some other thread requests a lock on the awaited object. If no unrelated code tries to lock on that object, then all other threads will be locked out, resulting in a deadlock.

**Noncompliant Code Example**
```java
synchronized (this.mon1) {  // threadB can't enter this block to request this.mon2 lock & release threadA
	synchronized (this.mon2) {
		this.mon2.wait();  // Noncompliant; threadA is stuck here holding lock on this.mon1
	}
}
```
#### Rule 24: "PreparedStatement" and "ResultSet" methods should be called with valid indices
##### Quality Category: Bug
The parameters in a PreparedStatement are numbered from 1, not 0, so using any "set" method of a PreparedStatement with a number less than 1 is a bug, as is using an index higher than the number of parameters. Similarly, ResultSet indices also start at 1, rather than 0

**Noncompliant Code Example**
```java
PreparedStatement ps = con.prepareStatement("SELECT fname, lname FROM employees where hireDate > ? and salary < ?");
ps.setDate(0, date);  // Noncompliant
ps.setDouble(3, salary);  // Noncompliant

ResultSet rs = ps.executeQuery();
while (rs.next()) {
  String fname = rs.getString(0);  // Noncompliant
  // ...
}


```
**Compliant Solution**
```java
PreparedStatement ps = con.prepareStatement("SELECT fname, lname FROM employees where hireDate > ? and salary < ?");
ps.setDate(1, date);
ps.setDouble(2, salary);

ResultSet rs = ps.executeQuery();
while (rs.next()) {
  String fname = rs.getString(1);
  // ...
}
```
#### Rule 25: Files opened in append mode should not be used with ObjectOutputStream
##### Quality Category: Bug
ObjectOutputStreams are used with serialization, and the first thing an ObjectOutputStream writes is the serialization stream header. This header should appear once per file, at the beginning. Pass a file opened in append mode into an ObjectOutputStream constructor and the serialization stream header will be added to the end of the file before your object is then also appended.

When you're trying to read your object(s) back from the file, only the first one will be read successfully, and a StreamCorruptedException will be thrown after that.

**Noncompliant Code Example**
```java
FileOutputStream fos = new FileOutputStream (fileName , true);  // fos opened in append mode
ObjectOutputStream out = new ObjectOutputStream(fos);  // Noncompliant


```
**Compliant Solution**
```java
FileOutputStream fos = new FileOutputStream (fileName);
ObjectOutputStream out = new ObjectOutputStream(fos);
```
#### Rule 26: "wait(...)" should be used instead of "Thread.sleep(...)" when a lock is held
##### Quality Category: Bug
If Thread.sleep(...) is called when the current thread holds a lock, it could lead to performance and scalability issues, or even worse to deadlocks because the execution of the thread holding the lock is frozen. It's better to call wait(...) on the monitor object to temporarily release the lock and allow other threads to run.

**Noncompliant Code Example**
```java
public void doSomething(){
  synchronized(monitor) {
    while(notReady()){
      Thread.sleep(200);
    }
    process();
  }
  ...
}


```
**Compliant Solution**
```java
public void doSomething(){
  synchronized(monitor) {
    while(notReady()){
      monitor.wait(200);
    }
    process();
  }
  ...
}


*See*

CERT, LCK09-J. - Do not perform operations that can block while holding a lock
#### Rule 27: Printf-style format strings should not lead to unexpected behavior at runtime
##### Quality Category: Bug
Because printf-style format strings are interpreted at runtime, rather than validated by the Java compiler, they can contain errors that lead to unexpected behavior or runtime errors. This rule statically validates the good behavior of printf-style formats when calling the format(...) methods of java.util.Formatter, java.lang.String, java.io.PrintStream, MessageFormat, and java.io.PrintWriter classes and the printf(...) methods of java.io.PrintStream or java.io.PrintWriter classes.

**Noncompliant Code Example**
```java
String.format("The value of my integer is %d", "Hello World");  // Noncompliant; an 'int' is expected rather than a String
String.format("Duke's Birthday year is %tX", c);  //Noncompliant; X is not a supported time conversion character
String.format("Display %0$d and then %d", 1);   //Noncompliant; arguments are numbered starting from 1
String.format("Not enough arguments %d and %d", 1);  //Noncompliant; the second argument is missing
String.format("%< is equals to %d", 2);   //Noncompliant; the argument index '<' refers to the previous format specifier but there isn't one

MessageFormat.format("Result {1}.", value); // Noncompliant; Not enough arguments. (first element is {0})
MessageFormat.format("Result {{0}.", value); // Noncompliant; Unbalanced number of curly brace (single curly braces should be escaped)
MessageFormat.format("Result ' {0}", value); // Noncompliant; Unbalanced number of quotes (single quote must be escaped)

java.util.logging.Logger logger;
logger.log(java.util.logging.Level.SEVERE, "Result {1}!", 14); // Noncompliant {{Not enough arguments.}}

org.slf4j.Logger slf4jLog;
org.slf4j.Marker marker;

slf4jLog.debug(marker, "message {}"); // Noncompliant {{Not enough arguments.}}


```
**Compliant Solution**
```java
String.format("The value of my integer is %d", 3);
String.format("Duke's Birthday year is %tY", c);
String.format("Display %1$d and then %d", 1);
String.format("Not enough arguments %d and %d", 1, 2);
String.format("%d is equals to %<", 2);

MessageFormat.format("Result {0}.", value);
MessageFormat.format("Result {0} & {1}.", value, value);
MessageFormat.format("Result {0}.", myObject);

java.util.logging.Logger logger;
logger.log(java.util.logging.Level.SEVERE, "Result {1}!", 14, 2); // Noncompliant {{Not enough arguments.}}

org.slf4j.Logger slf4jLog;
org.slf4j.Marker marker;

slf4jLog.debug(marker, "message {}", 1);


*See*

CERT, FIO47-C. - Use valid format strings
#### Rule 28: Methods "wait(...)", "notify()" and "notifyAll()" should not be called on Thread instances
##### Quality Category: Bug
The methods wait(...), notify() and notifyAll() are available on a Thread instance, but only because all classes in Java extend Object and therefore automatically inherit those methods. But there are two very good reasons for not calling them on a Thread:

 Internally, the JVM relies on these methods to change the state of the Thread (BLOCKED, WAITING, ...), so calling them will corrupt the behavior of the JVM.
 It is not clear (perhaps even to the original coder) what is really expected. For instance, it is waiting for the execution of the Thread to suspended, or is it the acquisition of the object monitor that is waited for?
**Noncompliant Code Example**
```java
Thread myThread = new Thread(new RunnableJob());
...
myThread.wait(2000);
```
#### Rule 29: Methods should not call same-class methods with incompatible "@Transactional" values
##### Quality Category: Bug
When using Spring proxies, calling a method in the same class (e.g. this.aMethod()) with an incompatible @Transactional requirement will result in runtime exceptions because Spring only "sees" the caller and makes no provisions for properly invoking the callee.

Therefore, certain calls should never be made within the same class:

From	To
non-@Transactional	MANDATORY, NESTED, REQUIRED, REQUIRES_NEW
MANDATORY	NESTED, NEVER, NOT_SUPPORTED, REQUIRES_NEW
NESTED	NESTED, NEVER, NOT_SUPPORTED, REQUIRES_NEW
NEVER	MANDATORY, NESTED, REQUIRED, REQUIRES_NEW
NOT_SUPPORTED	MANDATORY, NESTED, REQUIRED, REQUIRES_NEW
REQUIRED or @Transactional	NESTED, NEVER, NOT_SUPPORTED, REQUIRES_NEW
REQUIRES_NEW	NESTED, NEVER, NOT_SUPPORTED, REQUIRES_NEW
SUPPORTS	MANDATORY, NESTED, NEVER, NOT_SUPPORTED, REQUIRED, REQUIRES_NEW
**Noncompliant Code Example**
```java

@Override
public void doTheThing() {
  // ...
  actuallyDoTheThing();  // Noncompliant
}

@Override
@Transactional
public void actuallyDoTheThing() {
  // ...
}
```
#### Rule 30: Loops should not be infinite
##### Quality Category: Bug
An infinite loop is one that will never end while the program is running, i.e., you have to kill the program to get out of the loop. Whether it is by meeting the loop's end condition or via a break, every loop should have an end condition.

**Noncompliant Code Example**
```java
for (;;) {  // Noncompliant; end condition omitted
  // ...
}

int j;
while (true) { // Noncompliant; end condition omitted
  j++;
}

int k;
boolean b = true;
while (b) { // Noncompliant; b never written to in loop
  k++;
}


```
**Compliant Solution**
```java
int j;
while (true) { // reachable end condition added
  j++;
  if (j  == Integer.MIN_VALUE) {  // true at Integer.MAX_VALUE +1
    break;
  }
}

int k;
boolean b = true;
while (b) {
  k++;
  b = k < Integer.MAX_VALUE;
}


*See*

CERT, MSC01-J. - Do not use an empty infinite loop
#### Rule 31: Double-checked locking should not be used
##### Quality Category: Bug
Double-checked locking is the practice of checking a lazy-initialized object's state both before and after a synchronized block is entered to determine whether or not to initialize the object.

It does not work reliably in a platform-independent manner without additional synchronization for mutable instances of anything other than float or int. Using double-checked locking for the lazy initialization of any other type of primitive or mutable object risks a second thread using an uninitialized or partially initialized member while the first thread is still creating it, and crashing the program.

There are multiple ways to fix this. The simplest one is to simply not use double checked locking at all, and synchronize the whole method instead. With early versions of the JVM, synchronizing the whole method was generally advised against for performance reasons. But synchronized performance has improved a lot in newer JVMs, so this is now a preferred solution. If you prefer to avoid using synchronized altogether, you can use an inner static class to hold the reference instead. Inner static classes are guaranteed to load lazily.

**Noncompliant Code Example**
```java
@NotThreadSafe
public class DoubleCheckedLocking {
    private static Resource resource;

    public static Resource getInstance() {
        if (resource == null) {
            synchronized (DoubleCheckedLocking.class) {
                if (resource == null)
                    resource = new Resource();
            }
        }
        return resource;
    }

    static class Resource {

    }
}


```
**Compliant Solution**
```java
@ThreadSafe
public class SafeLazyInitialization {
    private static Resource resource;

    public synchronized static Resource getInstance() {
        if (resource == null)
            resource = new Resource();
        return resource;
    }

    static class Resource {
    }
}


With inner static holder:

@ThreadSafe
public class ResourceFactory {
    private static class ResourceHolder {
        public static Resource resource = new Resource(); // This will be lazily initialised
    }

    public static Resource getResource() {
        return ResourceFactory.ResourceHolder.resource;
    }

    static class Resource {
    }
}


Using "volatile":

class ResourceFactory {
  private volatile Resource resource;

  public Resource getResource() {
    Resource localResource = resource;
    if (localResource == null) {
      synchronized (this) {
        localResource = resource;
        if (localResource == null) {
          resource = localResource = new Resource();
        }
      }
    }
    return localResource;
  }

  static class Resource {
  }
}


*See*

The "Double-Checked Locking is Broken" Declaration
CERT, LCK10-J. - Use a correct form of the double-checked locking idiom
MITRE, CWE-609 - Double-checked locking
JLS 12.4 - Initialization of Classes and Interfaces
 Wikipedia: Double-checked locking
#### Rule 32: Resources should be closed
##### Quality Category: Bug
Connections, streams, files, and other classes that implement the Closeable interface or its super-interface, AutoCloseable, needs to be closed after use. Further, that close call must be made in a finally block otherwise an exception could keep the call from being made. Preferably, when class implements AutoCloseable, resource should be created using "try-with-resources" pattern and will be closed automatically.

Failure to properly close resources will result in a resource leak which could bring first the application and then perhaps the box it's on to their knees.

**Noncompliant Code Example**
```java
private void readTheFile() throws IOException {
  Path path = Paths.get(this.fileName);
  BufferedReader reader = Files.newBufferedReader(path, this.charset);
  // ...
  reader.close();  // Noncompliant
  // ...
  Files.lines("input.txt").forEach(System.out::println); // Noncompliant: The stream needs to be closed
}

private void doSomething() {
  OutputStream stream = null;
  try {
    for (String property : propertyList) {
      stream = new FileOutputStream("myfile.txt");  // Noncompliant
      // ...
    }
  } catch (Exception e) {
    // ...
  } finally {
    stream.close();  // Multiple streams were opened. Only the last is closed.
  }
}


```
**Compliant Solution**
```java
private void readTheFile(String fileName) throws IOException {
    Path path = Paths.get(fileName);
    try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
      reader.readLine();
      // ...
    }
    // ..
    try (Stream<String> input = Files.lines("input.txt"))  {
      input.forEach(System.out::println);
    }
}

private void doSomething() {
  OutputStream stream = null;
  try {
    stream = new FileOutputStream("myfile.txt");
    for (String property : propertyList) {
      // ...
    }
  } catch (Exception e) {
    // ...
  } finally {
    stream.close();
  }
}


```
**Exceptions**
```java

Instances of the following classes are ignored by this rule because close has no effect:

java.io.ByteArrayOutputStream
java.io.ByteArrayInputStream
java.io.CharArrayReader
java.io.CharArrayWriter
java.io.StringReader
java.io.StringWriter

Java 7 introduced the try-with-resources statement, which implicitly closes Closeables. All resources opened in a try-with-resources statement are ignored by this rule.

try (BufferedReader br = new BufferedReader(new FileReader(fileName))) {
  //...
}
catch ( ... ) {
  //...
}


*See*

MITRE, CWE-459 - Incomplete Cleanup
CERT, FIO04-J. - Release resources when they are no longer needed
CERT, FIO42-C. - Close files when they are no longer needed
Try With Resources

#### Rule 33: Methods returns should not be invariant
##### Quality Category: Code Smell
When a method is designed to return an invariant value, it may be poor design, but it shouldn't adversely affect the outcome of your program. However, when it happens on all paths through the logic, it is surely a bug.

This rule raises an issue when a method contains several return statements that all return the same value.

**Noncompliant Code Example**
```java
int foo(int a) {
  int b = 12;
  if (a == 1) {
    return b;
  }
  return b;  // Noncompliant
}
```
#### Rule 34: "ThreadGroup" should not be used
##### Quality Category: Code Smell
There is little valid reason to use the methods of the ThreadGroup class. Some are deprecated (allowThreadSuspension(), resume(), stop(), and suspend()), some are obsolete, others aren't thread-safe, and still others are insecure (activeCount(), enumerate()) . For these reasons, any use of ThreadGroup is suspicious and should be avoided.

Compliant Solution
ThreadFactory threadFactory = Executors.defaultThreadFactory();
ThreadPoolExecutor executorPool = new ThreadPoolExecutor(3, 10, 5, TimeUnit.SECONDS, new ArrayBlockingQueue<Runnable>(2), threadFactory);

for (int i = 0; i < 10; i++) {
  executorPool.execute(new JobThread("Job: " + i));
}

System.out.println(executorPool.getActiveCount()); // Compliant
executorPool.shutdown();


*See*

CERT, THI01-J. - Do not invoke ThreadGroup methods
#### Rule 35: "clone" should not be overridden
##### Quality Category: Code Smell
Many consider clone and Cloneable broken in Java, largely because the rules for overriding clone are tricky and difficult to get right, according to Joshua Bloch:

Object's clone method is very tricky. It's based on field copies, and it's "extra-linguistic." It creates an object without calling a constructor. There are no guarantees that it preserves the invariants established by the constructors. There have been lots of bugs over the years, both in and outside Sun, stemming from the fact that if you just call super.clone repeatedly up the chain until you have cloned an object, you have a shallow copy of the object. The clone generally shares state with the object being cloned. If that state is mutable, you don't have two independent objects. If you modify one, the other changes as well. And all of a sudden, you get random behavior.

A copy constructor or copy factory should be used instead.

This rule raises an issue when clone is overridden, whether or not Cloneable is implemented.

**Noncompliant Code Example**
```java
public class MyClass {
  // ...

  public Object clone() { // Noncompliant
    //...
  }
}


```
**Compliant Solution**
```java
public class MyClass {
  // ...

  MyClass (MyClass source) {
    //...
  }
}


*See*

Copy Constructor versus Cloning

*See*
 Also
 {rule:squid:S2157} - "Cloneables" should implement "clone"
 {rule:squid:S1182} - Classes that override "clone" should be "Cloneable" and call "super.clone()"
#### Rule 36: Assertions should be complete
##### Quality Category: Code Smell
It is very easy to write incomplete assertions when using some test frameworks. This rule enforces complete assertions in the following cases:

 Fest: assertThat is not followed by an assertion invocation
 AssertJ: assertThat is not followed by an assertion invocation
 Mockito: verify is not followed by a method invocation
 Truth: assertXXX is not followed by an assertion invocation

In such cases, what is intended to be a test doesn't actually verify anything

**Noncompliant Code Example**
```java
// Fest
boolean result = performAction();
// let's now check that result value is true
assertThat(result); // Noncompliant; nothing is actually checked, the test passes whether "result" is true or false

// Mockito
List mockedList = Mockito.mock(List.class);
mockedList.add("one");
mockedList.clear();
// let's check that "add" and "clear" methods are actually called
Mockito.verify(mockedList); // Noncompliant; nothing is checked here, oups no call is chained to verify()


```
**Compliant Solution**
```java
// Fest
boolean result = performAction();
// let's now check that result value is true
assertThat(result).isTrue();

// Mockito
List mockedList = Mockito.mock(List.class);
mockedList.add("one");
mockedList.clear();
// let's check that "add" and "clear" methods are actually called
Mockito.verify(mockedList).add("one");
Mockito.verify(mockedList).clear();


```
**Exceptions**
```java

Variable assignments and return statements are skipped to allow helper methods.

private BooleanAssert check(String filename, String key) {
  String fileContent = readFileContent(filename);
  performReplacements(fileContent);
  return assertThat(fileContent.contains(key)); // No issue is raised here
}

@Test
public void test() {
  check("foo.txt", "key1").isTrue();
  check("bar.txt", "key2").isTrue();
}

```
#### Rule 37: Tests should include assertions
##### Quality Category: Code Smell
A test case without assertions ensures only that no exceptions are thrown. Beyond basic runnability, it ensures nothing about the behavior of the code under test.

This rule raises an exception when no assertions from any of the following known frameworks are found in a test:

 JUnit
 Fest 1.x
 Fest 2.x
 Rest-assured 2.0
 AssertJ
 Hamcrest
 Spring's org.springframework.test.web.servlet.ResultActions.andExpect()
 Eclipse Vert.x
 Truth Framework
 Mockito
 EasyMock
 JMock
 WireMock
 RxJava 1.x
 RxJava 2.x
 Selenide
 JMockit

Furthermore, as new or custom assertion frameworks may be used, the rule can be parametrized to define specific methods that will also be considered as assertions. No issue will be raised when such methods are found in test cases. The parameter value should have the following format <FullyQualifiedClassName>#<MethodName>, where MethodName can end with the wildcard character. For constructors, the pattern should be <FullyQualifiedClassName>#<init>.

Example: com.company.CompareToTester#compare*,com.company.CustomAssert#customAssertMethod,com.company.CheckVerifier#<init>.

**Noncompliant Code Example**
```java
@Test
public void testDoSomething() {  // Noncompliant
  MyClass myClass = new MyClass();
  myClass.doSomething();
}


```
**Compliant Solution**
```java

Example when com.company.CompareToTester#compare* is used as parameter to the rule.

import com.company.CompareToTester;

@Test
public void testDoSomething() {
  MyClass myClass = new MyClass();
  assertNull(myClass.doSomething());  // JUnit assertion
  assertThat(myClass.doSomething()).isNull();  // Fest assertion
}

@Test
public void testDoSomethingElse() {
  MyClass myClass = new MyClass();
  new CompareToTester().compareWith(myClass);  // Compliant - custom assertion method defined as rule parameter
  CompareToTester.compareStatic(myClass);  // Compliant
}
```
#### Rule 38: Silly bit operations should not be performed
##### Quality Category: Code Smell
Certain bit operations are just silly and should not be performed because their results are predictable.

Specifically, using & -1 with any value will always result in the original value, as will anyValue ^ 0 and anyValue | 0.
#### Rule 39: JUnit framework methods should be declared properly
##### Quality Category: Code Smell
If the suite method in a JUnit 3 TestCase is not declared correctly, it will not be used. Such a method must be named "suite", have no arguments, be public static, and must return either a junit.framework.Test or a junit.framework.TestSuite.

Similarly, setUp and tearDown methods that aren't properly capitalized will also be ignored.

**Noncompliant Code Example**
```java
Test suite() { ... }  // Noncompliant; must be public static
public static boolean suite() { ... }  // Noncompliant; wrong return type
public static Test suit() { ... }  // Noncompliant; typo in method name
public static Test suite(int count) { ... } // Noncompliant; must be no-arg

public void setup() { ... } // Noncompliant; should be setUp
public void tearDwon() { ... }  // Noncompliant; should be tearDown


```
**Compliant Solution**
```java
public static Test suite() { ... }
public void setUp() { ... }
public void tearDown() { ... }
```
#### Rule 40: Child class fields should not shadow parent class fields
##### Quality Category: Code Smell
Having a variable with the same name in two unrelated classes is fine, but do the same thing within a class hierarchy and you'll get confusion at best, chaos at worst.

**Noncompliant Code Example**
```java
public class Fruit {
  protected Season ripe;
  protected Color flesh;

  // ...
}

public class Raspberry extends Fruit {
  private boolean ripe;  // Noncompliant
  private static Color FLESH; // Noncompliant
}


```
**Compliant Solution**
```java
public class Fruit {
  protected Season ripe;
  protected Color flesh;

  // ...
}

public class Raspberry extends Fruit {
  private boolean ripened;
  private static Color FLESH_COLOR;

}


```
**Exceptions**
```java

This rule ignores same-name fields that are static in both the parent and child classes. This rule ignores private parent class fields, but in all other such cases, the child class field should be renamed.

public class Fruit {
  private Season ripe;
  // ...
}

public class Raspberry extends Fruit {
  private Season ripe;  // Compliant as parent field 'ripe' is anyway not visible from Raspberry
  // ...
}

```
#### Rule 41: JUnit test cases should call super methods
##### Quality Category: Code Smell
Overriding a parent class method prevents that method from being called unless an explicit super call is made in the overriding method. In some cases not calling the super method is acceptable, but not with setUp and tearDown in a JUnit 3 TestCase.

**Noncompliant Code Example**
```java
public class MyClassTest extends MyAbstractTestCase {

  private MyClass myClass;
    @Override
    protected void setUp() throws Exception {  // Noncompliant
      myClass = new MyClass();
    }


```
**Compliant Solution**
```java
public class MyClassTest extends MyAbstractTestCase {

  private MyClass myClass;
    @Override
    protected void setUp() throws Exception {
      super.setUp();
      myClass = new MyClass();
    }
```
#### Rule 42: TestCases should contain tests
##### Quality Category: Code Smell
There's no point in having a JUnit TestCase without any test methods. Similarly, you shouldn't have a file in the tests directory with "Test" in the name, but no tests in the file. Doing either of these things may lead someone to think that uncovered classes have been tested.

This rule raises an issue when files in the test directory have "Test" in the name or implement TestCase but don't contain any tests.
#### Rule 43: Short-circuit logic should be used in boolean contexts
##### Quality Category: Code Smell
The use of non-short-circuit logic in a boolean context is likely a mistake - one that could cause serious program errors as conditions are evaluated under the wrong circumstances.

**Noncompliant Code Example**
```java
if(getTrue() | getFalse()) { ... } // Noncompliant; both sides evaluated


```
**Compliant Solution**
```java
if(getTrue() || getFalse()) { ... } // true short-circuit logic


*See*

CERT, EXP46-C. - Do not use a bitwise operator with a Boolean-like operand
#### Rule 44: Methods and field names should not be the same or differ only by capitalization
##### Quality Category: Code Smell
Looking at the set of methods in a class, including superclass methods, and finding two methods or fields that differ only by capitalization is confusing to users of the class. It is similarly confusing to have a method and a field which differ only in capitalization or a method and a field with exactly the same name and visibility.

In the case of methods, it may have been a mistake on the part of the original developer, who intended to override a superclass method, but instead added a new method with nearly the same name.

Otherwise, this situation simply indicates poor naming. Method names should be action-oriented, and thus contain a verb, which is unlikely in the case where both a method and a member have the same name (with or without capitalization differences). However, renaming a public method could be disruptive to callers. Therefore renaming the member is the recommended action.

**Noncompliant Code Example**
```java
public class Car{

  public DriveTrain drive;

  public void tearDown(){...}

  public void drive() {...}  // Noncompliant; duplicates field name
}

public class MyCar extends Car{
  public void teardown(){...}  // Noncompliant; not an override. It it really what's intended?

  public void drivefast(){...}

  public void driveFast(){...} //Huh?
}


```
**Compliant Solution**
```java
public class Car{

  private DriveTrain drive;

  public void tearDown(){...}

  public void drive() {...}  // field visibility reduced
}

public class MyCar extends Car{
  @Override
  public void tearDown(){...}

  public void drivefast(){...}

  public void driveReallyFast(){...}

}
```
#### Rule 45: Switch cases should end with an unconditional "break" statement
##### Quality Category: Code Smell
When the execution is not explicitly terminated at the end of a switch case, it continues to execute the statements of the following case. While this is sometimes intentional, it often is a mistake which leads to unexpected behavior.

**Noncompliant Code Example**
```java
switch (myVariable) {
  case 1:
    foo();
    break;
  case 2:  // Both 'doSomething()' and 'doSomethingElse()' will be executed. Is it on purpose ?
    doSomething();
  default:
    doSomethingElse();
    break;
}


```
**Compliant Solution**
```java
switch (myVariable) {
  case 1:
    foo();
    break;
  case 2:
    doSomething();
    break;
  default:
    doSomethingElse();
    break;
}


```
**Exceptions**
```java

This rule is relaxed in the following cases:

switch (myVariable) {
  case 0:                                // Empty case used to specify the same behavior for a group of cases.
  case 1:
    doSomething();
    break;
  case 2:                                // Use of return statement
    return;
  case 3:                                // Use of throw statement
    throw new IllegalStateException();
  case 4:                                // Use of continue statement
    continue;
  default:                               // For the last case, use of break statement is optional
    doSomethingElse();
}


*See*

 MISRA C:2004, 15.0 - The MISRA C switch syntax shall be used.
 MISRA C:2004, 15.2 - An unconditional break statement shall terminate every non-empty switch clause
 MISRA C++:2008, 6-4-3 - A switch statement shall be a well-formed switch statement.
 MISRA C++:2008, 6-4-5 - An unconditional throw or break statement shall terminate every non-empty switch-clause
 MISRA C:2012, 16.1 - All switch statements shall be well-formed
 MISRA C:2012, 16.3 - An unconditional break statement shall terminate every switch-clause
MITRE, CWE-484 - Omitted Break Statement in Switch
CERT, MSC17-C. - Finish every set of statements associated with a case label with a break statement
CERT, MSC52-J. - Finish every set of statements associated with a case label with a break statement

#### Rule 46: "switch" statements should not contain non-case labels
##### Quality Category: Code Smell
Even if it is legal, mixing case and non-case labels in the body of a switch statement is very confusing and can even be the result of a typing error.

**Noncompliant Code Example**
```java
switch (day) {
  case MONDAY:
  case TUESDAY:
  WEDNESDAY:   // Noncompliant; syntactically correct, but behavior is not what's expected
    doSomething();
    break;
  ...
}

switch (day) {
  case MONDAY:
    break;
  case TUESDAY:
    foo:for(int i = 0 ; i < X ; i++) {  // Noncompliant; the code is correct and behaves as expected but is barely readable
         /* ... */
        break foo;  // this break statement doesn't relate to the nesting case TUESDAY
         /* ... */
    }
    break;
    /* ... */
}


```
**Compliant Solution**
```java
switch (day) {
  case MONDAY:
  case TUESDAY:
  case WEDNESDAY:
    doSomething();
    break;
  ...
}

switch (day) {
  case MONDAY:
    break;
  case TUESDAY:
    compute(args); // put the content of the labelled "for" statement in a dedicated method
    break;

    /* ... */
}


*See*

 MISRA C:2004, 15.0 - The MISRA C switch syntax shall be used.
 MISRA C++:2008, 6-4-3 - A switch statement shall be a well-formed switch statement.
 MISRA C:2012, 16.1 - All switch statements shall be well-formed
#### Rule 47: Future keywords should not be used as names
##### Quality Category: Code Smell
Through Java's evolution keywords have been added. While code that uses those words as identifiers may be compilable under older versions of Java, it will not be under modern versions.

Following keywords are marked as invalid identifiers

Keyword	Added
_	9
enum	5.0

assert and strictfp are another example of valid identifiers which became keywords in later versions, however as documented in SONARJAVA-285, it is not easily possible to support parsing of the code for such old versions, therefore they are not supported by this rule.

**Noncompliant Code Example**
```java
public void doSomething() {
  int enum = 42;            // Noncompliant
  String _ = "";   // Noncompliant
}


```
**Compliant Solution**
```java
public void doSomething() {
  int magic = 42;
}
```
#### Rule 48: HTTP response headers should not be vulnerable to injection attacks
##### Quality Category: Vulnerability
User provided data, such as URL parameters, POST data payloads, or cookies, should always be considered untrusted and tainted. Applications constructing HTTP response headers based on tainted data could allow attackers to inject characters that would be interpreted as a new line in some browsers. This could, for example, enable Cross-Site Scripting (XSS) attacks.

Most modern web application frameworks and servers mitigate this type of attack by default, but there might be rare cases where older versions are still vulnerable. As a best practice, applications that use user provided data to construct the response header should always validate the data first. Validation should be based on a whitelist.

**Noncompliant Code Example**
```java
protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
  String value = req.getParameter("value");
  resp.addHeader("X-Header", value); // Noncompliant
  // ...
}


```
**Compliant Solution**
```java
protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
  String value = req.getParameter("value");

  // Allow only alphanumeric characters
  if (!value.matches("[a-zA-Z0-9]++"))
    throw new IOException();

  resp.addHeader("X-Header", value);
  // ...
}


*See*

OWASP Attack Category - HTTP Response Splitting
OWASP Top 10 2017 - Category A7 - Cross-Site Scripting (XSS)
MITRE, CWE-79 - Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
MITRE, CWE-113 - Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')
SANS Top 25 - Insecure Interaction Between Components
#### Rule 49: Persistent entities should not be used as arguments of "@RequestMapping" methods
##### Quality Category: Vulnerability
On one side, Spring MVC automatically bind request parameters to beans declared as arguments of methods annotated with @RequestMapping. Because of this automatic binding feature, it's possible to feed some unexpected fields on the arguments of the @RequestMapping annotated methods.

On the other end, persistent objects (@Entity or @Document) are linked to the underlying database and updated automatically by a persistence framework, such as Hibernate, JPA or Spring Data MongoDB.

These two facts combined together can lead to malicious attack: if a persistent object is used as an argument of a method annotated with @RequestMapping, it's possible from a specially crafted user input, to change the content of unexpected fields into the database.

For this reason, using @Entity or @Document objects as arguments of methods annotated with @RequestMapping should be avoided.

In addition to @RequestMapping, this rule also considers the annotations introduced in Spring Framework 4.3: @GetMapping, @PostMapping, @PutMapping, @DeleteMapping, @PatchMapping.

**Noncompliant Code Example**
```java
import javax.persistence.Entity;

@Entity
public class Wish {
  Long productId;
  Long quantity;
  Client client;
}

@Entity
public class Client {
  String clientId;
  String name;
  String password;
}

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class WishListController {

  @PostMapping(path = "/saveForLater")
  public String saveForLater(Wish wish) {
    session.save(wish);
  }

  @RequestMapping(path = "/saveForLater", method = RequestMethod.POST)
  public String saveForLater(Wish wish) {
    session.save(wish);
  }
}


```
**Compliant Solution**
```java
public class WishDTO {
  Long productId;
  Long quantity;
  Long clientId;
}

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class PurchaseOrderController {

  @PostMapping(path = "/saveForLater")
  public String saveForLater(WishDTO wish) {
    Wish persistentWish = new Wish();
    // do the mapping between "wish" and "persistentWish"
    [...]
    session.save(persistentWish);
  }

  @RequestMapping(path = "/saveForLater", method = RequestMethod.POST)
  public String saveForLater(WishDTO wish) {
    Wish persistentWish = new Wish();
    // do the mapping between "wish" and "persistentWish"
    [...]
    session.save(persistentWish);
  }
}


*See*

MITRE, CWE-915 - Improperly Controlled Modification of Dynamically-Determined Object Attributes
 OWASP Top 10 2017 Category A5 - Broken Access Control
Two Security Vulnerabilities in the Spring Framework’s MVC by Ryan Berg and Dinis Cruz
#### Rule 50: "HttpSecurity" URL patterns should be correctly ordered
##### Quality Category: Vulnerability
URL patterns configured on a HttpSecurity.authorizeRequests() method are considered in the order they were declared. It's easy to do a mistake and to declare a less restrictive configuration before a more restrictive one. Therefore, it's required to review the order of the "antMatchers" declarations. The /** one should be the last one if it is declared.

This rule raises an issue when:

- A pattern is preceded by another that ends with ** and has the same beginning. E.g.: /page*-admin/db/** is after /page*-admin/**

- A pattern without wildcard characters is preceded by another that matches. E.g.: /page-index/db is after /page*/**

**Noncompliant Code Example**
```java
  protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()
      .antMatchers("/resources/**", "/signup", "/about").permitAll() // Compliant
      .antMatchers("/admin/**").hasRole("ADMIN")
      .antMatchers("/admin/login").permitAll() // Noncompliant; the pattern "/admin/login" should occurs before "/admin/**"
      .antMatchers("/**", "/home").permitAll()
      .antMatchers("/db/**").access("hasRole('ADMIN') and hasRole('DBA')") // Noncompliant; the pattern "/db/**" should occurs before "/**"
      .and().formLogin().loginPage("/login").permitAll().and().logout().permitAll();
  }


```
**Compliant Solution**
```java
  protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()
      .antMatchers("/resources/**", "/signup", "/about").permitAll() // Compliant
      .antMatchers("/admin/login").permitAll()
      .antMatchers("/admin/**").hasRole("ADMIN") // Compliant
      .antMatchers("/db/**").access("hasRole('ADMIN') and hasRole('DBA')")
      .antMatchers("/**", "/home").permitAll() // Compliant; "/**" is the last one
      .and().formLogin().loginPage("/login").permitAll().and().logout().permitAll();
  }


*See*

 OWASP Top 10 2017 Category A6 - Security Misconfiguration
#### Rule 51: SMTP SSL connection should check server identity
##### Quality Category: Vulnerability
This rule raises an issue when:

- a JavaMail's javax.mail.Session is created with a Properties object having no mail.smtp.ssl.checkserveridentity or mail.smtps.ssl.checkserveridentity not configured to true

- a Apache Common Emails's org.apache.commons.mail.SimpleEmail is used with setSSLOnConnect(true) or setStartTLSEnabled(true) or setStartTLSRequired(true) without a call to setSSLCheckServerIdentity(true)

**Noncompliant Code Example**
```java
Email email = new SimpleEmail();
email.setSmtpPort(465);
email.setAuthenticator(new DefaultAuthenticator(username, password));
email.setSSLOnConnect(true); // Noncompliant; setSSLCheckServerIdentity(true) should also be called before sending the email
email.send();

Properties props = new Properties();
props.put("mail.smtp.host", "smtp.gmail.com");
props.put("mail.smtp.socketFactory.port", "465");
props.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory"); // Noncompliant; Session is created without having "mail.smtp.ssl.checkserveridentity" set to true
props.put("mail.smtp.auth", "true");
props.put("mail.smtp.port", "465");
Session session = Session.getDefaultInstance(props, new javax.mail.Authenticator() {
  protected PasswordAuthentication getPasswordAuthentication() {
    return new PasswordAuthentication("username@gmail.com", "password");
  }
});


```
**Compliant Solution**
```java
Email email = new SimpleEmail();
email.setSmtpPort(465);
email.setAuthenticator(new DefaultAuthenticator(username, password));
email.setSSLOnConnect(true);
email.setSSLCheckServerIdentity(true); // Compliant
email.send();

Properties props = new Properties();
props.put("mail.smtp.host", "smtp.gmail.com");
props.put("mail.smtp.socketFactory.port", "465");
props.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
props.put("mail.smtp.auth", "true");
props.put("mail.smtp.port", "465");
props.put("mail.smtp.ssl.checkserveridentity", true); // Compliant
Session session = Session.getDefaultInstance(props, new javax.mail.Authenticator() {
  protected PasswordAuthentication getPasswordAuthentication() {
    return new PasswordAuthentication("username@gmail.com", "password");
  }
});


*See*

CWE-297 - Improper Validation of Certificate with Host Mismatch
 OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
#### Rule 52: XML transformers should be secured
##### Quality Category: Vulnerability
An XML External Entity or XSLT External Entity (XXE) vulnerability can occur when a javax.xml.transform.Transformer is created without enabling "Secure Processing" or when one is created without disabling external DTDs. If that external entity is hijacked by an attacker it may lead to the disclosure of confidential data, denial of service, server side request forgery, port scanning from the perspective of the machine where the parser is located, and other system impacts.

This rule raises an issue when a Transformer is created without either of these settings.

**Noncompliant Code Example**
```java
Transformer transformer = TransformerFactory.newInstance().newTransformer();
transformer.transform(input, result);


```
**Compliant Solution**
```java
TransformerFactory factory = TransformerFactory.newInstance();
factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

Transformer transformer = factory.newTransformer();
transformer.setOutputProperty(OutputKeys.INDENT, "yes");

transformer.transform(input, result);


or

TransformerFactory factory = TransformerFactory.newInstance();
factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");

Transformer transformer = factory.newTransformer();
transformer.setOutputProperty(OutputKeys.INDENT, "yes");

transformer.transform(input, result);


*See*

MITRE, CWE-611 Improper Restriction of XML External Entity Reference ('XXE')
 OWASP Top 10 2017 Category A4 - XML External Entities
 [OWASP XXE cheat sheet| https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet#TransformerFactory]
 Derived from FindSecBugs rule XXE_DTD_TRANSFORM_FACTORY
 Derived from FindSecBugs rule XXE_XSLT_TRANSFORM_FACTORY
#### Rule 53: LDAP connections should be authenticated
##### Quality Category: Vulnerability
An un-authenticated LDAP connection can lead to transactions without access control. Authentication, and with it, access control, are the last line of defense against LDAP injections and should not be disabled.

This rule raises an issue when an LDAP connection is created with Context.SECURITY_AUTHENTICATION set to "none".

**Noncompliant Code Example**
```java
// Set up the environment for creating the initial context
Hashtable<String, Object> env = new Hashtable<String, Object>();
env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
env.put(Context.PROVIDER_URL, "ldap://localhost:389/o=JNDITutorial");

// Use anonymous authentication
env.put(Context.SECURITY_AUTHENTICATION, "none"); // Noncompliant

// Create the initial context
DirContext ctx = new InitialDirContext(env);


```
**Compliant Solution**
```java
// Set up the environment for creating the initial context
Hashtable<String, Object> env = new Hashtable<String, Object>();
env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
env.put(Context.PROVIDER_URL, "ldap://localhost:389/o=JNDITutorial");

// Use simple authentication
env.put(Context.SECURITY_AUTHENTICATION, "simple");
env.put(Context.SECURITY_PRINCIPAL, "cn=S. User, ou=NewHires, o=JNDITutorial");
env.put(Context.SECURITY_CREDENTIALS, getLDAPPassword());

// Create the initial context
DirContext ctx = new InitialDirContext(env);


*See*

CWE-521 - Weak Password Requirements
 OWASP Top 10 2017 Category A2 - Broken Authentication
Modes of Authenticating to LDAP
 Derived from FindSecBugs rule LDAP_ANONYMOUS
#### Rule 54: AES encryption algorithm should be used with secured mode
##### Quality Category: Vulnerability
The Advanced Encryption Standard (AES) encryption algorithm can be used with various modes. Some combinations are not secured:

 Electronic Codebook (ECB) mode: Under a given key, any given plaintext block always gets encrypted to the same ciphertext block. Thus, it does not hide data patterns well. In some senses, it doesn't provide serious message confidentiality, and it is not recommended for use in cryptographic protocols at all.
 Cipher Block Chaining (CBC) with PKCS#5 padding (or PKCS#7) is susceptible to padding oracle attacks.

In both cases, Galois/Counter Mode (GCM) with no padding should be preferred.

This rule raises an issue when a Cipher instance is created with either ECB or CBC/PKCS5Padding mode.

**Noncompliant Code Example**
```java
Cipher c1 = Cipher.getInstance("AES/ECB/NoPadding"); // Noncompliant
Cipher c2 = Cipher.getInstance("AES/CBC/PKCS5Padding"); // Noncompliant


```
**Compliant Solution**
```java
Cipher c = Cipher.getInstance("AES/GCM/NoPadding");


*See*

MITRE, CWE-327 - Use of a Broken or Risky Cryptographic Algorithm
 OWASP Top 10 2017 Category A6 - Security Misconfiguration
CERT, MSC61-J. - Do not use insecure or weak cryptographic algorithms
SANS Top 25 - Porous Defenses
Recommendation for Block Cipher Modes of Operation
 Derived from FindSecBugs rule ECB_MODE
 Derived from FindSecBugs rule PADDING_ORACLE
#### Rule 55: "SecureRandom" seeds should not be predictable
##### Quality Category: Vulnerability
The java.security.SecureRandom class provides a strong random number generator (RNG) appropriate for cryptography. However, seeding it with a constant or another predictable value will weaken it significantly. In general, it is much safer to rely on the seed provided by the SecureRandom implementation.

This rule raises an issue when SecureRandom.set
*See*
d() or SecureRandom(byte[]) are called with a seed that is either of:

 a constant
System.currentTimeMillis()
**Noncompliant Code Example**
```java
SecureRandom sr = new SecureRandom();
sr.set
*See*
d(123456L); // Noncompliant
int v = sr.next(32);

sr = new SecureRandom("abcdefghijklmnop".getBytes("us-ascii")); // Noncompliant
v = sr.next(32);


```
**Compliant Solution**
```java
SecureRandom sr = new SecureRandom();
int v = sr.next(32);


*See*

MITRE, CWE-330 - Use of Insufficiently Random Values
MITRE, CWE-332 - Insufficient Entropy in PRNG
MITRE, CWE-336 - Same 
*See*
d in Pseudo-Random Number Generator (PRNG)
MITRE, CWE-337 - Predictable 
*See*
d in Pseudo-Random Number Generator (PRNG)
 OWASP Top 10 2017 Category A6 - Security Misconfiguration
CERT, MSC63J. - Ensure that SecureRandom is properly seeded
#### Rule 56: Defined filters should be used
##### Quality Category: Vulnerability
Every filter defined in web.xml file should be used in a <filter-mapping> element. Otherwise such filters are not invoked.

**Noncompliant Code Example**
```java
  <filter>
     <filter-name>DefinedNotUsed</filter-name>
     <filter-class>com.myco.servlet.ValidationFilter</filter-class>
  </filter>


```
**Compliant Solution**
```java
  <filter>
     <filter-name>ValidationFilter</filter-name>
     <filter-class>com.myco.servlet.ValidationFilter</filter-class>
  </filter>

  <filter-mapping>
     <filter-name>ValidationFilter</filter-name>
     <url-pattern>/*</url-pattern>
  </filter-mapping>


*See*

 OWASP Top 10 2017 Category A6 - Security Misconfiguration
#### Rule 57: "HttpOnly" should be set on cookies
##### Quality Category: Vulnerability
The HttpOnly cookie attribute tells the browser to prevent client-side scripts from reading cookies with the attribute, and its use can go a long way to defending against Cross-Site Scripting (XSS) attacks. Thus, as a precaution, the attribute should be set by default on all cookies set server-side, such as session id cookies.

When implementing Cross Site Request Forgery (XSRF) protection, a JavaScript-readable session cookie, generally named XSRF-TOKEN, should be created on the first HTTP GET request. For such a cookie, the HttpOnly attribute should be set to "false".

Setting the attribute can be done either programmatically, or globally via configuration files.

**Noncompliant Code Example**
```java
Cookie cookie = new Cookie("myCookieName", value); // Noncompliant; by default cookie.isHttpOnly() is returning false


```
**Compliant Solution**
```java
Cookie cookie = new Cookie("myCookieName", value);
cookie.setHttpOnly(true); // Compliant


*See*

CWE-79 - Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
CWE-1004 - Sensitive Cookie Without 'HttpOnly' Flag
 OWASP Top 10 2017 Category A7 - Cross-Site Scripting (XSS)
OWASP HttpOnly
SANS Top 25 - Insecure Interaction Between Components
 Derived from FindSecBugs rule HTTPONLY_COOKIE
#### Rule 58: "File.createTempFile" should not be used to create a directory
##### Quality Category: Vulnerability
Using File.createTempFile as the first step in creating a temporary directory causes a race condition and is inherently unreliable and insecure. Instead, Files.createTempDirectory (Java 7+) or a library function such as Guava's similarly-named Files.createTempDir should be used.

This rule raises an issue when the following steps are taken in immediate sequence:

 call to File.createTempFile
 delete resulting file
 call mkdir on the File object

Note that this rule is automatically disabled when the project's sonar.java.source is lower than 7.

**Noncompliant Code Example**
```java
File tempDir;
tempDir = File.createTempFile("", ".");
tempDir.delete();
tempDir.mkdir();  // Noncompliant


```
**Compliant Solution**
```java
Path tempPath = Files.createTempDirectory("");
File tempDir = tempPath.toFile();


*See*

 OWASP Top 10 2017 Category A9 - Using Components with Known Vulnerabilities
#### Rule 59: Web applications should not have a "main" method
##### Quality Category: Vulnerability
There is no reason to have a main method in a web application. It may have been useful for debugging during application development, but such a method should never make it into production. Having a main method in a web application opens a door to the application logic that an attacker may never be able to reach (but watch out if one does!), but it is a sloppy practice and indicates that other problems may be present.

This rule raises an issue when a main method is found in a servlet or an EJB.

**Noncompliant Code Example**
```java
public class MyServlet extends HttpServlet {
  public void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
    if (userIsAuthorized(req)) {
      updatePrices(req);
    }
  }

  public static void main(String[] args) { // Noncompliant
    updatePrices(req);
  }
}


*See*

MITRE, CWE-489 - Leftover Debug Code
 OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
CERT, ENV06-J. - Production code must not contain debugging entry points
#### Rule 60: Basic authentication should not be used
##### Quality Category: Vulnerability
Basic authentication's only means of obfuscation is Base64 encoding. Since Base64 encoding is easily recognized and reversed, it offers only the thinnest veil of protection to your users, and should not be used.

**Noncompliant Code Example**
```java
// Using HttpPost from Apache HttpClient
String encoding = Base64Encoder.encode ("login:passwd");
org.apache.http.client.methods.HttpPost httppost = new HttpPost(url);
httppost.setHeader("Authorization", "Basic " + encoding);  // Noncompliant

or

// Using HttpURLConnection
String encoding = Base64.getEncoder().encodeToString(("login:passwd").getBytes(‌"UTF‌​-8"​));
HttpURLConnection conn = (HttpURLConnection) url.openConnection();
conn.setRequestMethod("POST");
conn.setDoOutput(true);
conn.setRequestProperty("Authorization", "Basic " + encoding); // Noncompliant


*See*

MITRE, CWE-522 - Insufficiently Protected Credentials
MITRE, CWE-311 - Missing Encryption of Sensitive Data
 OWASP Top 10 2017 Category A6 - Security Misconfiguration
SANS Top 25 - Porous Defenses
OWASP Basic Authentication
#### Rule 61: Cryptographic RSA algorithms should always incorporate OAEP (Optimal Asymmetric Encryption Padding)
##### Quality Category: Vulnerability
Without OAEP in RSA encryption, it takes less work for an attacker to decrypt the data or infer patterns from the ciphertext. This rule logs an issue as soon as a literal value starts with RSA/NONE.

**Noncompliant Code Example**
```java
Cipher rsa = javax.crypto.Cipher.getInstance("RSA/NONE/NoPadding");


```
**Compliant Solution**
```java
Cipher rsa = javax.crypto.Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");


*See*

MITRE CWE-780 - Use of RSA Algorithm without OAEP
MITRE CWE-327 - Use of a Broken or Risky Cryptographic Algorithm
 OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
 OWASP Top 10 2017 Category A6 - Security Misconfiguration
SANS Top 25 - Porous Defenses
 Derived from FindSecBugs rule RSA NoPadding Unsafe
#### Rule 62: "HttpServletRequest.getRequestedSessionId()" should not be used
##### Quality Category: Vulnerability
According to the Oracle Java API, the HttpServletRequest.getRequestedSessionId() method:

Returns the session ID specified by the client. This may not be the same as the ID of the current valid session for this request. If the client did not specify a session ID, this method returns null.

The session ID it returns is either transmitted in a cookie or a URL parameter so by definition, nothing prevents the end-user from manually updating the value of this session ID in the HTTP request.

Here is an example of a updated HTTP header:

GET /pageSomeWhere HTTP/1.1
Host: webSite.com
User-Agent: Mozilla/5.0
Cookie: JSESSIONID=Hacked_Session_Value'''">


Due to the ability of the end-user to manually change the value, the session ID in the request should only be used by a servlet container (E.G. Tomcat or Jetty) to see if the value matches the ID of an an existing session. If it does not, the user should be considered unauthenticated. Moreover, this session ID should never be logged to prevent hijacking of active sessions.

**Noncompliant Code Example**
```java
if(isActiveSession(request.getRequestedSessionId()) ){
  ...
}


*See*

MITRE, CWE-807 - Reliance on Untrusted Inputs in a Security Decision
SANS Top 25 - Porous Defenses
 OWASP Top 10 2017 Category A2 - Broken Authentication
#### Rule 63: Getters and setters should access the expected fields
##### Quality Category: Bug
Getters and setters provide a way to enforce encapsulation by providing public methods that give controlled access to private fields. However in classes with multiple fields it is not unusual that cut and paste is used to quickly create the needed getters and setters, which can result in the wrong field being accessed by a getter or setter.

This rule raises an issue in any of these cases:

 A setter does not update the field with the corresponding name.
 A getter does not access the field with the corresponding name.
**Noncompliant Code Example**
```java
class A {
  private int x;
  private int y;

  public void setX(int val) { // Noncompliant: field 'x' is not updated
    this.y = val;
  }

  public int getY() { // Noncompliant: field 'y' is not used in the return value
    return this.x;
  }
}


```
**Compliant Solution**
```java
class A {
  private int x;
  private int y;

  public void setX(int val) {
    this.x = val;
  }

  public int getY() {
    return this.y;
  }
}
```
#### Rule 64: Hibernate should not update database schemas
##### Quality Category: Bug
The use of any value but "validate" for hibernate.hbm2ddl.auto may cause the database schema used by your application to be changed, dropped, or cleaned of all data. In short, the use of this property is risky, and should only be used in production with the "validate" option, if it is used at all.

**Noncompliant Code Example**
```java
<session-factory>
  <property name="hibernate.hbm2ddl.auto">update</property>  <!-- Noncompliant -->
</session-factory>


```
**Compliant Solution**
```java
<session-factory>
  <property name="hibernate.hbm2ddl.auto">validate</property>  <!-- Compliant -->
</session-factory>


or

<session-factory>
  <!-- Property deleted -->
</session-factory>
```
#### Rule 65: Zero should not be a possible denominator
##### Quality Category: Bug
If the denominator to a division or modulo operation is zero it would result in a fatal error.

**Noncompliant Code Example**
```java
void test_divide() {
  int z = 0;
  if (unknown()) {
    // ..
    z = 3;
  } else {
    // ..
  }
  z = 1 / z; // Noncompliant, possible division by zero
}


```
**Compliant Solution**
```java
void test_divide() {
  int z = 0;
  if (unknown()) {
    // ..
    z = 3;
  } else {
    // ..
    z = 1;
  }
  z = 1 / z;
}


*See*

MITRE, CWE-369 - Divide by zero
CERT, NUM02-J. - Ensure that division and remainder operations do not result in divide-by-zero errors
CERT, INT33-C. - Ensure that division and remainder operations do not result in divide-by-zero errors
#### Rule 66: Dependencies should not have "system" scope
##### Quality Category: Bug
system dependencies are sought at a specific, specified path. This drastically reduces portability because if you deploy your artifact in an environment that's not configured just like yours is, your code won't work.

**Noncompliant Code Example**
```java
<dependency>
  <groupId>javax.sql</groupId>
  <artifactId>jdbc-stdext</artifactId>
  <version>2.0</version>
  <scope>system</scope>  <!-- Noncompliant -->
  <systemPath>/usr/bin/lib/rt.jar</systemPath>  <!-- remove this -->
</dependency>
```
#### Rule 67: Locks should be released
##### Quality Category: Bug
If a lock is acquired and released within a method, then it must be released along all execution paths of that method.

Failing to do so will expose the conditional locking logic to the method's callers and hence be deadlock-prone.

**Noncompliant Code Example**
```java
public class MyClass {
  private Lock lock = new Lock();

  public void doSomething() {
    lock.lock(); // Noncompliant
    if (isInitialized()) {
      // ...
      lock.unlock();
    }
  }
}


```
**Compliant Solution**
```java
public class MyClass {
  private Lock lock = new Lock();

  public void doSomething() {
    if (isInitialized()) {
      lock.lock();
      // ...
      lock.unlock();
    }
  }
}


*See*

MITRE, CWE-459 - Incomplete Cleanup
#### Rule 68: "runFinalizersOnExit" should not be called
##### Quality Category: Bug
Running finalizers on JVM exit is disabled by default. It can be enabled with System.runFinalizersOnExit and Runtime.runFinalizersOnExit, but both methods are deprecated because they are are inherently unsafe.

According to the Oracle Javadoc:

It may result in finalizers being called on live objects while other threads are concurrently manipulating those objects, resulting in erratic behavior or deadlock.

If you really want to be execute something when the virtual machine begins its shutdown sequence, you should attach a shutdown hook.

**Noncompliant Code Example**
```java
public static void main(String [] args) {
  ...
  System.runFinalizersOnExit(true);  // Noncompliant
  ...
}

protected void finalize(){
  doSomething();
}


```
**Compliant Solution**
```java
public static void main(String [] args) {
  Runtime.addShutdownHook(new Runnable() {
    public void run(){
      doSomething();
    }
  });
  //...


*See*

CERT, MET12-J. - Do not use finalizers
#### Rule 69: "ScheduledThreadPoolExecutor" should not have 0 core threads
##### Quality Category: Bug
java.util.concurrent.ScheduledThreadPoolExecutor's pool is sized with corePoolSize, so setting corePoolSize to zero means the executor will have no threads and run nothing.

This rule detects instances where corePoolSize is set to zero, via either its setter or the object constructor.

**Noncompliant Code Example**
```java
public void do(){

  ScheduledThreadPoolExecutor stpe1 = new ScheduledThreadPoolExecutor(0); // Noncompliant

  ScheduledThreadPoolExecutor stpe2 = new ScheduledThreadPoolExecutor(POOL_SIZE);
  stpe2.setCorePoolSize(0);  // Noncompliant
```
#### Rule 70: "Random" objects should be reused
##### Quality Category: Bug
Creating a new Random object each time a random value is needed is inefficient and may produce numbers which are not random depending on the JDK. For better efficiency and randomness, create a single Random, then store, and reuse it.

The Random() constructor tries to set the seed with a distinct value every time. However there is no guarantee that the seed will be random or even uniformly distributed. Some JDK will use the current time as seed, which makes the generated numbers not random at all.

This rule finds cases where a new Random is created each time a method is invoked and assigned to a local random variable.

**Noncompliant Code Example**
```java
public void doSomethingCommon() {
  Random rand = new Random();  // Noncompliant; new instance created with each invocation
  int rValue = rand.nextInt();
  //...


```
**Compliant Solution**
```java
private Random rand = SecureRandom.getInstanceStrong();  // SecureRandom is preferred to Random

public void doSomethingCommon() {
  int rValue = this.rand.nextInt();
  //...


```
**Exceptions**
```java

A class which uses a Random in its constructor or in a static main function and nowhere else will be ignored by this rule.


*See*

 OWASP Top 10 2017 Category A6 - Security Misconfiguration

#### Rule 71: The signature of "finalize()" should match that of "Object.finalize()"
##### Quality Category: Bug
Object.finalize() is called by the Garbage Collector at some point after the object becomes unreferenced.

In general, overloading Object.finalize() is a bad idea because:

 The overload may not be called by the Garbage Collector.
 Users are not expected to call Object.finalize() and will get confused.

But beyond that it's a terrible idea to name a method "finalize" if it doesn't actually override Object.finalize().

**Noncompliant Code Example**
```java
public int finalize(int someParameter) {        // Noncompliant
  /* ... */
}


```
**Compliant Solution**
```java
public int someBetterName(int someParameter) {  // Compliant
  /* ... */
}
```
#### Rule 72: Jump statements should not occur in "finally" blocks
##### Quality Category: Bug
Using return, break, throw, and so on from a finally block suppresses the propagation of any unhandled Throwable which was thrown in the try or catch block.

This rule raises an issue when a jump statement (break, continue, return, throw, and goto) would force control flow to leave a finally block.

**Noncompliant Code Example**
```java
public static void main(String[] args) {
  try {
    doSomethingWhichThrowsException();
    System.out.println("OK");   // incorrect "OK" message is printed
  } catch (RuntimeException e) {
    System.out.println("ERROR");  // this message is not shown
  }
}

public static void doSomethingWhichThrowsException() {
  try {
    throw new RuntimeException();
  } finally {
    for (int i = 0; i < 10; i ++) {
      //...
      if (q == i) {
        break; // ignored
      }
    }

    /* ... */
    return;      // Noncompliant - prevents the RuntimeException from being propagated
  }
}


```
**Compliant Solution**
```java
public static void main(String[] args) {
  try {
    doSomethingWhichThrowsException();
    System.out.println("OK");
  } catch (RuntimeException e) {
    System.out.println("ERROR");  // "ERROR" is printed as expected
  }
}

public static void doSomethingWhichThrowsException() {
  try {
    throw new RuntimeException();
  } finally {
    for (int i = 0; i < 10; i ++) {
      //...
      if (q == i) {
        break; // ignored
      }
    }

    /* ... */
  }
}


*See*

MITRE, CWE-584 - Return Inside Finally Block
CERT, ERR04-J. - Do not complete abruptly from a finally block
#### Rule 73: Expanding archive files is security-sensitive
##### Quality Category: Security Hotspot
Expanding archive files is security-sensitive. For example, expanding archive files has led in the past to the following vulnerabilities:

CVE-2018-1263
CVE-2018-16131

Applications that expand archive files (zip, tar, jar, war, 7z, ...) should verify the path where the archive's files are expanded and not trust blindly the content of the archive. Archive's files should not be expanded outside of the root directory where the archive is supposed to be expanded. Also, applications should control the size of the expanded data to not be a victim of Zip Bomb attack. Failure to do so could allow an attacker to use a specially crafted archive that holds directory traversal paths (e.g. ../../attacker.sh) or the attacker could overload the file system, processors or memory of the operating system where the archive is expanded making the target OS completely unusable.

This rule raises an issue when code handle archives. The goal is to guide security code reviews.

Ask Yourself Whether
 there is no validation of the name of the archive entry
 there is no validation of the effective path where the archive entry is going to be expanded
 there is no validation of the size of the expanded archive entry
 there is no validation of the ratio between the compressed and uncompressed archive entry

You are at risk if you answered yes to any of those questions.

Recommended Secure Coding Practices
 Validate the full path of the extracted file against the full path of the directory where files are uncompressed.
 the canonical path of the uncompressed file must start with the canonical path of the directory where files are extracted.
 the name of the archive entry must not contain "..", i.e. reference to a parent directory.
String canonicalDirPath = outputDir.getCanonicalPath();
String canonicalDestPath = targetFile.getCanonicalPath();

if (!canonicalDestPath.startsWith(canonicalDirPath + File.separator)) { // Sanitizer
  throw new ArchiverException("Entry is trying to leave the target dir: " + zipEntry.getName());
}

 Stop extracting the archive if any of its entries has been tainted with a directory traversal path.
 Define and control the ratio between compressed and uncompress bytes.
 Define and control the maximum allowed uncompressed file size.
 Count the number of file entries extracted from the archive and abort the extraction if their number is greater than a predefined threshold.
Questionable Code Example
java.util.zip.ZipFile zipFile = new ZipFile(zipFileName);

Enumeration<? extends ZipEntry> entries = zipFile.entries();
while (entries.hasMoreElements()) {
  ZipEntry e = entries.nextElement(); // Questionable
  File f = new File(outputDir, e.getName());
  InputStream input = zipFile.getInputStream(e);
  extractFile(new ZipInputStream(input), outputDir, e.getName());
}


```
**Exceptions**
```java

This rule doesn't raise an issue when a ZipEntry or a ArchiveEntry:

 is declared as a class field
 is a parameter of an abstract method of an interface or abstract class

*See*

MITRE, CWE-409 - Improper Handling of Highly Compressed Data (Data Amplification)
 OWASP Top 10 2017 Category A1 - Injection
CERT, IDS04-J. - Safely extract files from ZipInputStream
 Snyk Research Team: Zip Slip Vulnerability

#### Rule 74: Controlling permissions is security-sensitive
##### Quality Category: Security Hotspot
Controlling permissions is security-sensitive. It has led in the past to the following vulnerabilities:

CVE-2018-12999
CVE-2018-10285
CVE-2017-7455

Attackers can only damage what they have access to. Thus limiting their access is a good way to prevent them from wreaking havoc, but it has to be done properly.

This rule flags code that controls the access to resources and actions. The goal is to guide security code reviews.

More specifically it will raise issues on the following Spring code:

 The definition of any class implementing interfaces

org.springframework.security.access.AccessDecisionVoter

org.springframework.security.access.AccessDecisionManager

org.springframework.security.access.AfterInvocationProvider

org.springframework.security.access.PermissionEvaluator

org.springframework.security.access.expression.SecurityExpressionOperations

org.springframework.security.access.expression.method.MethodSecurityExpressionHandler

org.springframework.security.core.GrantedAuthority

org.springframework.security.acls.model.PermissionGrantingStrategy

 The definition of any class extending class

org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration

 Any method annotated with

Pre-post annotations: @PreAuthorize, @PreFilter, @PostAuthorize or @PostFilter from org.springframework.security.access.prepost package.

@org.springframework.security.access.annotation.Secured

 Calls to any of the following methods

org.springframework.security.acls.model.MutableAclService: createAcl, deleteAcl, updateAcl

org.springframework.security.config.annotation.web.builders.HttpSecurity: authorizeRequests

 The instantiation of an anonymous class implementing org.springframework.security.core.GrantedAuthority or of any class implementing this interface directly.

It will also raise issue on JSR-250 annotations @RolesAllowed, @PermitAll and @DenyAll from javax.annotation.security package.

Ask Yourself Whether
 at least one accessed action or resource is security-sensitive.
 there is no access control in place or it does not cover all sensitive actions and resources.
 users have permissions they don't need.
 the access control is based on a user input or on some other unsafe data.
 permissions are difficult to remove or take a long time to be updated.

You are at risk if you answered yes to the first question and any of the following ones.

Recommended Secure Coding Practices

The first step is to restrict all sensitive actions to authenticated users.

Each user should have the lowest privileges possible. The access control granularity should match the sensitivity of each resource or action. The more sensitive it is, the less people should have access to it.

Do not base the access control on a user input or on a value which might have been tampered with. For example, the developer should not read a user's permissions from an HTTP cookie as it can be modified client-side.

Check that the access to each action and resource is properly restricted.

Enable administrators to swiftly remove permissions when necessary. This enables them to reduce the time an attacker can have access to your systems when a breach occurs.

Log and monitor refused access requests as they can reveal an attack.


*See*

 OWASP Top 10 2017 Category A5 - Broken Access Control
SANS Top 25 - Porous Defenses
#### Rule 75: Reading the Standard Input is security-sensitive
##### Quality Category: Security Hotspot
Reading Standard Input is security-sensitive. It has led in the past to the following vulnerabilities:

CVE-2005-2337
CVE-2017-11449

It is common for attackers to craft inputs enabling them to exploit software vulnerabilities. Thus any data read from the standard input (stdin) can be dangerous and should be validated.

This rule flags code that reads from the standard input.

Ask Yourself Whether
 data read from the standard input is not sanitized before being used.

You are at risk if you answered yes to this question.

Recommended Secure Coding Practices

Sanitize all data read from the standard input before using it.

Questionable Code Example
class A {
    void foo(String fmt, Object args) throws Exception {
        // Questionable. Check how the standard input is used.
        System.in.read();

        // Questionable. Check how safe this new InputStream is.
        System.setIn(new java.io.FileInputStream("test.txt"));

        java.io.Console console = System.console();
        // Questionable. All the following calls should be reviewed as they use the standard input.
        console.reader();
        console.readLine();
        console.readLine(fmt, args);
        console.readPassword();
        console.readPassword(fmt, args);
    }
}


```
**Exceptions**
```java

All references to System.in will create issues except direct calls to System.in.close().

Command line parsing libraries such as JCommander often read standard input when asked for passwords. However this rule doesn't raise any issue in this case as another hotspot rule covers command line arguments.


*See*
:
MITRE, CWE-20 - Improper Input Validation

#### Rule 76: Sending HTTP requests is security-sensitive
##### Quality Category: Security Hotspot
Sending HTTP requests is security-sensitive. It has led in the past to the following vulnerabilities:

CVE-2014-8150
CVE-2018-1000007
CVE-2010-0660

An HTTP request has different kinds of vulnerabilities:

 it sends data which might be intercepted or dangerous.
 it receives a response which might have been crafted by an attacker.
 as each request opens a socket and triggers some processing for the sender and the recipient, it is possible to exhaust resources on both sides by sending too many requests.

This rule flags code that initiates an HTTP request. The goal is to guide security code reviews.

Ask Yourself Whether
 the http connection is encrypted or not.
 the recipient is not allowed to receive some of the data you send.
 the data sent might be dangerous (example: it contains unvalidated user input).
 an uncontrolled number of requests might be sent. For example, a request might be sent every time a user performs an action, and this action is not limited.

You are at risk if you answered yes to any of those questions.

Recommended Secure Coding Practices
 First, it is important to encrypt all HTTP connection if there is any chance for them to be eavesdropped. Use HTTPS whenever possible.
 Ensure that you control the URIs you send requests to and the number or requests you send. Your software could otherwise be used to attack other services.
 Avoid sending sensitive information, be it in the URL, header or body. If part of the data comes from an untrusted source, such as a user input, sanitize it beforehand.
 Validate and sanitize the response before using it in any way.
Questionable Code Example
// === Java URL connection ===
import java.net.URL;
import java.net.HttpURLConnection;

abstract class URLConnection {
    void foo() throws Exception {
        URL url = new URL("http://example.com");
        HttpURLConnection con = (HttpURLConnection) url.openConnection(); // Questionable: review how the http connection is used

        doSomething((HttpURLConnection) url.openConnection()); // Questionable: review how the http connection is used
    }

    abstract void doSomething(HttpURLConnection httpUrlConnection);
}

// === HttpClient Java 9 ===
import jdk.incubator.http.HttpClient;
import jdk.incubator.http.HttpRequest;
import jdk.incubator.http.HttpResponse;

class JavaNet9 {
    void foo(HttpRequest request, HttpResponse.BodyHandler<Object> responseBodyHandler, HttpResponse.MultiProcessor<?,?> multiProcessor) throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        client.send(request, responseBodyHandler); // Questionable
        client.sendAsync(request, responseBodyHandler); // Questionable
        client.sendAsync(request, multiProcessor); // Questionable
    }
}

// === HttpClient Java 10 ===
import jdk.incubator.http.HttpClient;
import jdk.incubator.http.HttpRequest;
import jdk.incubator.http.HttpResponse;

class JavaNet10 {
    void foo(HttpRequest request, HttpResponse.BodyHandler<Object> responseBodyHandler, HttpResponse.MultiSubscriber<?,?> multiSubscriber) throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        client.send(request, responseBodyHandler); // Questionable
        client.sendAsync(request, responseBodyHandler); // Questionable
        client.sendAsync(request, multiSubscriber); // Questionable
    }
}

// === HttpClient Java 11 ===
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

class JavaNet11 {
    void foo(HttpRequest request, HttpResponse.BodyHandler<Object> responseBodyHandler, HttpResponse.PushPromiseHandler<Object> pushPromiseHandler) throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        client.send(request, responseBodyHandler); // Questionable
        client.sendAsync(request, responseBodyHandler); // Questionable
        client.sendAsync(request, responseBodyHandler, pushPromiseHandler); // Questionable
    }
}

// === apache ===
import org.apache.http.client.HttpClient;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.HttpClientConnection;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.protocol.HttpContext;

class ApacheHttpClient {
    void foo(HttpClientConnection con, HttpHost target, HttpRequest request, HttpContext context,
            ResponseHandler<?> responseHandler, HttpUriRequest uriRequest, HttpEntityEnclosingRequest eeRequest)
            throws Exception {
        HttpClient client = HttpClientBuilder.create().build();

        // All the following are Questionable
        client.execute(target, request);
        client.execute(target, request, context);
        client.execute(target, request, responseHandler);
        client.execute(target, request, responseHandler, context);
        client.execute(uriRequest);
        client.execute(uriRequest, context);
        client.execute(uriRequest, responseHandler);
        client.execute(uriRequest, responseHandler, context);
        con.sendRequestEntity(eeRequest);
        con.sendRequestHeader(request);
    }
}

// === google-http-java-client ===
import java.util.concurrent.Executor;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.javanet.NetHttpTransport;

class GoogleHttpClient {
    void foo(Executor executor) throws Exception {
        HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
        HttpRequest request = requestFactory.buildGetRequest(new GenericUrl("http://example.com"));

        // All the following are Questionable
        request.execute();
        request.executeAsync();
        request.executeAsync(executor);
    }
}


*See*

MITRE, CWE-20 - Improper Input Validation
MITRE, CWE-400 - Uncontrolled Resource Consumption ('Resource Exhaustion')
MITRE, CWE-200 - Information Exposure
 OWASP Top 10 2017 Category A1 - Injection
 OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
#### Rule 77: Using command line arguments is security-sensitive
##### Quality Category: Security Hotspot
Using command line arguments is security-sensitive. It has led in the past to the following vulnerabilities:

CVE-2018-7281
CVE-2018-12326
CVE-2011-3198

Command line arguments can be dangerous just like any other user input. They should never be used without being first validated and sanitized.

Remember also that any user can retrieve the list of processes running on a system, which makes the arguments provided to them visible. Thus passing sensitive information via command line arguments should be considered as insecure.

This rule raises an issue when on every program entry points (main methods) when command line arguments are used. The goal is to guide security code reviews.

Ask Yourself Whether
 any of the command line arguments are used without being sanitized first.
 your application accepts sensitive information via command line arguments.

If you answered yes to any of these questions you are at risk.

Recommended Secure Coding Practices

Sanitize all command line arguments before using them.

Any user or application can list running processes and see the command line arguments they were started with. There are safer ways of providing sensitive information to an application than exposing them in the command line. It is common to write them on the process' standard input, or give the path to a file containing the information.

Questionable Code Example

This rule raises an issue as soon as there is a reference to argv, be it for direct use or via a CLI library like JCommander, GetOpt or Apache CLI.

public class Main {
    public static void main (String[] argv) {
        String option = argv[0];  // Questionable: check how the argument is used
    }
}

// === JCommander ===
import com.beust.jcommander.*;

public class Main {
    public static void main (String[] argv) {
        Main main = new Main();
        JCommander.newBuilder()
        .addObject(main)
        .build()
        .parse(argv); // Questionable
        main.run();
    }
}

// === GNU Getopt ===
import gnu.getopt.Getopt;

public class Main {
    public static void main (String[] argv) {
        Getopt g = new Getopt("myprog", argv, "ab"); // Questionable
    }
}

// === Apache CLI ===
import org.apache.commons.cli.*;

public class Main {
    public static void main (String[] argv) {
        Options options = new Options();
        CommandLineParser parser = new DefaultParser();
        try {
            CommandLine line = parser.parse(options, argv); // Questionable
        }
    }
}


In the case of Args4J, an issue is created on the public void run method of any class using org.kohsuke.args4j.Option or org.kohsuke.args4j.Argument.

Such a class is called directly by org.kohsuke.args4j.Starter outside of any public static void main method. If the class has no run method, no issue will be raised as there must be a public static void main and its argument is already highlighted.

// === argv4J ===
import org.kohsuke.args4j.Option;
import org.kohsuke.args4j.Argument;

public class Main {
    @Option(name="-myopt",usage="An option")
    public String myopt;

    @Argument(usage = "An argument", metaVar = "<myArg>")
    String myarg;

    String file;

    @Option(name="-file")
    public void setFile(String file) {
        this.file = file;
    }

    String arg2;

    @Argument(index=1)
    public void setArg2(String arg2) {
        this.arg2 = arg2;
    }

    public void run() { // Questionable: This function
        myarg; // check how this argument is used
    }
}


```
**Exceptions**
```java

The support of Argv4J without the use of org.kohsuke.argv4j.Option is out of scope as there is no way to know which Bean will be used as the mainclass.

No issue will be raised on public static void main(String[] argv) if argv is not referenced in the method.


*See*

MITRE, CWE-88 - Argument Injection or Modification
MITRE, CWE-214 - Information Exposure Through Process Environment
 OWASP Top 10 2017 Category A1 - Injection
SANS Top 25 - Insecure Interaction Between Components

#### Rule 78: Using Sockets is security-sensitive
##### Quality Category: Security Hotspot
Using sockets is security-sensitive. It has led in the past to the following vulnerabilities:

CVE-2011-178
CVE-2017-5645
CVE-2018-6597

Sockets are vulnerable in multiple ways:

 They enable a software to interact with the outside world. As this world is full of attackers it is necessary to check that they cannot receive sensitive information or inject dangerous input.
 The number of sockets is limited and can be exhausted. Which makes the application unresponsive to users who need additional sockets.

This rules flags code that creates sockets. It matches only the direct use of sockets, not use through frameworks or high-level APIs such as the use of http connections.

Ask Yourself Whether
 sockets are created without any limit every time a user performs an action.
 input received from sockets is used without being sanitized.
 sensitive data is sent via sockets without being encrypted.

You are at risk if you answered yes to any of these questions.

Recommended Secure Coding Practices
 In many cases there is no need to open a socket yourself. Use instead libraries and existing protocols.
 Encrypt all data sent if it is sensitive. Usually it is better to encrypt it even if the data is not sensitive as it might change later.
Sanitize any input read from the socket.
 Limit the number of sockets a given user can create. Close the sockets as soon as possible.
Questionable Code Example
// === java.net ===
import java.net.Socket;
import java.net.InetAddress;
import java.net.Proxy;
import java.net.ServerSocket;
import javax.net.SocketFactory;

class A {
    void foo(SocketFactory factory, String address, int port, InetAddress localAddr, int localPort, boolean stream,
            String host, Proxy proxy, int backlog, InetAddress bindAddr)
            throws Exception {
        new Socket(); // Questionable.
        new Socket(address, port); // Questionable.
        new Socket(address, port, localAddr, localPort); // Questionable.
        new Socket(host, port, stream); // Questionable.
        new Socket(proxy); // Questionable.
        new Socket(host, port); // Questionable.
        new Socket(host, port, stream); // Questionable.
        new Socket(host, port, localAddr, localPort); // Questionable.

        new ServerSocket(); // Questionable.
        new ServerSocket(port); // Questionable.
        new ServerSocket(port, backlog); // Questionable.
        new ServerSocket(port, backlog, bindAddr); // Questionable.

        factory.createSocket(); // Questionable
    }
}

abstract class mySocketFactory extends SocketFactory { // Questionable. Review how the sockets are created.
    // ...
}

// === java.nio.channels ===
import java.net.SocketAddress;
import java.nio.channels.AsynchronousChannelGroup;
import java.nio.channels.AsynchronousServerSocketChannel;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.channels.ServerSocketChannel;

class A {
    void foo(AsynchronousChannelGroup group, SocketAddress remote) throws Exception {
        AsynchronousServerSocketChannel.open(); // Questionable.
        AsynchronousServerSocketChannel.open(group); // Questionable.
        AsynchronousSocketChannel.open(); // Questionable.
        AsynchronousSocketChannel.open(group); // Questionable.
        SocketChannel.open(); // Questionable.
        SocketChannel.open(remote); // Questionable.
        ServerSocketChannel.open(); // Questionable.
    }
}

// === Netty ===
import io.netty.channel.ChannelInitializer;
import io.netty.channel.socket.ServerSocketChannel;
import io.netty.channel.socket.SocketChannel;

class CustomChannelInitializer extends ChannelInitializer<ServerSocketChannel> { // Questionable. Review how the SocketChannel is used.
    @Override
    protected void initChannel(ServerSocketChannel ch) throws Exception {
    }
}

class A {
    void foo() {
        new ChannelInitializer<SocketChannel>() {  // Questionable
            @Override
            public void initChannel(SocketChannel ch) throws Exception {
                // ...
            }
        };
    }
}


*See*

MITRE, CWE-20 - Improper Input Validation
MITRE, CWE-400 - Uncontrolled Resource Consumption ('Resource Exhaustion')
MITRE, CWE-200 - Information Exposure
 OWASP Top 10 2017 Category A1 - Injection
 OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
SANS Top 25 - Risky Resource Management
SANS Top 25 - Porous Defenses
#### Rule 79: Executing XPath expressions is security-sensitive
##### Quality Category: Security Hotspot
Executing XPATH expressions is security-sensitive. It has led in the past to the following vulnerabilities:

CVE-2016-6272
CVE-2016-9149
CVE-2012-4837

User provided data such as URL parameters should always be considered as untrusted and tainted. Constructing XPath expressions directly from tainted data enables attackers to inject specially crafted values that changes the initial meaning of the expression itself. Successful XPath injections attacks can read sensitive information from the XML document.

Ask Yourself Whether
 the XPATH expression might contain some unsafe input coming from a user.

You are at risk if you answered yes to this question.

Recommended Secure Coding Practices

Sanitize any user input before using it in an XPATH expression.

Questionable Code Example
// === javax.xml.xpath.XPath ===
import javax.xml.namespace.QName;
import javax.xml.xpath.XPath;

import org.xml.sax.InputSource;

class M {
    void foo(XPath xpath, String expression, InputSource source, QName returnType, Object item) throws Exception {
        xpath.compile(expression); // Questionable
        xpath.evaluate(expression, source); // Questionable
        xpath.evaluate(expression, source, returnType); // Questionable
        xpath.evaluate(expression, item); // Questionable
        xpath.evaluate(expression, item, returnType); // Questionable
    }
}

// === Apache XML Security ===
import org.apache.xml.utils.PrefixResolver;
import org.apache.xml.security.utils.XPathAPI;
import org.w3c.dom.Node;

class M {
    void foo(XPathAPI api, Node contextNode, String str, Node namespaceNode, PrefixResolver prefixResolver,
            Node xpathnode) throws Exception {
        api.evaluate(contextNode, xpathnode, str, namespaceNode); // Questionable
        api.selectNodeList(contextNode, xpathnode, str, namespaceNode); // Questionable
    }
}

// === Apache Xalan ===
import org.apache.xml.utils.PrefixResolver;
import org.apache.xpath.XPathAPI;
import org.w3c.dom.Node;

class M {
    void foo(XPathAPI api, Node contextNode, String str, Node namespaceNode, PrefixResolver prefixResolver)
            throws Exception {
        XPathAPI.eval(contextNode, str); // Questionable
        XPathAPI.eval(contextNode, str, namespaceNode); // Questionable
        XPathAPI.eval(contextNode, str, prefixResolver); // Questionable
        XPathAPI.selectNodeIterator(contextNode, str); // Questionable
        XPathAPI.selectNodeIterator(contextNode, str, namespaceNode); // Questionable
        XPathAPI.selectNodeList(contextNode, str); // Questionable
        XPathAPI.selectNodeList(contextNode, str, namespaceNode); // Questionable
        XPathAPI.selectSingleNode(contextNode, str); // Questionable
        XPathAPI.selectSingleNode(contextNode, str, namespaceNode); // Questionable
    }
}

// === org.apache.commons.jxpath ===
import org.apache.commons.jxpath.JXPathContext;

abstract class A extends JXPathContext{
    A(JXPathContext compilationContext, Object contextBean) {
        super(compilationContext, contextBean);
    }


    void foo(JXPathContext context, String str, Object obj, Class<?> requiredType) {
        JXPathContext.compile(str); // Questionable
        this.compilePath(str); // Questionable
        context.createPath(str); // Questionable
        context.createPathAndSetValue(str, obj); // Questionable
        context.getPointer(str); // Questionable
        context.getValue(str); // Questionable
        context.getValue(str, requiredType); // Questionable
        context.iterate(str); // Questionable
        context.iteratePointers(str); // Questionable
        context.removeAll(str); // Questionable
        context.removePath(str); // Questionable
        context.selectNodes(str); // Questionable
        context.selectSingleNode(str); // Questionable
        context.setValue(str, obj); // Questionable
    }
}


*See*

MITRE, CWE-643 - Improper Neutralization of Data within XPath Expressions
 OWASP Top 10 2017 Category A1 - Injection
CERT, IDS53-J. - Prevent XPath Injection
#### Rule 80: Handling files is security-sensitive
##### Quality Category: Security Hotspot
Handling files is security-sensitive. It has led in the past to the following vulnerabilities:

CVE-2018-0358
CVE-2017-7560
CVE-2005-4015
CVE-2018-3835
CVE-2018-8008
CVE-2010-2320

Any access to the file system can create a vulnerability. Exposing a file's content, path or even its existence or absence is dangerous. It is also extremely risky to create or write files without making sure that their permission and content is safe and controlled. Using a file path or reading a file content must be always done with caution as they could have been tampered with.

The file system is a resource which can be easily exhausted. Opening too many files will use up all file descriptors, preventing other software from opening files. Filling the storage space will also prevent any additional write from happening.

This rule flags code that initiates the use of files. It does not highlight how the files are used as this is often done in external libraries or via abstractions like InputStream. It focuses instead on the creation of java.io.File or equivalent from a String. This action indicates that one or multiple files will be processed just after this code. The goal is to guide manual security code reviews.

Ask Yourself Whether
 the file or directory path you are using is coming from a user input or could have been tampered with.
 the code exposes to an unauthorized person the existence of a file or directory. Any hint given to a user might be dangerous. The information could be given by displaying an error if the file/directory does not exist or just by returning an "Unauthorized" error when the file/directory exists but the person can't perform an action.
 the code exposes to an unauthorized person the paths of files and/or directories, for example by listing the content of a directory and displaying the output.
 a file or directory may be created with the wrong permissions.
 an unvalidated user input is written into a file.
 a file is read and its content is used without being validated.
 a file is read and its content is exposed to an unauthorized person.
 a file is open, created or written into each time a user performs an action.
 files are open and not closed before executing a child process. This is only dangerous if file descriptors are inherited in your programming language (example: C, C++).

You are at risk if you answered yes to any of those questions.

Recommended Secure Coding Practices

Avoid using paths provided by users or other untrusted sources if possible. If this is required, check that the path does not reference an unauthorized directory or file. 
*See*
 OWASP recommendations as to how to test for directory traversal. Note that the paths length should be validated too.

No File and directory names should be exposed. They can contain sensitive information. This means that a user should not be able to list the content of unauthorized directories.

Make sure that no attackers can test for the existence or absence of sensitive files. Knowing that a specific file exists can reveal a vulnerability or at least expose file and directory names.

Files and directories should be created with restricted permissions and ownership. Only authorized users and applications should be able to access the files, and they should have as little permissions as needed. Modifying a file's permissions is not good enough. The permissions should be restricted from the very beginning.

Writing user input into files should be done with caution. It could fill the storage space if the amount of data written is not controlled. It could also write dangerous data which will later be used by an application or returned to another user. This is why the user input should be validated before being written.

Reading a file can lead to other vulnerabilities. Any file could have been modified by an attacker. Thus the same validation as for any user input should be performed on file content.

Once a file is read, its content should only be exposed to authorized users.

Add limits to the number of files your application access simultaneously or create because of a user action. It is possible to perform a Denial of Service attack by opening too many files, and thus exhausting available file descriptors, or by filling the file system with new files. Release file descriptors by closing files as soon as possible.

We also recommended to have tools monitoring your system and alerting you whenever resources are nearly exhausted.

Do not allow untrusted code to access the filesystem. For some programming languages, child-processes may have access to file descriptors opened by the parent process before the creation of the child process. This creates a vulnerability when a child process doesn't have the permission to access a file but is still able to modify it via the inherited file descriptor. Check your language documentation for "file descriptor leak" or the use of the flags O_CLOEXEC, FD_CLOEXEC, or bInheritHandles. File descriptors can be inherited in the following languages: C, C++, C#, Objective-C, Swift, Go (but disabled by default), some JVM versions, Javascript and TypeScript in Nodejs, Some PHP versions, Python, Ruby, Rust, VB6 and VB.NET.

Questionable Code Example
// === java.io.File ===
import java.io.File;

class A {
    void foo(String strPath, String StrParent, String StrChild, String prefix, String suffix, java.net.URI uri) throws Exception {

        // Questionable: check what is done with this file
        new File(strPath);
        new File(StrParent, StrChild);
        new File(uri);
        File.createTempFile(prefix, suffix);
    }
}

// === java.nio.file ===
import java.nio.file.attribute.FileAttribute;
import java.nio.file.*;

class A {
    void foo(FileSystem fileSystem, java.net.URI uri, String part1, String part2, String prefix, FileAttribute<?> attrs,
            String suffix) throws Exception {
        Path path = Paths.get(part1, part2); // Questionable
        Path path2 = Paths.get(uri); // Questionable

        Iterable<Path> paths = fileSystem.getRootDirectories(); // Questionable
        Path path3 = fileSystem.getPath(part1, part2); // Questionable

        Path path4 = Files.createTempDirectory(prefix, attrs); // Questionable
        Path path5 = Files.createTempFile(prefix, suffix, attrs); // Questionable
    }
}

// === Opening file from a string path ===
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.RandomAccessFile;

class A {
    void foo(String mode) throws Exception {
        FileReader reader = new FileReader("test.txt"); // Questionable
        FileInputStream instream = new FileInputStream("test.txt"); // Questionable
        FileWriter writer = new FileWriter("out.txt"); // Questionable
        FileOutputStream outstream = new FileOutputStream("out2.txt"); // Questionable
        RandomAccessFile file = new RandomAccessFile("test.txt", mode); // Questionable
    }
}

// ===  org.apache.commons.io.FileUtils ===
import org.apache.commons.io.FileUtils;

class A {
    void foo() {
        FileUtils.getFile("test.txt"); // Questionable
        FileUtils.getTempDirectory(); // Questionable
        FileUtils.getUserDirectory(); // Questionable
    }
}

// === Guava ===
import java.nio.charset.Charset;

import com.google.common.io.FileBackedOutputStream;
import com.google.common.io.MoreFiles;
import com.google.common.io.Resources;
import com.google.common.io.Files;
import com.google.common.io.LineProcessor;

class M {
    void foo(java.net.URL url, Charset charset, java.io.OutputStream stream, String resourceName, Class<?> contextClass,
            LineProcessor<Object> callback, int fileThreshold, boolean resetOnFinalize) throws Exception {

        Files.createTempDir(); // Questionable
        Files.fileTreeTraverser(); // Questionable (removed from public API in Guava 25.0)
        Files.fileTraverser(); // Questionable
        MoreFiles.directoryTreeTraverser(); // Questionable (removed from public API in Guava 25.0)
        MoreFiles.fileTraverser(); // Questionable
        Resources.asByteSource(url); // Questionable
        Resources.asCharSource(url, charset); // Questionable
        Resources.copy(url, stream); // Questionable
        Resources.getResource(contextClass, resourceName); // Questionable
        Resources.getResource(resourceName); // Questionable
        Resources.readLines(url, charset); // Questionable
        Resources.readLines(url, charset, callback); // Questionable
        Resources.toByteArray(url); // Questionable
        Resources.toString(url, charset); // Questionable

        // these OutputStreams creates files
        new FileBackedOutputStream(fileThreshold); // Questionable
        new FileBackedOutputStream(fileThreshold, resetOnFinalize); // Questionable
    }
}


```
**Exceptions**
```java

This rule doesn't highlight any function call receiving a Path or File arguments as the arguments themselves have been highlighted before.

For example we highlight new File(String parent, String child) but not new File(File parent, String child) as the parent File should have been flagged earlier.


*See*

MITRE, CWE-732 - Incorrect Permission Assignment for Critical Resource
MITRE, CWE-73 - External Control of File Name or Path
MITRE, CWE-20 - Improper Input Validation
MITRE, CWE-22 - Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
MITRE, CWE-400 - Uncontrolled Resource Consumption ('Resource Exhaustion')
MITRE, CWE-538 - File and Directory Information Exposure
MITRE, CWE-403 - Exposure of File Descriptor to Unintended Control Sphere ('File Descriptor Leak')
CERT, FIO01-J. - Create files with appropriate access permissions
CERT, FIO06-C. - Create files with appropriate access permissions
CERT, FIO22-C. Close files before spawning processes
 OWASP Top 10 2017 Category A1 - Injection
 OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
SANS Top 25 - Risky Resource Management
SANS Top 25 - Porous Defenses

#### Rule 81: Configuring loggers is security-sensitive
##### Quality Category: Security Hotspot
Configuring loggers is security-sensitive. It has led in the past to the following vulnerabilities:

CVE-2018-0285
CVE-2000-1127
CVE-2017-15113
CVE-2015-5742

Logs are useful before, during and after a security incident.

 Attackers will most of the time start their nefarious work by probing the system for vulnerabilities. Monitoring this activity and stopping it is the first step to prevent an attack from ever happening.
 In case of a successful attack, logs should contain enough information to understand what damage an attacker may have inflicted.

Logs are also a target for attackers because they might contain sensitive information. Configuring loggers has an impact on the type of information logged and how they are logged.

This rule flags for review code that initiates loggers configuration. The goal is to guide security code reviews.

Ask Yourself Whether
 unauthorized users might have access to the logs, either because they are stored in an insecure location or because the application gives access to them.
 the logs contain sensitive information on a production server. This can happen when the logger is in debug mode.
 the log can grow without limit. This can happen when additional information is written into logs every time a user performs an action and the user can perform the action as many times as he/she wants.
 the logs do not contain enough information to understand the damage an attacker might have inflicted. The loggers mode (info, warn, error) might filter out important information. They might not print contextual information like the precise time of events or the server hostname.
 the logs are only stored locally instead of being backuped or replicated.

You are at risk if you answered yes to any of those questions.

Recommended Secure Coding Practices
 Check that your production deployment doesn't have its loggers in "debug" mode as it might write sensitive information in logs.
 Production logs should be stored in a secure location which is only accessible to system administrators.
 Configure the loggers to display all warnings, info and error messages. Write relevant information such as the precise time of events and the hostname.
 Choose log format which is easy to parse and process automatically. It is important to process logs rapidly in case of an attack so that the impact is known and limited.
 Check that the permissions of the log files are correct. If you index the logs in some other service, make sure that the transfer and the service are secure too.
 Add limits to the size of the logs and make sure that no user can fill the disk with logs. This can happen even when the user does not control the logged information. An attacker could just repeat a logged action many times.

Remember that configuring loggers properly doesn't make them bullet-proof. Here is a list of recommendations explaining on how to use your logs:

 Don't log any sensitive information. This obviously includes passwords and credit card numbers but also any personal information such as user names, locations, etc... Usually any information which is protected by law is good candidate for removal.
 Sanitize all user inputs before writing them in the logs. This includes checking its size, content, encoding, syntax, etc... As for any user input, validate using whitelists whenever possible. Enabling users to write what they want in your logs can have many impacts. It could for example use all your storage space or compromise your log indexing service.
 Log enough information to monitor suspicious activities and evaluate the impact an attacker might have on your systems. Register events such as failed logins, successful logins, server side input validation failures, access denials and any important transaction.
 Monitor the logs for any suspicious activity.


*See*


MITRE, CWE-532 - Information Exposure Through Log Files
MITRE, CWE-117 - Improper Output Neutralization for Logs
MITRE, CWE-778 - Insufficient Logging
 OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
 OWASP Top 10 2017 Category A10 - Insufficient Logging & Monitoring
SANS Top 25 - Porous Defenses
Questionable Code Example

This rule supports the following libraries: Log4J, java.util.logging and Logback

// === Log4J 2 ===
import org.apache.logging.log4j.core.config.builder.api.ConfigurationBuilderFactory;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.*;
import org.apache.logging.log4j.core.config.*;

// Questionable: creating a new custom configuration
abstract class CustomConfigFactory extends ConfigurationFactory {
    // ...
}

class A {
    void foo(Configuration config, LoggerContext context, java.util.Map<String, Level> levelMap,
            Appender appender, java.io.InputStream stream, java.net.URI uri,
            java.io.File file, java.net.URL url, String source, ClassLoader loader, Level level, Filter filter)
            throws java.io.IOException {
        // Creating a new custom configuration
        ConfigurationBuilderFactory.newConfigurationBuilder();  // Questionable

        // Setting loggers level can result in writing sensitive information in production
        Configurator.setAllLevels("com.example", Level.DEBUG);  // Questionable
        Configurator.setLevel("com.example", Level.DEBUG);  // Questionable
        Configurator.setLevel(levelMap);  // Questionable
        Configurator.setRootLevel(Level.DEBUG);  // Questionable

        config.addAppender(appender); // Questionable: this modifies the configuration

        LoggerConfig loggerConfig = config.getRootLogger();
        loggerConfig.addAppender(appender, level, filter); // Questionable
        loggerConfig.setLevel(level); // Questionable

        context.setConfigLocation(uri); // Questionable

        // Load the configuration from a stream or file
        new ConfigurationSource(stream);  // Questionable
        new ConfigurationSource(stream, file);  // Questionable
        new ConfigurationSource(stream, url);  // Questionable
        ConfigurationSource.fromResource(source, loader);  // Questionable
        ConfigurationSource.fromUri(uri);  // Questionable
    }
}




// === java.util.logging ===
import java.util.logging.*;

class M {
    void foo(LogManager logManager, Logger logger, java.io.InputStream is, Handler handler)
            throws SecurityException, java.io.IOException {
        logManager.readConfiguration(is); // Questionable

        logger.setLevel(Level.FINEST); // Questionable
        logger.addHandler(handler); // Questionable
    }
}

// === Logback ===
import ch.qos.logback.classic.util.ContextInitializer;
import ch.qos.logback.core.Appender;
import ch.qos.logback.classic.joran.JoranConfigurator;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.*;

class M {
    void foo(Logger logger, Appender<ILoggingEvent> fileAppender) {
        System.setProperty(ContextInitializer.CONFIG_FILE_PROPERTY, "config.xml"); // Questionable
        JoranConfigurator configurator = new JoranConfigurator(); // Questionable

        logger.addAppender(fileAppender); // Questionable
        logger.setLevel(Level.DEBUG); // Questionable
    }
}


```
**Exceptions**
```java

Log4J 1.x is not covered as it has reached end of life.

#### Rule 82: Hashing data is security-sensitive
##### Quality Category: Security Hotspot
Hashing data is security-sensitive. It has led in the past to the following vulnerabilities:

CVE-2018-9233
CVE-2013-5097
CVE-2007-1051

Cryptographic hash functions are used to uniquely identify information without storing their original form. When not done properly, an attacker can steal the original information by guessing it (ex: with a rainbow table), or replace the original data with another one having the same hash.

This rule flags code that initiates hashing.

Ask Yourself Whether
 the hashed value is used in a security context.
 the hashing algorithm you are using is known to have vulnerabilities.
salts are not automatically generated and applied by the hashing function.
 any generated salts are cryptographically weak or not credential-specific.

You are at risk if you answered yes to the first question and any of the following ones.

Recommended Secure Coding Practices
 for security related purposes, use only hashing algorithms which are currently known to be strong. Avoid using algorithms like MD5 and SHA1 completely in security contexts.
 do not define your own hashing- or salt algorithms as they will most probably have flaws.
 do not use algorithms that compute too quickly, like SHA256, as it must remain beyond modern hardware capabilities to perform brute force and dictionary based attacks.
 use a hashing algorithm that generate its own salts as part of the hashing. If you generate your own salts, make sure that a cryptographically strong salt algorithm is used, that generated salts are credential-specific, and finally, that the salt is applied correctly before the hashing.
 save both the salt and the hashed value in the relevant database record; during future validation operations, the salt and hash can then be retrieved from the database. The hash is recalculated with the stored salt and the value being validated, and the result compared to the stored hash.
 the strength of hashing algorithms often decreases over time as hardware capabilities increase. Check regularly that the algorithms you are using are still considered secure. If needed, rehash your data using a stronger algorithm.
Questionable Code Example
// === MessageDigest ===
import java.security.MessageDigest;
import java.security.Provider;

class A {
    void foo(String algorithm, String providerStr, Provider provider) throws Exception {
        MessageDigest.getInstance(algorithm); // Questionable
        MessageDigest.getInstance(algorithm, providerStr); // Questionable
        MessageDigest.getInstance(algorithm, provider); // Questionable
    }
}


Regarding SecretKeyFactory. Any call to SecretKeyFactory.getInstance("...") with an argument starting by "PBKDF2" will be highlighted. 
*See*
 OWASP guidelines, list of standard algorithms and algorithms on android.

// === javax.crypto ===
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;

class A {
    void foo(char[] password, byte[] salt, int iterationCount, int keyLength) throws Exception {
        // Questionable. Review this, even if it is the way recommended by OWASP
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterationCount, keyLength);
        factory.generateSecret(spec).getEncoded();
    }
}


Regarding Guava, only the hashing functions which are usually misused for sensitive data will raise an issue, i.e. md5 and sha*.

// === Guava ===
import com.google.common.hash.Hashing;

class A {
    void foo() {
        Hashing.md5(); // Questionable
        Hashing.sha1(); // Questionable
        Hashing.sha256(); // Questionable
        Hashing.sha384(); // Questionable
        Hashing.sha512(); // Questionable
    }
}

// === org.apache.commons ===
import org.apache.commons.codec.digest.DigestUtils;

class A {
    void foo(String strName, byte[] data, String str, java.io.InputStream stream) throws Exception {
        new DigestUtils(strName); // Questionable
        new DigestUtils(); // Questionable

        DigestUtils.getMd2Digest(); // Questionable
        DigestUtils.getMd5Digest(); // Questionable
        DigestUtils.getShaDigest(); // Questionable
        DigestUtils.getSha1Digest(); // Questionable
        DigestUtils.getSha256Digest(); // Questionable
        DigestUtils.getSha384Digest(); // Questionable
        DigestUtils.getSha512Digest(); // Questionable


        DigestUtils.md2(data); // Questionable
        DigestUtils.md2(stream); // Questionable
        DigestUtils.md2(str); // Questionable
        DigestUtils.md2Hex(data); // Questionable
        DigestUtils.md2Hex(stream); // Questionable
        DigestUtils.md2Hex(str); // Questionable

        DigestUtils.md5(data); // Questionable
        DigestUtils.md5(stream); // Questionable
        DigestUtils.md5(str); // Questionable
        DigestUtils.md5Hex(data); // Questionable
        DigestUtils.md5Hex(stream); // Questionable
        DigestUtils.md5Hex(str); // Questionable

        DigestUtils.sha(data); // Questionable
        DigestUtils.sha(stream); // Questionable
        DigestUtils.sha(str); // Questionable
        DigestUtils.shaHex(data); // Questionable
        DigestUtils.shaHex(stream); // Questionable
        DigestUtils.shaHex(str); // Questionable

        DigestUtils.sha1(data); // Questionable
        DigestUtils.sha1(stream); // Questionable
        DigestUtils.sha1(str); // Questionable
        DigestUtils.sha1Hex(data); // Questionable
        DigestUtils.sha1Hex(stream); // Questionable
        DigestUtils.sha1Hex(str); // Questionable

        DigestUtils.sha256(data); // Questionable
        DigestUtils.sha256(stream); // Questionable
        DigestUtils.sha256(str); // Questionable
        DigestUtils.sha256Hex(data); // Questionable
        DigestUtils.sha256Hex(stream); // Questionable
        DigestUtils.sha256Hex(str); // Questionable

        DigestUtils.sha384(data); // Questionable
        DigestUtils.sha384(stream); // Questionable
        DigestUtils.sha384(str); // Questionable
        DigestUtils.sha384Hex(data); // Questionable
        DigestUtils.sha384Hex(stream); // Questionable
        DigestUtils.sha384Hex(str); // Questionable

        DigestUtils.sha512(data); // Questionable
        DigestUtils.sha512(stream); // Questionable
        DigestUtils.sha512(str); // Questionable
        DigestUtils.sha512Hex(data); // Questionable
        DigestUtils.sha512Hex(stream); // Questionable
        DigestUtils.sha512Hex(str); // Questionable
    }
}


*See*

MITRE, CWE-916 - Use of Password Hash With Insufficient Computational Effort
MITRE, CWE-759 - Use of a One-Way Hash without a Salt
MITRE, CWE-760 - Use of a One-Way Hash with a Predictable Salt
 OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
SANS Top 25 - Porous Defenses
#### Rule 83: Encrypting data is security-sensitive
##### Quality Category: Security Hotspot
Encrypting data is security-sensitive. It has led in the past to the following vulnerabilities:

CVE-2017-7902
CVE-2006-1378
CVE-2003-1376

Proper encryption requires both the encryption algorithm and the key to be strong. Obviously the private key needs to remain secret and be renewed regularly. However these are not the only means to defeat or weaken an encryption.

This rule flags function calls that initiate encryption/decryption. The goal is to guide security code reviews.

Ask Yourself Whether
 the private key might not be random, strong enough or the same key is reused for a long long time.
 the private key might be compromised. It can happen when it is stored in an unsafe place or when it was transferred in an unsafe manner.
 the key exchange is made without properly authenticating the receiver.
 the encryption algorithm is not strong enough for the level of protection required. Note that encryption algorithms strength decreases as time passes.
 the chosen encryption library is deemed unsafe.
 a nonce is used, and the same value is reused multiple times, or the nonce is not random.
 the RSA algorithm is used, and it does not incorporate an Optimal Asymmetric Encryption Padding (OAEP), which might weaken the encryption.
 the CBC (Cypher Block Chaining) algorithm is used for encryption, and it's IV (Initialization Vector) is not generated using a secure random algorithm, or it is reused.
 the Advanced Encryption Standard (AES) encryption algorithm is used with an unsecure mode. 
*See*
 the recommended practices for more information.

You are at risk if you answered yes to any of those questions.

Recommended Secure Coding Practices
 Generate encryption keys using secure random algorithms.
 When generating cryptographic keys (or key pairs), it is important to use a key length that provides enough entropy against brute-force attacks. For the Blowfish algorithm the key should be at least 128 bits long, while for the RSA algorithm it should be at least 2048 bits long.
 Regenerate the keys regularly.
 Always store the keys in a safe location and transfer them only over safe channels.
 If there is an exchange of cryptographic keys, check first the identity of the receiver.
 Only use strong encryption algorithms. Check regularly that the algorithm is still deemed secure. It is also imperative that they are implemented correctly. Use only encryption libraries which are deemed secure. Do not define your own encryption algorithms as they will most probably have flaws.
 When a nonce is used, generate it randomly every time.
 When using the RSA algorithm, incorporate an Optimal Asymmetric Encryption Padding (OAEP).
 When CBC is used for encryption, the IV must be random and unpredictable. Otherwise it exposes the encrypted value to crypto-analysis attacks like "Chosen-Plaintext Attacks". Thus a secure random algorithm should be used. An IV value should be associated to one and only one encryption cycle, because the IV's purpose is to ensure that the same plaintext encrypted twice will yield two different ciphertexts.
 The Advanced Encryption Standard (AES) encryption algorithm can be used with various modes. Galois/Counter Mode (GCM) with no padding should be preferred to the following combinations which are not secured:
 Electronic Codebook (ECB) mode: Under a given key, any given plaintext block always gets encrypted to the same ciphertext block. Thus, it does not hide data patterns well. In some senses, it doesn't provide serious message confidentiality, and it is not recommended for use in cryptographic protocols at all.
 Cipher Block Chaining (CBC) with PKCS#5 padding (or PKCS#7) is susceptible to padding oracle attacks.
Questionable Code Example
// === javax.crypto ===
import javax.crypto.Cipher;
Cipher c = Cipher.getInstance(...);  // Questionable

// === apache.commons.crypto ===
import java.util.Properties;
import org.apache.commons.crypto.utils.Utils;
import org.apache.commons.crypto.cipher.CryptoCipherFactory;
import org.apache.commons.crypto.cipher.CryptoCipherFactory.CipherProvider;

Properties properties = new Properties();
properties.setProperty(CryptoCipherFactory.CLASSES_KEY, CipherProvider.OPENSSL.getClassName());
final String transform = "AES/CBC/PKCS5Padding";
Utils.getCipherInstance(transform, properties);  // Questionable


*See*

MITRE, CWE-321 - Use of Hard-coded Cryptographic Key
MITRE, CWE-322 - Key Exchange without Entity Authentication
MITRE, CWE-323 - Reusing a Nonce, Key Pair in Encryption
MITRE, CWE-324 - Use of a Key Past its Expiration Date
MITRE, CWE-325 - Missing Required Cryptographic Step
MITRE, CWE-326 - Inadequate Encryption Strength
MITRE, CWE-327 - Use of a Broken or Risky Cryptographic Algorithm
MITRE, CWE-522 - Insufficiently Protected Credentials
 [OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
 [OWASP Top 10 2017 Category A6 - Security Misconfiguration
SANS Top 25 - Porous Defenses
#### Rule 84: Using regular expressions is security-sensitive
##### Quality Category: Security Hotspot
Using regular expressions is security-sensitive. It has led in the past to the following vulnerabilities:

CVE-2017-16021
CVE-2018-13863
CVE-2018-8926

Regular Expressions are subject to different kinds of vulnerabilities.

First, evaluating regular expressions against input strings is potentially an extremely CPU-intensive task. Specially crafted regular expressions such as (a+)+ will take several seconds to evaluate the input string aaaaaaaaaaaaaaaaaaaaaaaaaaaaa!. The problem is that with every additional a character added to the input, the time required to evaluate the regex doubles. However, the equivalent regular expression, a+ (without grouping) is efficiently evaluated in milliseconds and scales linearly with the input size.

Evaluating user-provided strings as regular expressions opens the door to Regular expression Denial of Service (ReDoS) attacks. In the context of a web application, attackers can force the web server to spend all of its resources evaluating regular expressions thereby making the service inaccessible to genuine users.

Another type of vulnerability can occur when regular expressions are used to validate user input. A regular expression can be used to filter unsafe input by either matching a whole input when it is valid (example: the whole string should only contain alphanumeric characters) or by detecting dangerous parts of an input. In both cases it is possible to let dangerous values through. For example, searching for <script> tags in some HTML code with the regular expression .*<script>.* will miss <script id="test">.

This rule flags any regular expression execution or compilation for review.

Ask Yourself Whether
 a user input string is executed as a regular-expression, or it is inserted in a regular expression.
 a user can provide a string which will be analyzed by a regular expression.
 your regular expression engine performance decrease with specially crafted inputs and regular expressions.
 the regular expression is used to validate unsafe input, but it does not detect all dangerous values.

You may be at risk if you answered yes to any of those questions.

Recommended Secure Coding Practices

Avoid executing a user input string as a regular expression. If this is required, restrict the allowed regular expressions.

Check whether your regular expression engine (the algorithm executing your regular expression) has any known vulnerabilities. Search for vulnerability reports mentioning the one engine you're are using.

Test your regular expressions with techniques such as equivalence partitioning, and boundary value analysis, and test for robustness. Try not to make complex regular expressions as they are difficult to understand and test. Note that some regular expression engines will match only part of the input if no anchors are used. In PHP for example preg_match("/[A-Za-z0-9]+/", $text) will accept any string containing at least one alphanumeric character because it has no anchors.

Questionable Code Example
import java.util.regex.Pattern;

class BasePattern {
  String regex; // a regular expression
  String input; // a user input

  void foo(CharSequence htmlString) {
    input.matches(regex);  // Questionable
    Pattern.compile(regex);  // Questionable
    Pattern.compile(regex, Pattern.CASE_INSENSITIVE);  // Questionable

    String replacement = "test";
    input.replaceAll(regex, replacement);  // Questionable
    input.replaceFirst(regex, replacement);  // Questionable

    if (!Pattern.matches(".*<script>.*", htmlString)) { // Questionable, even if the pattern is hard-coded
    }
  }
}


This also applies for bean validation, where regexp can be specified:

import java.io.Serializable;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Email;
import org.hibernate.validator.constraints.URL;

class BeansRegex implements Serializable {
  @Pattern(regexp=".+@.+")  // Questionable
  private String email;

  @Email(regexp=".+@.+")  // Questionable
  private String email2;

  @URL(regexp=".*") // Questionable
  private String url;
  // ...
}


```
**Exceptions**
```java

Calls to java.util.regex.Pattern.matcher(...), java.util.regex.Pattern.split(...) and all methods of java.util.regex.Matcher are not highlighted as the pattern compilation is already highlighted.

Calls to String.split(regex) and String.split(regex, limit) will not raise an exception despite their use of a regular expression. These methods are used most of the time to split on a single character, which doesn't create any vulnerability.


*See*

MITRA, CWE-624 - Executable Regular Expression Error
MITRA, CWE-185 - Incorrect Regular Expression
 OWASP Regular expression Denial of Service - ReDoS
 OWASP Top 10 2017 Category A1 - Injection
SANS Top 25 - Porous Defenses

#### Rule 85: Executing OS commands is security-sensitive
##### Quality Category: Security Hotspot
OS commands are security-sensitive. For example, their use has led in the past to the following vulnerabilities:

CVE-2018-12465
CVE-2018-7187

Applications that execute operating system commands or execute commands that interact with the underlying system should neutralize any externally-provided input used to construct those commands. Failure to do so could allow an attacker to execute unexpected or dangerous commands, potentially leading to loss of confidentiality, integrity or availability.

This rule flags code that specifies the name of the command to run. The goal is to guide security code reviews.

Ask Yourself Whether
 the executed command is constructed by input that is externally-influenced, for example, user input (attacker). (*)
 the command execution is not restricted to the right users. (*)
 the application can be redesigned to not rely on external input to execute the command.

(*) You are at risk if you answered yes to any of those questions.

Recommended Secure Coding Practices

Restrict the control given to the user over the executed command:

 make the executed command part of a whitelist and reject all commands not part of this list.
 sanitize the user input.

Restrict which users can have access to the command:

 use a firewall to protect the process running the code, and to protect the network from the command.
 authenticate the user and allow only some users to run the command.

Reduce the damage the command can do:

 execute the code in a sandbox environment that enforces strict boundaries between the operating system and the process. For example: a "jail".
 refuse to run the command if the process has too many privileges. For example: forbid running the code as "root".

Questionable Code Example
Runtime.getRuntime().exec(...);  // Questionable. Validate the executed command.

ProcessBuilder pb = new ProcessBuilder(command);  // Questionable.
pb.command(command);  // Questionable.

// === apache.commons ===
import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;

CommandLine cmdLine = CommandLine.parse("bad.exe");
DefaultExecutor executor = new DefaultExecutor();
executor.execute(cmdLine); // Questionable



```
**Exceptions**
```java

The following code will not raise any issue.

ProcessBuilder pb = new ProcessBuilder();
pb.command();


*See*

MITRE, CWE-78 - Improper Neutralization of Special Elements used in an OS Command
 OWASP Top 10 2017 Category A1 - Injection
SANS Top 25 - Insecure Interaction Between Components

#### Rule 86: Using unsafe Jackson deserialization configuration is security-sensitive
##### Quality Category: Security Hotspot
When Jackson is configured to allow Polymorphic Type Handling (aka PTH), formerly known as Polymorphic Deserialization, "deserialization gadgets" may allow an attacker to perform remote code execution.

This rule raises an issue when:

- enableDefaultTyping() is called on an instance of com.fasterxml.jackson.databind.ObjectMapper or org.codehaus.jackson.map.ObjectMapper

- or when the annotation @JsonTypeInfo is set at class or field levels and configured with use = JsonTypeInfo.Id.CLASS) or use = Id.MINIMAL_CLASS

Recommended Secure Coding Practices
 Consider using @JsonTypeInfo instead of enabling globally PTH
 Use @JsonTypeInfo(use = Id.NAME) instead
**Noncompliant Code Example**
```java
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping(); // Noncompliant

@JsonTypeInfo(use = Id.CLASS) // Noncompliant
abstract class PhoneNumber {
}


```
**Compliant Solution**
```java

- use the latest patch versions of jackson-databind blocking the already discovered "deserialization gadgets"

- avoid using the default typing configuration: ObjectMapper.enableDefaultTyping()

- use @JsonTypeInfo(use = Id.NAME) instead of @JsonTypeInfo(use = Id.CLASS) or @JsonTypeInfo(use = Id. MINIMAL_CLASS) and so rely on @JsonTypeName and @JsonSubTypes


*See*

MITRE, CWE-502 - Deserialization of Untrusted Data
 OWASP Top 10 2017 Category A8 - Insecure Deserialization
OWASP Deserialization of untrusted data
On Jackson CVEs: Don’t Panic
CVE-2017-1509
CVE-2017-7525
 Derived from FindSecBugs rule JACKSON_UNSAFE_DESERIALIZATION
#### Rule 87: Exposing HTTP endpoints is security-sensitive
##### Quality Category: Security Hotspot
Exposing HTTP endpoints is security-sensitive. It has led in the past to the following vulnerabilities:

CVE-2016-3072
CVE-2015-3175
CVE-2003-0218

HTTP endpoints are webservices' main entrypoint. Attackers will take advantage of any vulnerability by sending crafted inputs for headers (including cookies), body and URI. No input should be trusted and extreme care should be taken with all returned value (header, body and status code).

This rule flags code which creates HTTP endpoint. It guides security code reviews to security-sensitive code.

In the case of the Spring framework, methods of a @Controller object annotated with @RequestMapping (or all its variants such as @GetMapping, @PostMapping, @PutMapping, @PatchMapping and @DeleteMapping) are declaring HTTP endpoints.

Ask Yourself Whether
 an input is not sanitized before being used. This includes any value coming from the URI, header, body and cookies.
 the response contains some unsafe data. for example the input could come from a database which contains user inputs. Check the response's headers, cookies, body and status code.
 the response contains some sensitive information which the user shouldn't have access to.

no access control prevents attackers from successfully performing a forbidden request.

 an attacker can get sensitive information by analyzing the returned errors. For example, a web service can expose the existence of user accounts by returning 403 (Forbidden) instead of 404 (Not Found) when an attacker ask for them.

You are at risk if you answered yes to any of those questions.

Recommended Secure Coding Practices

Never trust any part of the request to be safe. Make sure that the URI, header and body are properly sanitized before being used. Their content, length, encoding, name (ex: name of URL query parameters) should be checked. Validate that the values are in a predefined whitelist. The opposite, i.e. searching for dangerous values in a given input, can easily miss some of them.

Do not rely solely on cookies when you implement your authentication and permission logic. Use additional protections such as CSRF tokens when possible.

Do not expose sensitive information in your response. If the endpoint serves files, limit the access to a dedicated directory. Protect your sensitive cookies so that client-side javascript cannot read or modify them.

Sanitize all values before returning them in a response, be it in the body, header or status code. Special care should be taken to avoid the following attacks:

Cross-site Scripting (XSS), which happens when an unsafe value is included in an HTML page.
Unvalidated redirects which can happen when the Location header is compromised.

Restrict security-sensitive actions, such as file upload, to authenticated users.

Be careful when errors are returned to the client, as they can provide sensitive information. Use 404 (Not Found) instead of 403 (Forbidden) when the existence of a resource is sensitive.

**Noncompliant Code Example**
```java
@RequestMapping(path = "/profile", method = RequestMethod.GET) // Noncompliant
public UserProfile getUserProfile(String name) {
...
}


*See*

MITRE, CWE-20 - Improper Input Validation
MITRE, CWE-352 - Cross-Site Request Forgery (CSRF)
MITRE, CWE-79 - Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
MITRE, CWE-22 - Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
 OWASP Top 10 2017 Category A1 - Injection
 OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
 OWASP Top 10 2017 Category A7 - Cross-Site Scripting (XSS)
SANS Top 25 - Insecure Interaction Between Components
SANS Top 25 - Risky Resource Management
SANS Top 25 - Porous Defenses
#### Rule 88: Setting JavaBean properties is security-sensitive
##### Quality Category: Security Hotspot
Setting JavaBean properties is security sensitive. Doing it with untrusted values has led in the past to the following vulnerability:

CVE-2014-0114

JavaBeans can have their properties or nested properties set by population functions. An attacker can leverage this feature to push into the JavaBean malicious data that can compromise the software integrity. A typical attack will try to manipulate the ClassLoader and finally execute malicious code.

This rule raises an issue when:

 BeanUtils.populate(...) or BeanUtilsBean.populate(...) from Apache Commons BeanUtils are called
 BeanUtils.setProperty(...) or BeanUtilsBean.setProperty(...) from Apache Commons BeanUtils are called
 org.springframework.beans.BeanWrapper.setPropertyValue(...) or org.springframework.beans.BeanWrapper.setPropertyValues(...) from Spring is called
Ask Yourself Whether
 the new property values might have been tampered with or provided by an untrusted source.
 sensitive properties can be modified, for example: class.classLoader

You are at risk if you answered yes to any of these question.

Recommended Secure Coding Practices

Sanitize all values used as JavaBean properties.

Don't set any sensitive properties. Keep full control over which properties are set. If the property names are provided by an unstrusted source, filter them with a whitelist.

**Noncompliant Code Example**
```java
Company bean = new Company();
HashMap map = new HashMap();
Enumeration names = request.getParameterNames();
while (names.hasMoreElements()) {
    String name = (String) names.nextElement();
    map.put(name, request.getParameterValues(name));
}
BeanUtils.populate(bean, map); // Noncompliant; "map" is populated with data coming from user input, here "request.getParameterNames()"


*See*

MITRE, CWE-15 - External Control of System or Configuration Setting
 OWASP Top 10 2017 Category A1 - Injection
CERT, MSC61-J. - Do not use insecure or weak cryptographic algorithms
 Derived from FindSecBugs rule BEAN_PROPERTY_INJECTION
#### Rule 89: Deserializing XML from an untrusted source is security-sensitive
##### Quality Category: Security Hotspot
Deserialization from an untrusted source using the XMLDecoder library can lead to unexpected code execution. For example, it has led in the past to the following vulnerability:

CVE-2013-4221

XMLDecoder supports arbitrary method invocation. This capability is intended to call setter methods only but nothing prevents the execution of any other method.

This rule raises an issue when XMLDecoder is instantiated. The call to "readObject" is also highlighted to show where the malicious code can be executed.

Ask Yourself Whether
 the XML input can come from an untrusted source and be tainted by a hacker. (*)
 you require the advanced functionalities provided by the XMLDecoder class. If you simply need to deserialize XML you can use a more secure deserialization function.

(*) You are at risk if you answered yes to this question.

Recommended Secure Coding Practices

If you only need a simple deserialization, use instead one of the deserialization libraries recommended by OWASP.

If you really need to use XMLDecoder, make sure that the serialized data cannot be tampered with.

**Noncompliant Code Example**
```java
public void decode(InputStream in) {
  XMLDecoder d = new XMLDecoder(in); // Noncompliant
  Object result = d.readObject();
  [...]
  d.close();
}


*See*

MITRE, CWE-502 - Deserialization of Untrusted Data
 OWASP Top 10 2017 Category A1 - Injection
 OWASP Top 10 2017 Category A8 - Insecure Deserialization
OWASP Deserialization of untrusted data
 Derived from FindSecBugs rule XML_DECODER
#### Rule 90: Deserializing objects from an untrusted source is security-sensitive
##### Quality Category: Security Hotspot
Deserializing objects is security-sensitive. For example, it has led in the past to the following vulnerabilities:

CVE-2018-10654: Hazelcast Library: Java deserialization vulnerability
CVE-2018-1000058: Jenkins Pipeline: arbitrary code execution vulnerability

Object deserialization from an untrusted source can lead to unexpected code execution. ObjectInputStream doesn't provide a way to apply rules on its InputStream argument. Knowing that all serializable classes in the scope of the classloader will be deserialized, there is a possibility that malicious code could be executed during the deserialization phase even if, in the end, a ClassCastException will be raised.

Deserialization takes a stream of bits and turns it into an object. If the stream contains the type of object you expect, all is well. But if you're deserializing untrusted input, and an attacker has inserted some other type of object, you're in trouble. Why? There are a few different attack scenarios, but one widely-documented one goes like this: Deserialization first instantiates an Object, then uses the readObject method to populate it. If the attacker has overridden readObject then he is entirely in control of what code executes during that process. It is only after readObject has completed that your newly-minted Object can be cast to the type you expected. A ClassCastException or ClassNotFoundException will be thrown, but at that point it's too late.

Ask Yourself Whether
 an attacker could have tampered with the source provided to the deserialization function.
 you are using an unsafe deserialization function. 
*See*
 the Recommended Secure Coding Practices for examples of safe libraries.

You are at risk if you answered yes to any of those questions.

Recommended Secure Coding Practices

To prevent insecure deserialization, you should either use look-ahead deserialization (pre-Java 9) or a filter to make sure you're dealing with the correct type of object before you act on it.

Several third-party libraries offer look-ahead deserialization, including:

 ikkisoft's SerialKiller
 Apache Commons Class IO's ValidatingObjectInputStream
 contrast-rO0's SafeObjectInputStream

Note that it is possible to set a deserialization filter at the level of the JVM, but relying on that requires that your environment be configured perfectly. Every time. Additionally, such a filter may have unwanted impacts on other applications in the environment. On the other hand, setting a filter as close as possible to the deserialization that uses it allows you to specify a very narrow, focused filter.

You should also limit access to the serialized source. For example:

 if it is a file, restrict the access to it.
 if it comes from the network, restrict who has access to the process, such as with a Firewall or by authenticating the sender first.

*See*

MITRE, CWE-502 - Deserialization of Untrusted Data
 OWASP Top 10 2017 Category A8 - Insecure Deserialization
OWASP Deserialization of untrusted data
 Derived from FindSecBugs rule OBJECT_DESERIALIZATION
#### Rule 91: Delivering code in production with debug features activated is security-sensitive
##### Quality Category: Security Hotspot
Delivering code in production with debug features activated is security-sensitive. It has led in the past to the following vulnerabilities:

CVE-2018-1999007
CVE-2015-5306
CVE-2013-2006

An application's debug features enable developers to find bugs more easily. It often gives access to detailed information on both the system running the application and users. Sometime it even enables the execution of custom commands. Thus deploying on production servers an application which has debug features activated is extremely dangerous.

Ask Yourself Whether
 the code or configuration enabling the application debug features is deployed on production servers.
 the application runs by default with debug features activated.

You are at risk if you answered yes to any of these questions.

Recommended Secure Coding Practices

The application should run by default in the most secure mode, i.e. as on production servers. This is to prevent any mistake. Enabling debug features should be explicitly asked via a command line argument, an environment variable or a configuration file.

Check that every debug feature is controlled by only very few configuration variables: logging, exception/error handling, access control, etc... It is otherwise very easy to forget one of them.

Do not enable debug features on production servers.

**Noncompliant Code Example**
```java
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@Configuration
@EnableWebSecurity(debug = true) // Noncompliant
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
  // ...
}


```
**Compliant Solution**
```java
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@Configuration
@EnableWebSecurity(debug = false) // Compliant
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
  // ...
}


*See*

MITRE, CWE-489 - Leftover Debug Code
MITRE, CWE-215 - Information Exposure Through Debug Information
 OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
#### Rule 92: Disabling Spring Security's CSRF protection is security-sensitive
##### Quality Category: Security Hotspot
Spring Security is coming out of the box with a protection against CSRF attacks. With 4.0, this protection is even enabled by default. Spring's recommendation is to "use CSRF protection for any request that could be processed by a browser by normal users". So there is no reason to disable it for standard web applications.

Recommended Secure Coding Practices
 activate Spring Security's CSRF protection.
**Noncompliant Code Example**
```java
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  @Override
  protected void configure(HttpSecurity http) throws Exception {
	  http.csrf().disable(); // Noncompliant
	}
}


*See*

MITRE, CWE-352 - Cross-Site Request Forgery (CSRF)
 OWASP Top 10 2017 Category A6 - Security Misconfiguration
OWASP: Cross-Site Request Forgery
SANS Top 25 - Insecure Interaction Between Components
 Derived from FindSecBugs rule SPRING_CSRF_PROTECTION_DISABLED
Spring Security Official Documentation: When to use CSRF protection
#### Rule 93: Cookie domains should be as narrow as possible
##### Quality Category: Security Hotspot
A cookie's domain specifies which websites should be able to read it. Left blank, browsers are supposed to only send the cookie to sites that exactly match the sending domain. For example, if a cookie was set by lovely.dream.com, it should only be readable by that domain, and not by nightmare.com or even strange.dream.com. If you want to allow sub-domain access for a cookie, you can specify it by adding a dot in front of the cookie's domain, like so: .dream.com. But cookie domains should always use at least two levels.

Cookie domains can be set either programmatically or via configuration. This rule raises an issue when any cookie domain is set with a single level, as in .com.

**Noncompliant Code Example**
```java
Cookie myCookie = new Cookie("name", "val");
myCookie.setDomain(".com"); // Noncompliant
java.net.HttpCookie myOtherCookie = new java.net.HttpCookie("name", "val");
myOtherCookie.setDomain(".com"); // Noncompliant


```
**Compliant Solution**
```java
Cookie myCookie = new Cookie("name", "val"); // Compliant; by default, cookies are only returned to the server that sent them.

// or

Cookie myCookie = new Cookie("name", "val");
myCookie.setDomain(".myDomain.com"); // Compliant

java.net.HttpCookie myOtherCookie = new java.net.HttpCookie("name", "val");
myOtherCookie.setDomain(".myDomain.com"); // Compliant


*See*

 OWASP Top 10 2017 Category A7 - Cross-Site Scripting (XSS)
#### Rule 94: Changing or bypassing accessibility is security-sensitive
##### Quality Category: Security Hotspot
Changing or bypassing accessibility is security-sensitive. For example, it has led in the past to the following vulnerability:

CVE-2012-4681

private methods were made private for a reason, and the same is true of every other visibility level. Altering or bypassing the accessibility of classes, methods, or fields violates the encapsulation principle and could introduce security holes.

This rule raises an issue when reflection is used to change the visibility of a class, method or field, and when it is used to directly update a field value.

Ask Yourself Whether
 there is a good reason to override the existing accessibility level of the method/field. This is very rarely the case. Accessing hidden fields and methods will make your code unstable as they are not part of the public API and may change in future versions.
 this method is called by untrusted code. *
 it is possible to modify or bypass the accessibility of sensitive methods or fields using this code. *
 untrusted code can access the java reflection API. *

* You are at risk if you answered yes to those questions.

Recommended Secure Coding Practices

Don't change or bypass the accessibility of any method or field if possible.

If untrusted code can execute this method, make sure that it cannot decide which method or field's accessibility can be modified or bypassed.

Untrusted code should never have direct access to the java Reflection API. If this method can do it, make sure that it is an exception. Use ClassLoaders and SecurityManagers in order to sandbox any untrusted code and forbid access to the Reflection API.

Questionable Code Example
public void makeItPublic(String methodName) throws NoSuchMethodException {

  this.getClass().getMethod(methodName).setAccessible(true); // Questionable
}

public void setItAnyway(String fieldName, int value) {
  this.getClass().getDeclaredField(fieldName).setInt(this, value); // Questionable; bypasses controls in setter
}


*See*

 OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
CERT, SEC05-J. - Do not use reflection to increase accessibility of classes, methods, or fields
#### Rule 95: Using non-standard cryptographic algorithms is security-sensitive
##### Quality Category: Security Hotspot
The use of a non-standard algorithm is dangerous because a determined attacker may be able to break the algorithm and compromise whatever data has been protected. Standard algorithms like SHA-256, SHA-384, SHA-512, ... should be used instead.

This rule tracks creation of java.security.MessageDigest subclasses.

Recommended Secure Coding Practices
 use a standard algorithm instead of creating a custom one.
**Noncompliant Code Example**
```java
MyCryptographicAlgorithm extends MessageDigest {
  ...
}


*See*

CWE-327 - Use of a Broken or Risky Cryptographic Algorithm
 OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
SANS Top 25 - Porous Defenses
 Derived from FindSecBugs rule MessageDigest is Custom
#### Rule 96: Using pseudorandom number generators (PRNGs) is security-sensitive
##### Quality Category: Security Hotspot
Using pseudorandom number generators (PRNGs) is security-sensitive. For example, it has led in the past to the following vulnerabilities:

CVE-2013-6386
CVE-2006-3419
CVE-2008-4102

When software generates predictable values in a context requiring unpredictability, it may be possible for an attacker to guess the next value that will be generated, and use this guess to impersonate another user or access sensitive information.

As the java.util.Random class relies on a pseudorandom number generator, this class and relating java.lang.Math.random() method should not be used for security-critical applications or for protecting sensitive data. In such context, the java.security.SecureRandom class which relies on a cryptographically strong random number generator (RNG) should be used in place.

Ask Yourself Whether
 the code using the generated value requires it to be unpredictable. It is the case for all encryption mechanisms or when a secret value, such as a password, is hashed.
 the function you use generates a value which can be predicted (pseudo-random).
 the generated value is used multiple times.
 an attacker can access the generated value.

You are at risk if you answered yes to the first question and any of the following ones.

Recommended Secure Coding Practices
 Use a cryptographically strong random number generator (RNG) like "java.security.SecureRandom" in place of this PRNG.
 Use the generated random values only once.
 You should not expose the generated random value. If you have to store it, make sure that the database or file is secure.
Questionable Code Example
Random random = new Random(); // Questionable use of Random
byte bytes[] = new byte[20];
random.nextBytes(bytes); // Check if bytes is used for hashing, encryption, etc...

Compliant Solution
SecureRandom random = new SecureRandom(); // Compliant for security-sensitive use cases
byte bytes[] = new byte[20];
random.nextBytes(bytes);


*See*

MITRE, CWE-338 - Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
MITRE, CWE-330 - Use of Insufficiently Random Values
MITRE, CWE-326 - Inadequate Encryption Strength
MITRE, CWE-310 - Cryptographic Issues
CERT, MSC02-J. - Generate strong random numbers
CERT, MSC30-C. - Do not use the rand() function for generating pseudorandom numbers
CERT, MSC50-CPP. - Do not use std::rand() for generating pseudorandom numbers
 OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
 Derived from FindSecBugs rule Predictable Pseudo Random Number Generator
#### Rule 97: Executing SQL queries is security-sensitive
##### Quality Category: Security Hotspot
Executing SQL queries is security-sensitive. It has led in the past to the following vulnerabilities:

CVE-2018-9019
CVE-2018-7318
CVE-2017-5611

SQL injection is still one of the top 10 security vulnerabilities. Applications that execute SQL commands should neutralize any externally-provided values used in those commands. Failure to do so could allow an attacker to include input that changes the query so that unintended commands are executed, or sensitive data is exposed. Instead of trying to sanitize data by hand, SQL binding mechanisms should be used; they can be relied on to automatically perform a full sanitization.

This rule checks a variety of methods from different frameworks which are susceptible to SQL injection if not used properly. Frameworks which are covered are Java JDBC, JPA, JDO, Hibernate and Spring. The following specific method signatures are tested. Any SQL query built by concatenating or formatting Strings is considered susceptible. The goal is to guide security code reviews.

org.hibernate.Session.createQuery
org.hibernate.Session.createSQLQuery
java.sql.Statement.executeQuery
java.sql.Statement.execute
java.sql.Statement.executeUpdate
java.sql.Statement.executeLargeUpdate
java.sql.Statement.addBatch
java.sql.Connection.prepareStatement
java.sql.Connection.prepareCall
java.sql.Connection.nativeSQL
javax.persistence.EntityManager.createNativeQuery
javax.persistence.EntityManager.createQuery
org.springframework.jdbc.core.JdbcOperations.batchUpdate
org.springframework.jdbc.core.JdbcOperations.execute
org.springframework.jdbc.core.JdbcOperations.query
org.springframework.jdbc.core.JdbcOperations.queryForList
org.springframework.jdbc.core.JdbcOperations.queryForMap
org.springframework.jdbc.core.JdbcOperations.queryForObject
org.springframework.jdbc.core.JdbcOperations.queryForRowSet
org.springframework.jdbc.core.JdbcOperations.queryForInt
org.springframework.jdbc.core.JdbcOperations.queryForLong
org.springframework.jdbc.core.JdbcOperations.update
org.springframework.jdbc.core.PreparedStatementCreatorFactory.<init>
org.springframework.jdbc.core.PreparedStatementCreatorFactory.newPreparedStatementCreator
javax.jdo.PersistenceManager.newQuery
javax.jdo.Query.setFilter
javax.jdo.Query.setGrouping

If a method is defined in an interface, implementations are also tested. For example this is the case for org.springframework.jdbc.core.JdbcOperations , which is usually used as org.springframework.jdbc.core.JdbcTemplate).

Ask Yourself Whether
 the SQL query contains any non sanitized input from a user or another untrusted source.

You are at risk if you answered yes to this question.

Recommended Secure Coding Practices
 Avoid building queries manually using concatenation or formatting. If you do it anyway, do not include user input in this building process.
 Use parameterized queries, prepared statements, or stored procedures whenever possible.
 You may also use ORM frameworks such as Hibernate which, if used correctly, reduce injection risks.
 Avoid executing SQL queries containing unsafe input in stored procedures or functions.
Sanitize every unsafe input.

You can also reduce the impact of an attack by using a database account with low privileges.

**Noncompliant Code Example**
```java
public User getUser(Connection con, String user) throws SQLException {

  Statement stmt1 = null;
  Statement stmt2 = null;
  PreparedStatement pstmt;
  try {
    stmt1 = con.createStatement();
    ResultSet rs1 = stmt1.executeQuery("GETDATE()"); // Compliant; parameters not used here

    stmt2 = con.createStatement();
    ResultSet rs2 = stmt2.executeQuery("select FNAME, LNAME, SSN " +
                 "from USERS where UNAME=" + user);  // Noncompliant; parameter concatenated directly into query

    pstmt = con.prepareStatement("select FNAME, LNAME, SSN " +
                 "from USERS where UNAME=" + user);  // Noncompliant; parameter concatenated directly into query
    ResultSet rs3 = pstmt.executeQuery();

    //...
}

public User getUserHibernate(org.hibernate.Session session, String userInput) {

  org.hibernate.Query query = session.createQuery(  // Compliant
            "FROM students where fname = " + userInput);  // Noncompliant; parameter binding should be used instead
  // ...
}


```
**Compliant Solution**
```java
public User getUser(Connection con, String user) throws SQLException {

  Statement stmt1 = null;
  PreparedStatement pstmt = null;
  String query = "select FNAME, LNAME, SSN " +
                 "from USERS where UNAME=?"
  try {
    stmt1 = con.createStatement();
    ResultSet rs1 = stmt1.executeQuery("GETDATE()");

    pstmt = con.prepareStatement(query);
    pstmt.setString(1, user);  // Compliant; PreparedStatements escape their inputs.
    ResultSet rs2 = pstmt.executeQuery();

    //...
  }
}

public User getUserHibernate(org.hibernate.Session session, String userInput) {

  org.hibernate.Query query =  session.createQuery("FROM students where fname = ?");
  query = query.setParameter(0,userInput);  // Parameter binding escapes all input
  // ...


*See*

MITRE, CWE-89 - Improper Neutralization of Special Elements used in an SQL Command
MITRE, CWE-564 - SQL Injection: Hibernate
MITRE, CWE-20 - Improper Input Validation
MITRE, CWE-943 - Improper Neutralization of Special Elements in Data Query Logic
 OWASP Top 10 2017 Category A1 - Injection
CERT, IDS00-J. - Prevent SQL injection
SANS Top 25 - Insecure Interaction Between Components
 Derived from FindSecBugs rules Potential SQL/JPQL Injection (JPA), Potential SQL/JDOQL Injection (JDO), Potential SQL/HQL Injection (Hibernate)
#### Rule 98: Dynamically executing code is security-sensitive
##### Quality Category: Security Hotspot
Executing code dynamically is security-sensitive. It has led in the past to the following vulnerabilities:

CVE-2017-9807
CVE-2017-9802
CVE-2016-9182
CVE-2018-1000210

It is dangerous to let external sources either:

 execute unknown code in your process. Such Injected Code can either run on the server or in the client (exemple: XSS attack).
 select the code which will be executed via reflection.

This rule marks for review each occurence of such dynamic code execution. The goal is to guide security code reviews.

Ask Yourself Whether
 the executed code may come from a untrusted source and hasn't been sanitized.
 the code to run is dynamically chosen via reflection, and an untrusted source can use it to choose which code to run. For example a class could be retrieved by its name and this name comes from a user input.

You are at risk if you answered yes to any of these questions.

Recommended Secure Coding Practices

Regarding the execution of unknown code, the best solution is to not run code provided by an untrusted source. If you really need to do it, run the code in a sandboxed environment. Use jails, firewalls and whatever means your operating system and programming language provide (example: Security Managers in java, iframes and same-origin policy for javascript in a web browser).

Do not try to create a blacklist of dangerous code. It is impossible to cover all attacks that way.

As for the use of reflection, it should be strictly controlled as it can lead to many vulnerabilities. Never let an untrusted source decide what code to run. If you have to do it anyway, create a list of allowed code and choose among this list.

Questionable Code Example
public class Reflection {

    public static void run(java.lang.ClassLoader loader, String className, String methodName, String fieldName,
            Class<?> parameterTypes)
            throws NoSuchMethodException, SecurityException, ClassNotFoundException, NoSuchFieldException {

        Class<?> clazz = Class.forName(className); // Questionable
        clazz.getMethod(methodName, parameterTypes); // Questionable
        clazz.getMethods(); // Questionable
        clazz.getField(fieldName); // Questionable
        clazz.getFields(); // Questionable
        clazz.getDeclaredField(fieldName); // Questionable
        clazz.getDeclaredFields(); // Questionable
        clazz.getDeclaredClasses(); // Questionable

        loader.loadClass(className); // Questionable
    }
}


```
**Exceptions**
```java

Calling reflection methods with a hard-coded type name, method name or field name will not raise an issue.


*See*

MITRE CWE-95 - Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')
MITRE CWE-470 - Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')
 OWASP Top 10 2017 Category A1 - Injection
 OWASP Top 10 2017 Category A7 - Cross-Site Scripting (XSS)

#### Rule 99: String offset-based methods should be preferred for finding substrings from offsets
##### Quality Category: Code Smell
Looking for a given substring starting from a specified offset can be achieved by such code: str.substring(beginIndex).indexOf(char1). This works well, but it creates a new String for each call to the substring method. When this is done in a loop, a lot of Strings are created for nothing, which can lead to performance problems if str is large.

To avoid performance problems, String.substring(beginIndex) should not be chained with the following methods:

- indexOf(int ch)

- indexOf(String str)

- lastIndexOf(int ch)

- lastIndexOf(String str)

- startsWith(String prefix)

For each of these methods, another method with an additional parameter is available to specify an offset.

Using these methods gives the same result while avoiding the creation of additional String instances.

**Noncompliant Code Example**
```java
str.substring(beginIndex).indexOf(char1); // Noncompliant; a new String is going to be created by "substring"


```
**Compliant Solution**
```java
str.indexOf(char1, beginIndex);
```
#### Rule 100: "default" clauses should be last
##### Quality Category: Code Smell
switch can contain a default clause for various reasons: to handle unexpected values, to show that all the cases were properly considered.

For readability purpose, to help a developer to quickly find the default behavior of a switch statement, it is recommended to put the default clause at the end of the switch statement. This rule raises an issue if the default clause is not the last one of the switch's cases.

**Noncompliant Code Example**
```java
switch (param) {
  case 0:
    doSomething();
    break;
  default: // default clause should be the last one
    error();
    break;
  case 1:
    doSomethingElse();
    break;
}


```
**Compliant Solution**
```java
switch (param) {
  case 0:
    doSomething();
    break;
  case 1:
    doSomethingElse();
    break;
  default:
    error();
    break;
}


*See*

 MISRA C:2004, 15.3 - The final clause of a switch statement shall be the default clause
 MISRA C++:2008, 6-4-6 - The final clause of a switch statement shall be the default-clause
 MISRA C:2012, 16.4 - Every switch statement shall have a default label
 MISRA C:2012, 16.5 - A default label shall appear as either the first or the last switch label of a switch statement
#### Rule 101: "equals" method parameters should not be marked "@Nonnull"
##### Quality Category: Code Smell
By contract, the equals(Object) method, from java.lang.Object, should accept a null argument. Among all the other cases, the null case is even explicitly detailed in the Object.equals(...) Javadoc, stating "_For any non-null reference value x, x.equals(null) should return false._"

Assuming that the argument to equals is always non-null, and enforcing that assumption with an annotation is not only a fundamental violation of the contract of equals, but it is also likely to cause problems in the future as the use of the class evolves over time.

The rule raises an issue when the equals method is overridden and its parameter annotated with any kind of @Nonnull annotation.

**Noncompliant Code Example**
```java
public boolean equals(@javax.annotation.Nonnull Object obj) { // Noncompliant
  // ...
}


```
**Compliant Solution**
```java
public boolean equals(Object obj) {
  if (obj == null) {
    return false;
  }
  // ...
}
```
#### Rule 102: A conditionally executed single line should be denoted by indentation
##### Quality Category: Code Smell
In the absence of enclosing curly braces, the line immediately after a conditional is the one that is conditionally executed. By both convention and good practice, such lines are indented. In the absence of both curly braces and indentation the intent of the original programmer is entirely unclear and perhaps not actually what is executed. Additionally, such code is highly likely to be confusing to maintainers.

**Noncompliant Code Example**
```java
if (condition)  // Noncompliant
doTheThing();

doTheOtherThing();
somethingElseEntirely();

foo();


```
**Compliant Solution**
```java
if (condition)
  doTheThing();

doTheOtherThing();
somethingElseEntirely();

foo();
```
#### Rule 103: Conditionals should start on new lines
##### Quality Category: Code Smell
Code is clearest when each statement has its own line. Nonetheless, it is a common pattern to combine on the same line an if and its resulting then statement. However, when an if is placed on the same line as the closing } from a preceding else or else if, it is either an error - else is missing - or the invitation to a future error as maintainers fail to understand that the two statements are unconnected.

**Noncompliant Code Example**
```java
if (condition1) {
  // ...
} if (condition2) {  // Noncompliant
  //...
}


```
**Compliant Solution**
```java
if (condition1) {
  // ...
} else if (condition2) {
  //...
}


Or

if (condition1) {
  // ...
}

if (condition2) {
  //...
}
```
#### Rule 104: Cognitive Complexity of methods should not be too high
##### Quality Category: Code Smell
Cognitive Complexity is a measure of how hard the control flow of a method is to understand. Methods with high Cognitive Complexity will be difficult to maintain.


*See*

Cognitive Complexity
#### Rule 105: Factory method injection should be used in "@Configuration" classes
##### Quality Category: Code Smell
When @Autowired is used, dependencies need to be resolved when the class is instantiated, which may cause early initialization of beans or lead the context to look in places it shouldn't to find the bean. To avoid this tricky issue and optimize the way the context loads, dependencies should be requested as late as possible. That means using parameter injection instead of field injection for dependencies that are only used in a single @Bean method.

**Noncompliant Code Example**
```java
@Configuration
public class ​FooConfiguration {

  @Autowired private ​DataSource dataSource​;  // Noncompliant

  @Bean
  public ​MyService myService() {
    return new ​MyService(this​.dataSource​);
  }
}


```
**Compliant Solution**
```java
@Configuration
public class ​FooConfiguration {

 @Bean
  public ​MyService myService(DataSource dataSource) {
    return new ​MyService(dataSource);
  }
}


```
**Exceptions**
```java

Fields used in methods that are called directly by other methods in the application (as opposed to being invoked automatically by the Spring framework) are ignored by this rule so that direct callers don't have to provide the dependencies themselves.
```
#### Rule 106: Instance methods should not write to "static" fields
##### Quality Category: Code Smell
Correctly updating a static field from a non-static method is tricky to get right and could easily lead to bugs if there are multiple class instances and/or multiple threads in play. Ideally, static fields are only updated from synchronized static methods.

This rule raises an issue each time a static field is updated from a non-static method.

**Noncompliant Code Example**
```java
public class MyClass {

  private static int count = 0;

  public void doSomething() {
    //...
    count++;  // Noncompliant
  }
}
```
#### Rule 107: "indexOf" checks should not be for positive numbers
##### Quality Category: Code Smell
Most checks against an indexOf value compare it with -1 because 0 is a valid index. Any checks which look for values >0 ignore the first element, which is likely a bug. If the intent is merely to check inclusion of a value in a String or a List, consider using the contains method instead.

This rule raises an issue when an indexOf value retrieved either from a String or a List is tested against >0.

**Noncompliant Code Example**
```java
String color = "blue";
String name = "ishmael";

List<String> strings = new ArrayList<String> ();
strings.add(color);
strings.add(name);

if (strings.indexOf(color) > 0) {  // Noncompliant
  // ...
}
if (name.indexOf("ish") > 0) { // Noncompliant
  // ...
}
if (name.indexOf("ae") > 0) { // Noncompliant
  // ...
}


```
**Compliant Solution**
```java
String color = "blue";
String name = "ishmael";

List<String> strings = new ArrayList<String> ();
strings.add(color);
strings.add(name);

if (strings.indexOf(color) > -1) {
  // ...
}
if (name.indexOf("ish") >= 0) {
  // ...
}
if (name.contains("ae") {
  // ...
}
```
#### Rule 108: Method overrides should not change contracts
##### Quality Category: Code Smell
Because a subclass instance may be cast to and treated as an instance of the superclass, overriding methods should uphold the aspects of the superclass contract that relate to the Liskov Substitution Principle. Specifically, if the parameters or return type of the superclass method are marked with any of the following: @Nullable, @CheckForNull, @NotNull, @NonNull, and @Nonnull, then subclass parameters are not allowed to tighten the contract, and return values are not allowed to loosen it.

**Noncompliant Code Example**
```java
public class Fruit {

  private Season ripe;
  private String color;

  public void setRipe(@Nullable Season ripe) {
    this.ripe = ripe;
  }

  public @NotNull Integer getProtein() {
    return 12;
  }
}

public class Raspberry extends Fruit {

  public void setRipe(@NotNull Season ripe) {  // Noncompliant
    this.ripe = ripe;
  }

  public @Nullable Integer getProtein() {  // Noncompliant
    return null;
  }
}


*See*

 https://en.wikipedia.org/wiki/Liskov_substitution_principle
#### Rule 109: Null should not be returned from a "Boolean" method
##### Quality Category: Code Smell
While null is technically a valid Boolean value, that fact, and the distinction between Boolean and boolean is easy to forget. So returning null from a Boolean method is likely to cause problems with callers' code.

**Noncompliant Code Example**
```java
public Boolean isUsable() {
  // ...
  return null;  // Noncompliant
}


*See*

MITRE CWE-476 - NULL Pointer Dereference
CERT, EXP01-J. - Do not use a null in a case where an object is required
#### Rule 110: Classes should not access their own subclasses during initialization
##### Quality Category: Code Smell
When a parent class references a member of a subclass during its own initialization, the results might not be what you expect because the child class might not have been initialized yet. This could create what is known as an "initialisation cycle", or even a deadlock in some extreme cases.

To make things worse, these issues are very hard to diagnose so it is highly recommended you avoid creating this kind of dependencies.

**Noncompliant Code Example**
```java
class Parent {
  static int field1 = Child.method(); // Noncompliant
  static int field2 = 42;

  public static void main(String[] args) {
    System.out.println(Parent.field1); // will display "0" instead of "42"
  }
}

class Child extends Parent {
  static int method() {
    return Parent.field2;
  }
}


*See*

CERT, DCL00-J. - Prevent class initialization cycles
 Java Language Specifications - Section 12.4: Initialization of Classes and Interfaces
#### Rule 111: "Object.wait(...)" and "Condition.await(...)" should be called inside a "while" loop
##### Quality Category: Code Smell
According to the documentation of the Java Condition interface:

When waiting upon a Condition, a "spurious wakeup" is permitted to occur, in general, as a concession to the underlying platform semantics. This has little practical impact on most application programs as a Condition should always be waited upon in a loop, testing the state predicate that is being waited for. An implementation is free to remove the possibility of spurious wakeups but it is recommended that applications programmers always assume that they can occur and so always wait in a loop.

The same advice is also found for the Object.wait(...) method:

waits should always occur in loops, like this one:

synchronized (obj) {
  while (<condition does not hold>){
    obj.wait(timeout);
  }
   ... // Perform action appropriate to condition
}

**Noncompliant Code Example**
```java
synchronized (obj) {
  if (!suitableCondition()){
    obj.wait(timeout);   //the thread can wake up even if the condition is still false
  }
   ... // Perform action appropriate to condition
}


```
**Compliant Solution**
```java
synchronized (obj) {
  while (!suitableCondition()){
    obj.wait(timeout);
  }
   ... // Perform action appropriate to condition
}


*See*

CERT THI03-J. - Always invoke wait() and await() methods inside a loop
#### Rule 112: IllegalMonitorStateException should not be caught
##### Quality Category: Code Smell
According to Oracle Javadoc:

IllegalMonitorStateException is thrown when a thread has attempted to wait on an object's monitor or to notify other threads waiting on an object's monitor without owning the specified monitor.

In other words, this exception can be thrown only in case of bad design because Object.wait(...), Object.notify() and Object.notifyAll() methods should never be called on an object whose monitor is not held.

**Noncompliant Code Example**
```java
public void doSomething(){
  ...
  try {
    ...
    anObject.notify();
    ...
  } catch(IllegalMonitorStateException e) {
    ...
  }
}


```
**Compliant Solution**
```java
public void doSomething(){
  ...
  synchronized(anObject) {
    ...
    anObject.notify();
    ...
  }
}
```
#### Rule 113: JUnit assertions should not be used in "run" methods
##### Quality Category: Code Smell
JUnit assertions should not be made from the run method of a Runnable, because failed assertions result in AssertionErrors being thrown. If the error is thrown from a thread other than the one that ran the test, the thread will exit but the test won't fail.

**Noncompliant Code Example**
```java
public void run() {
  // ...
  Assert.assertEquals(expected, actual);  // Noncompliant
}
```
#### Rule 114: Class names should not shadow interfaces or superclasses
##### Quality Category: Code Smell
While it's perfectly legal to give a class the same simple name as a class in another package that it extends or interface it implements, it's confusing and could cause problems in the future.

**Noncompliant Code Example**
```java
package my.mypackage;

public class Foo implements a.b.Foo { // Noncompliant


```
**Compliant Solution**
```java
package my.mypackage;

public class FooJr implements a.b.Foo {
```
#### Rule 115: "Cloneables" should implement "clone"
##### Quality Category: Code Smell
Simply implementing Cloneable without also overriding Object.clone() does not necessarily make the class cloneable. While the Cloneable interface does not include a clone method, it is required by convention, and ensures true cloneability. Otherwise the default JVM clone will be used, which copies primitive values and object references from the source to the target. I.e. without overriding clone, any cloned instances will potentially share members with the source instance.

Removing the Cloneable implementation and providing a good copy constructor is another viable (some say preferable) way of allowing a class to be copied.

**Noncompliant Code Example**
```java
class Team implements Cloneable {  // Noncompliant
  private Person coach;
  private List<Person> players;
  public void addPlayer(Person p) {...}
  public Person getCoach() {...}
}


```
**Compliant Solution**
```java
class Team implements Cloneable {
  private Person coach;
  private List<Person> players;
  public void addPlayer(Person p) { ... }
  public Person getCoach() { ... }

  @Override
  public Object clone() {
    Team clone = (Team) super.clone();
    //...
  }
}
```
#### Rule 116: Try-with-resources should be used
##### Quality Category: Code Smell
Java 7 introduced the try-with-resources statement, which guarantees that the resource in question will be closed. Since the new syntax is closer to bullet-proof, it should be preferred over the older try/catch/finally version.

This rule checks that close-able resources are opened in a try-with-resources statement.

Note that this rule is automatically disabled when the project's sonar.java.source is lower than 7.

**Noncompliant Code Example**
```java
FileReader fr = null;
BufferedReader br = null;
try {
  fr = new FileReader(fileName);
  br = new BufferedReader(fr);
  return br.readLine();
} catch (...) {
} finally {
  if (br != null) {
    try {
      br.close();
    } catch(IOException e){...}
  }
  if (fr != null ) {
    try {
      br.close();
    } catch(IOException e){...}
  }
}


```
**Compliant Solution**
```java
try (
    FileReader fr = new FileReader(fileName);
    BufferedReader br = new BufferedReader(fr)
  ) {
  return br.readLine();
}
catch (...) {}


or

try (BufferedReader br =
        new BufferedReader(new FileReader(fileName))) { // no need to name intermediate resources if you don't want to
  return br.readLine();
}
catch (...) {}


*See*

CERT, ERR54-J. - Use a try-with-resources statement to safely handle closeable resources
#### Rule 117: "readResolve" methods should be inheritable
##### Quality Category: Code Smell
The readResolve() method allows final tweaks to the state of an object during deserialization. Non-final classes which implement readResolve(), should not set its visibility to private since it will then be unavailable to child classes.

**Noncompliant Code Example**
```java
public class Fruit implements Serializable {
  private static final long serialVersionUID = 1;

  private Object readResolve() throws ObjectStreamException  // Noncompliant
  {...}

  //...
}

public class Raspberry extends Fruit implements Serializable {  // No access to parent's readResolve() method
  //...
}


```
**Compliant Solution**
```java
public class Fruit implements Serializable {
  private static final long serialVersionUID = 1;

  protected Object readResolve() throws ObjectStreamException
  {...}

  //...
}

public class Raspberry extends Fruit implements Serializable {
  //...
}
```
#### Rule 118: "for" loop increment clauses should modify the loops' counters
##### Quality Category: Code Smell
It can be extremely confusing when a for loop's counter is incremented outside of its increment clause. In such cases, the increment should be moved to the loop's increment clause if at all possible.

**Noncompliant Code Example**
```java
for (i = 0; i < 10; j++) { // Noncompliant
  // ...
  i++;
}


```
**Compliant Solution**
```java
for (i = 0; i < 10; i++, j++) {
  // ...
}


Or

for (i = 0; i < 10; i++) {
  // ...
  j++;
}
```
#### Rule 119: Fields in a "Serializable" class should either be transient or serializable
##### Quality Category: Code Smell
Fields in a Serializable class must themselves be either Serializable or transient even if the class is never explicitly serialized or deserialized. For instance, under load, most J2EE application frameworks flush objects to disk, and an allegedly Serializable object with non-transient, non-serializable data members could cause program crashes, and open the door to attackers. In general a Serializable class is expected to fulfil its contract and not have an unexpected behaviour when an instance is serialized.

This rule raises an issue on non-Serializable fields, and on collection fields when they are not private (because they could be assigned non-Serializable values externally), and when they are assigned non-Serializable types within the class.

**Noncompliant Code Example**
```java
public class Address {
  //...
}

public class Person implements Serializable {
  private static final long serialVersionUID = 1905122041950251207L;

  private String name;
  private Address address;  // Noncompliant; Address isn't serializable
}


```
**Compliant Solution**
```java
public class Address implements Serializable {
  private static final long serialVersionUID = 2405172041950251807L;
}

public class Person implements Serializable {
  private static final long serialVersionUID = 1905122041950251207L;

  private String name;
  private Address address;
}


```
**Exceptions**
```java

The alternative to making all members serializable or transient is to implement special methods which take on the responsibility of properly serializing and de-serializing the object. This rule ignores classes which implement the following methods:

 private void writeObject(java.io.ObjectOutputStream out)
     throws IOException
 private void readObject(java.io.ObjectInputStream in)
     throws IOException, ClassNotFoundException;


*See*

MITRE, CWE-594 - Saving Unserializable Objects to Disk
Oracle Java 6, Serializable
Oracle Java 7, Serializable

#### Rule 120: Package declaration should match source file directory
##### Quality Category: Code Smell
By convention, a Java class' physical location (source directories) and its logical representation (packages) should be kept in sync. Thus a Java file located at "src/org/bar/Foo.java" should have a package of "org.bar".

Unfortunately, this convention is not enforced by Java compilers, and nothing prevents a developer from making the "Foo.java" class part of the "com.apple" package, which could degrade the maintainability of both the class and its application.

Similarly, source placed in a folder with dots in its name instead of having the equivalent folder structure will compile but cause problems at run time. For instance, code with a package declaration of org.foo.bar that is placed in org/foo.bar will compile, but the classloader will always search for the class into the folder based on package structure, and will consequently expect sources to be in org/foo/bar folder. foo.bar is therefore not a proper folder name for sources.
#### Rule 121: Generic wildcard types should not be used in return parameters
##### Quality Category: Code Smell
It is highly recommended not to use wildcard types as return types. Because the type inference rules are fairly complex it is unlikely the user of that API will know how to use it correctly.

Let's take the example of method returning a "List<? extends Animal>". Is it possible on this list to add a Dog, a Cat, ... we simply don't know. And neither does the compiler, which is why it will not allow such a direct use. The use of wildcard types should be limited to method parameters.

This rule raises an issue when a method returns a wildcard type.

**Noncompliant Code Example**
```java
List<? extends Animal> getAnimals(){...}


```
**Compliant Solution**
```java
List<Animal> getAnimals(){...}


or

List<Dog> getAnimals(){...}
```
#### Rule 122: "switch" statements should have "default" clauses
##### Quality Category: Code Smell
The requirement for a final default clause is defensive programming. The clause should either take appropriate action, or contain a suitable comment as to why no action is taken.

**Noncompliant Code Example**
```java
switch (param) {  //missing default clause
  case 0:
    doSomething();
    break;
  case 1:
    doSomethingElse();
    break;
}

switch (param) {
  default: // default clause should be the last one
    error();
    break;
  case 0:
    doSomething();
    break;
  case 1:
    doSomethingElse();
    break;
}


```
**Compliant Solution**
```java
switch (param) {
  case 0:
    doSomething();
    break;
  case 1:
    doSomethingElse();
    break;
  default:
    error();
    break;
}


```
**Exceptions**
```java

If the switch parameter is an Enum and if all the constants of this enum are used in the case statements, then no default clause is expected.

Example:

public enum Day {
    SUNDAY, MONDAY
}
...
switch(day) {
  case SUNDAY:
    doSomething();
    break;
  case MONDAY:
    doSomethingElse();
    break;
}


*See*

 MISRA C:2004, 15.0 - The MISRA C switch syntax shall be used.
 MISRA C:2004, 15.3 - The final clause of a switch statement shall be the default clause
 MISRA C++:2008, 6-4-3 - A switch statement shall be a well-formed switch statement.
 MISRA C++:2008, 6-4-6 - The final clause of a switch statement shall be the default-clause
 MISRA C:2012, 16.1 - All switch statements shall be well-formed
 MISRA C:2012, 16.4 - Every switch statement shall have a default label
 MISRA C:2012, 16.5 - A default label shall appear as either the first or the last switch label of a switch statement
MITRE, CWE-478 - Missing Default Case in Switch Statement
CERT, MSC01-C. - Strive for logical completeness

#### Rule 123: Execution of the Garbage Collector should be triggered only by the JVM
##### Quality Category: Code Smell
Calling System.gc() or Runtime.getRuntime().gc() is a bad idea for a simple reason: there is no way to know exactly what will be done under the hood by the JVM because the behavior will depend on its vendor, version and options:

 Will the whole application be frozen during the call?
 Is the -XX:DisableExplicitGC option activated?
 Will the JVM simply ignore the call?
 ...

An application relying on these unpredictable methods is also unpredictable and therefore broken. The task of running the garbage collector should be left exclusively to the JVM.
#### Rule 124: Constants should not be defined in interfaces
##### Quality Category: Code Smell
According to Joshua Bloch, author of "Effective Java":

The constant interface pattern is a poor use of interfaces.

That a class uses some constants internally is an implementation detail.

Implementing a constant interface causes this implementation detail to leak into the class's exported API. It is of no consequence to the users of a class that the class implements a constant interface. In fact, it may even confuse them. Worse, it represents a commitment: if in a future release the class is modified so that it no longer needs to use the constants, it still must implement the interface to ensure binary compatibility. If a nonfinal class implements a constant interface,

all of its subclasses will have their namespaces polluted by the constants in the interface.

**Noncompliant Code Example**
```java
interface Status {                      // Noncompliant
   int OPEN = 1;
   int CLOSED = 2;
}


```
**Compliant Solution**
```java
public enum Status {                    // Compliant
  OPEN,
  CLOSED;
}


or

public final class Status {             // Compliant
   public static final int OPEN = 1;
   public static final int CLOSED = 2;
}
```
#### Rule 125: String literals should not be duplicated
##### Quality Category: Code Smell
Duplicated string literals make the process of refactoring error-prone, since you must be sure to update all occurrences.

On the other hand, constants can be referenced from many places, but only need to be updated in a single place.

**Noncompliant Code Example**
```java

With the default threshold of 3:

public void run() {
  prepare("action1");                              // Noncompliant - "action1" is duplicated 3 times
  execute("action1");
  release("action1");
}

@SuppressWarning("all")                            // Compliant - annotations are excluded
private void method1() { /* ... */ }
@SuppressWarning("all")
private void method2() { /* ... */ }

public String method3(String a) {
  System.out.println("'" + a + "'");               // Compliant - literal "'" has less than 5 characters and is excluded
  return "";                                       // Compliant - literal "" has less than 5 characters and is excluded
}


```
**Compliant Solution**
```java
private static final String ACTION_1 = "action1";  // Compliant

public void run() {
  prepare(ACTION_1);                               // Compliant
  execute(ACTION_1);
  release(ACTION_1);
}


```
**Exceptions**
```java

To prevent generating some false-positives, literals having less than 5 characters are excluded.
```
#### Rule 126: Methods should not be empty
##### Quality Category: Code Smell
There are several reasons for a method not to have a method body:

 It is an unintentional omission, and should be fixed to prevent an unexpected behavior in production.
 It is not yet, or never will be, supported. In this case an UnsupportedOperationException should be thrown.
 The method is an intentionally-blank override. In this case a nested comment should explain the reason for the blank override.
**Noncompliant Code Example**
```java
public void doSomething() {
}

public void doSomethingElse() {
}


```
**Compliant Solution**
```java
@Override
public void doSomething() {
  // Do nothing because of X and Y.
}

@Override
public void doSomethingElse() {
  throw new UnsupportedOperationException();
}


```
**Exceptions**
```java

Default (no-argument) constructors are ignored when there are other constructors in the class, as are empty methods in abstract classes.

public abstract class Animal {
  void speak() {  // default implementation ignored
  }
}

```
#### Rule 127: "Object.finalize()" should remain protected (versus public) when overriding
##### Quality Category: Code Smell
The contract of the Object.finalize() method is clear: only the Garbage Collector is supposed to call this method.

Making this method public is misleading, because it implies that any caller can use it.

**Noncompliant Code Example**
```java
public class MyClass {

  @Override
  public void finalize() {    // Noncompliant
    /* ... */
  }
}


*See*

MITRE, CWE-583 - finalize() Method Declared Public
CERT, MET12-J. - Do not use finalizers
#### Rule 128: Exceptions should not be thrown in finally blocks
##### Quality Category: Code Smell
Throwing an exception from within a finally block will mask any exception which was previously thrown in the try or catch block, and the masked's exception message and stack trace will be lost.

**Noncompliant Code Example**
```java
try {
  /* some work which end up throwing an exception */
  throw new IllegalArgumentException();
} finally {
  /* clean up */
  throw new RuntimeException();       // Noncompliant; masks the IllegalArgumentException
}


```
**Compliant Solution**
```java
try {
  /* some work which end up throwing an exception */
  throw new IllegalArgumentException();
} finally {
  /* clean up */
}


*See*

CERT, ERR05-J. - Do not let checked exceptions escape from a finally block
#### Rule 129: Constant names should comply with a naming convention
##### Quality Category: Code Smell
Shared coding conventions allow teams to collaborate efficiently. This rule checks that all constant names match a provided regular expression.

**Noncompliant Code Example**
```java

With the default regular expression ^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$:

public class MyClass {
  public static final int first = 1;
}

public enum MyEnum {
  first;
}


```
**Compliant Solution**
```java
public class MyClass {
  public static final int FIRST = 1;
}

public enum MyEnum {
  FIRST;
}
```
#### Rule 130: Server-side requests should not be vulnerable to forging attacks
##### Quality Category: Vulnerability
User provided data, such as URL parameters, POST data payloads, or cookies, should always be considered untrusted and tainted. A remote server making requests to URLs based on tainted data could enable attackers to make arbitrary requests to the internal network or to the local file system.

The problem could be mitigated in any of the following ways:

 Validate the user provided data based on a whitelist and reject input not matching.
 Redesign the application to not send requests based on user provided data.
**Noncompliant Code Example**
```java
protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
  URL url = new URL(req.getParameter("url"));
  HttpURLConnection conn = (HttpURLConnection) url.openConnection(); // Noncompliant
  // ...
}


```
**Compliant Solution**
```java
protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
  URL url = new URL(req.getParameter("url"));

  // The safest way is to match the incoming URL against a whitelist
  if (!urlWhiteList.contains(url.toString()))
    throw new IOException();

  // If whitelisting is not possible, at least make sure that things like file:// and http://localhost are blocked
  InetAddress inetAddress = InetAddress.getByName(url.getHost());
  if (!url.getProtocol().startsWith("http") ||
      inetAddress.isAnyLocalAddress() ||
      inetAddress.isLoopbackAddress() ||
      inetAddress.isLinkLocalAddress())
    throw new IOException();

  HttpURLConnection conn = (HttpURLConnection) url.openConnection();
  // ...
}


*See*

OWASP Attack Category - Server Side Request Forgery
OWASP Top 10 2017 - Category A5 - Broken Access Control
MITRE, CWE-918 - Server-Side Request Forgery (SSRF)
MITRE, CWE-641 - Improper Restriction of Names for Files and Other Resources
SANS Top 25 - Risky Resource Management
#### Rule 131: TrustManagers should not blindly accept any certificates
##### Quality Category: Vulnerability
Empty implementations of the X509TrustManager interface are often created to allow connection to a host that is not signed by a root certificate authority. Such an implementation will accept any certificate, which leaves the application vulnerable to Man-in-the-middle attacks. The correct solution is to provide an appropriate trust store.

This rule raises an issue when an implementation of X509TrustManager never throws exception.

**Noncompliant Code Example**
```java
class TrustAllManager implements X509TrustManager {

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {  // Noncompliant, nothing means trust any client
    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException { // Noncompliant, this method never throws exception, it means trust any client
        LOG.log(Level.SEVERE, ERROR_MESSAGE);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return null;
    }
}


*See*

MITRE, CWE-295 - Improper Certificate Validation
 OWASP Top 10 2017 Category A6 - Security Misconfiguration
CERT, MSC61-J. - Do not use insecure or weak cryptographic algorithms
#### Rule 132: Weak SSL protocols should not be used
##### Quality Category: Vulnerability
javax.net.ssl.SSLContext.getInstance returns a SSLContext object that implements the specified secure socket protocol. However, not all protocols are created equal and some legacy ones like "SSL", have been proven to be insecure.

This rule raises an issue when an SSLContext is created with an insecure protocol (ie: a protocol different from "TLS", "DTLS", "TLSv1.2", "DTLSv1.2", "TLSv1.3", "DTLSv1.3").

The recommended value is "TLS" or "DTLS" as it will always use the latest version of the protocol. However an issue will be raised if the bytecode was compiled with JDK7 or an even older version of JDK because they are not alias for TLSv1.2 and DTLSv1.2 but for weaker protocols.

Note that calling SSLContext.getInstance(...) with "TLSv1.2" or "DTLSv1.2" doesn't prevent protocol version negotiation. For example, if a client connects with "TLSv1.1" and the server used SSLContext.getInstance("TLSv1.2"), the connection will use "TLSv1.1". It is possible to enable only specific protocol versions by calling setEnabledProtocols on SSLSocket, SSLServerSocket or SSLEngine. However this should be rarely needed as clients usually ask for the most secure protocol supported.

**Noncompliant Code Example**
```java
context = SSLContext.getInstance("SSL"); // Noncompliant


```
**Compliant Solution**
```java
context = SSLContext.getInstance("TLSv1.2");


*See*

MITRE, CWE-327 - Inadequate Encryption Strength
MITRE, CWE-326 - Use of a Broken or Risky Cryptographic Algorithm
 OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
 OWASP Top 10 2017 Category A6 - Security Misconfiguration
SANS Top 25 - Porous Defenses
Diagnosing TLS, SSL, and HTTPS
#### Rule 133: Strings and Boxed types should be compared using "equals()"
##### Quality Category: Bug
It's almost always a mistake to compare two instances of java.lang.String or boxed types like java.lang.Integer using reference equality == or !=, because it is not comparing actual value but locations in memory.

**Noncompliant Code Example**
```java
String firstName = getFirstName(); // String overrides equals
String lastName = getLastName();

if (firstName == lastName) { ... }; // Non-compliant; false even if the strings have the same value


```
**Compliant Solution**
```java
String firstName = getFirstName();
String lastName = getLastName();

if (firstName != null && firstName.equals(lastName)) { ... };


*See*

MITRE, CWE-595 - Comparison of Object References Instead of Object Contents
MITRE, CWE-597 - Use of Wrong Operator in String Comparison
CERT, EXP03-J. - Do not use the equality operators when comparing values of boxed primitives
CERT, EXP50-J. - Do not confuse abstract object equality with reference equality
#### Rule 134: InputSteam.read() implementation should not return a signed byte
##### Quality Category: Bug
According to the Java documentation, any implementation of the InputSteam.read() method is supposed to read the next byte of data from the input stream. The value byte must be an int in the range 0 to 255. If no byte is available because the end of the stream has been reached, the value -1 is returned.

But in Java, the byte primitive data type is an 8-bit signed two's complement integer. It has a minimum value of -128 and a maximum value of 127. So by contract, the implementation of an InputSteam.read() method should never directly return a byte primitive data type. A conversion into an unsigned byte must be done before by applying a bitmask.

**Noncompliant Code Example**
```java
@Override
public int read() throws IOException {
  if (pos == buffer.length()) {
    return -1;
  }
  return buffer.getByte(pos++); // Noncompliant, a signed byte value is returned
}


```
**Compliant Solution**
```java
@Override
public int read() throws IOException {
  if (pos == buffer.length()) {
    return -1;
  }
  return buffer.getByte(pos++) & 0xFF; // The 0xFF bitmask is applied
}
```
#### Rule 135: "compareTo" should not be overloaded
##### Quality Category: Bug
When implementing the Comparable<T>.compareTo method, the parameter's type has to match the type used in the Comparable declaration. When a different type is used this creates an overload instead of an override, which is unlikely to be the intent.

This rule raises an issue when the parameter of the compareTo method of a class implementing Comparable<T> is not same as the one used in the Comparable declaration.

**Noncompliant Code Example**
```java
public class Foo {
  static class Bar implements Comparable<Bar> {
    public int compareTo(Bar rhs) {
      return -1;
    }
  }

  static class FooBar extends Bar {
    public int compareTo(FooBar rhs) {  // Noncompliant: Parameter should be of type Bar
      return 0;
    }
  }
}


```
**Compliant Solution**
```java
public class Foo {
  static class Bar implements Comparable<Bar> {
    public int compareTo(Bar rhs) {
      return -1;
    }
  }

  static class FooBar extends Bar {
    public int compareTo(Bar rhs) {
      return 0;
    }
  }
}
```
#### Rule 136: "iterator" should not return "this"
##### Quality Category: Bug
There are two classes in the Java standard library that deal with iterations: Iterable<T> and Iterator<T>. An Iterable<T> represents a data structure that can be the target of the "for-each loop" statement, and an Iterator<T> represents the state of an ongoing traversal. An Iterable<T> is generally expected to support multiple traversals.

An Iterator<T> that also implements Iterable<t> by returning itself as its iterator() will not support multiple traversals since its state will be carried over.

This rule raises an issue when the iterator() method of a class implementing both Iterable<T> and Iterator<t> returns this.

**Noncompliant Code Example**
```java
class FooIterator implements Iterator<Foo>, Iterable<Foo> {
  private Foo[] seq;
  private int idx = 0;

  public boolean hasNext() {
    return idx < seq.length;
  }

  public Foo next() {
    return seq[idx++];
  }

  public Iterator<Foo> iterator() {
    return this; // Noncompliant
  }
  // ...
}


```
**Compliant Solution**
```java
class FooSequence implements Iterable<Foo> {
  private Foo[] seq;

  public Iterator<Foo> iterator() {
    return new Iterator<Foo>() {
      private int idx = 0;

      public boolean hasNext() {
        return idx < seq.length;
      }

      public Foo next() {
        return seq[idx++];
      }
    };
  }
  // ...
}
```
#### Rule 137: Map values should not be replaced unconditionally
##### Quality Category: Bug
It is highly suspicious when a value is saved for a key or index and then unconditionally overwritten. Such replacements are likely in error.

**Noncompliant Code Example**
```java
letters.put("a", "Apple");
letters.put("a", "Boy");  // Noncompliant

towns[i] = "London";
towns[i] = "Chicago";  // Noncompliant
```
#### Rule 138: Week Year ("YYYY") should not be used for date formatting
##### Quality Category: Bug
Few developers are aware of the difference between Y for "Week year" and y for Year when formatting and parsing a date with SimpleDateFormat. That's likely because for most dates, Week year and Year are the same, so testing at any time other than the first or last week of the year will yield the same value for both y and Y. But in the last week of December and the first week of January, you may get unexpected results.

According to the Javadoc:

A week year is in sync with a WEEK_OF_YEAR cycle. All weeks between the first and last weeks (inclusive) have the same week year value. Therefore, the first and last days of a week year may have different calendar year values.

For example, January 1, 1998 is a Thursday. If getFirstDayOfWeek() is MONDAY and getMinimalDaysInFirstWeek() is 4 (ISO 8601 standard compatible setting), then week 1 of 1998 starts on December 29, 1997, and ends on January 4, 1998. The week year is 1998 for the last three days of calendar year 1997. If, however, getFirstDayOfWeek() is SUNDAY, then week 1 of 1998 starts on January 4, 1998, and ends on January 10, 1998; the first three days of 1998 then are part of week 53 of 1997 and their week year is 1997.

**Noncompliant Code Example**
```java
Date date = new SimpleDateFormat("yyyy/MM/dd").parse("2015/12/31");
String result = new SimpleDateFormat("YYYY/MM/dd").format(date);   //Noncompliant; yields '2016/12/31'


```
**Compliant Solution**
```java
Date date = new SimpleDateFormat("yyyy/MM/dd").parse("2015/12/31");
String result = new SimpleDateFormat("yyyy/MM/dd").format(date);   //Yields '2015/12/31' as expected


```
**Exceptions**
```java
Date date = new SimpleDateFormat("yyyy/MM/dd").parse("2015/12/31");
String result = new SimpleDateFormat("YYYY-ww").format(date);  //compliant, 'Week year' is used along with 'Week of year'. result = '2016-01'

```
#### Rule 139: Exception should not be created without being thrown
##### Quality Category: Bug
Creating a new Throwable without actually throwing it is useless and is probably due to a mistake.

**Noncompliant Code Example**
```java
if (x < 0)
  new IllegalArgumentException("x must be nonnegative");


```
**Compliant Solution**
```java
if (x < 0)
  throw new IllegalArgumentException("x must be nonnegative");
```
#### Rule 140: Collection sizes and array length comparisons should make sense
##### Quality Category: Bug
The size of a collection and the length of an array are always greater than or equal to zero. So testing that a size or length is greater than or equal to zero doesn't make sense, since the result is always true. Similarly testing that it is less than zero will always return false. Perhaps the intent was to check the non-emptiness of the collection or array instead.

**Noncompliant Code Example**
```java
if (myList.size() >= 0) { ... }

if (myList.size() < 0) { ... }

boolean result = myArray.length >= 0;

if (0 > myArray.length) { ... }


```
**Compliant Solution**
```java
if (!myList.isEmpty()) { ... }

if (myArray.length >= 42) { ... }
```
#### Rule 141: Consumed Stream pipelines should not be reused
##### Quality Category: Bug
Stream operations are divided into intermediate and terminal operations, and are combined to form stream pipelines. After the terminal operation is performed, the stream pipeline is considered consumed, and cannot be used again. Such a reuse will yield unexpected results.

**Noncompliant Code Example**
```java
Stream<Widget> pipeline = widgets.stream().filter(b -> b.getColor() == RED);
int sum1 = pipeline.sum();
int sum2 = pipeline.mapToInt(b -> b.getWeight()).sum(); // Noncompliant


*See*


Stream Operations
#### Rule 142: Intermediate Stream methods should not be left unused
##### Quality Category: Bug
There are two types of stream operations: intermediate operations, which return another stream, and terminal operations, which return something other than a stream. Intermediate operations are lazy, meaning they aren't actually executed until and unless a terminal stream operation is performed on their results. Consequently if the result of an intermediate stream operation is not fed to a terminal operation, it serves no purpose, which is almost certainly an error.

**Noncompliant Code Example**
```java
widgets.stream().filter(b -> b.getColor() == RED); // Noncompliant


```
**Compliant Solution**
```java
int sum = widgets.stream()
                      .filter(b -> b.getColor() == RED)
                      .mapToInt(b -> b.getWeight())
                      .sum();
Stream<Widget> pipeline = widgets.stream()
                                 .filter(b -> b.getColor() == GREEN)
                                 .mapToInt(b -> b.getWeight());
sum = pipeline.sum();


*See*


Stream Operations
#### Rule 143: All branches in a conditional structure should not have exactly the same implementation
##### Quality Category: Bug
Having all branches in a switch or if chain with the same implementation is an error. Either a copy-paste error was made and something different should be executed, or there shouldn't be a switch/if chain at all.

**Noncompliant Code Example**
```java
if (b == 0) {  // Noncompliant
  doOneMoreThing();
} else {
  doOneMoreThing();
}

int b = a > 12 ? 4 : 4;  // Noncompliant

switch (i) {  // Noncompliant
  case 1:
    doSomething();
    break;
  case 2:
    doSomething();
    break;
  case 3:
    doSomething();
    break;
  default:
    doSomething();
}


```
**Exceptions**
```java

This rule does not apply to if chains without else-s, or to switch-es without default clauses.

if(b == 0) {    //no issue, this could have been done on purpose to make the code more readable
  doSomething();
} else if(b == 1) {
  doSomething();
}

```
#### Rule 144: Optional value should only be accessed after calling isPresent()
##### Quality Category: Bug
Optional value can hold either a value or not. The value held in the Optional can be accessed using the get() method, but it will throw a

NoSuchElementException if there is no value present. To avoid the exception, calling the isPresent() method should always be done before any call to get().

Alternatively, note that other methods such as orElse(...), orElseGet(...) or orElseThrow(...) can be used to specify what to do with an empty Optional.

**Noncompliant Code Example**
```java
Optional<String> value = this.getOptionalValue();

// ...

String stringValue = value.get(); // Noncompliant


```
**Compliant Solution**
```java
Optional<String> value = this.getOptionalValue();

// ...

if (value.isPresent()) {
  String stringValue = value.get();
}


or

Optional<String> value = this.getOptionalValue();

// ...

String stringValue = value.orElse("default");


*See*

MITRE, CWE-476 - NULL Pointer Dereference
#### Rule 145: Overrides should match their parent class methods in synchronization
##### Quality Category: Bug
When @Overrides of synchronized methods are not themselves synchronized, the result can be improper synchronization as callers rely on the thread-safety promised by the parent class.

**Noncompliant Code Example**
```java
public class Parent {

  synchronized void foo() {
    //...
  }
}

public class Child extends Parent {

 @Override
  public foo () {  // Noncompliant
    // ...
    super.foo();
  }
}


```
**Compliant Solution**
```java
public class Parent {

  synchronized void foo() {
    //...
  }
}

public class Child extends Parent {

  @Override
  synchronized foo () {
    // ...
    super.foo();
  }
}


*See*

CERT, TSM00-J - Do not override thread-safe methods with methods that are not thread-safe
#### Rule 146: "DefaultMessageListenerContainer" instances should not drop messages during restarts
##### Quality Category: Bug
DefaultMessageListenerContainer is implemented as a JMS poller. While the Spring container is shutting itself down, as each in-progress JMS Consumer.receive() call completes, any non-null return value will be a JMS message that the DMLC will discard due to the shutdown in progress. That will result in the received message never being processed.

To prevent message loss during restart operations, set acceptMessagesWhileStopping to true so that such messages will be processed before shut down.

**Noncompliant Code Example**
```java
<bean id="listenerContainer" class="org.springframework.jms.listener.DefaultMessageListenerContainer">  <!-- Noncompliant -->
   <property name="connectionFactory" ref="connFactory" />
   <property name="destination" ref="dest" />
   <property name="messageListener" ref="serviceAdapter" />
   <property name="autoStartup" value="true" />
   <property name="concurrentConsumers" value="10" />
   <property name="maxConcurrentConsumers" value="10" />
   <property name="clientId" value="myClientID" />
</bean>
 {code}


```
**Compliant Solution**
```java
<bean id="listenerContainer" class="org.springframework.jms.listener.DefaultMessageListenerContainer">
   <property name="connectionFactory" ref="connFactory" />
   <property name="destination" ref="dest" />
   <property name="messageListener" ref="serviceAdapter" />
   <property name="autoStartup" value="true" />
   <property name="concurrentConsumers" value="10" />
   <property name="maxConcurrentConsumers" value="10" />
   <property name="clientId" value="myClientID" />
   <property name="acceptMessagesWhileStopping" value="true" />
</bean>
```
#### Rule 147: "SingleConnectionFactory" instances should be set to "reconnectOnException"
##### Quality Category: Bug
Use of a Spring SingleConnectionFactory without enabling the reconnectOnException setting will prevent automatic connection recovery when the connection goes bad.

That's because the reconnectOnException property defaults to false. As a result, even if the code that uses this connection factory (Spring's DefaultMessageListenerContainer or your own code) has reconnect logic, that code won't work because the SingleConnectionFactory will act like a single-connection pool by preventing connection close calls from actually closing anything. As a result, subsequent factory create operations will just hand back the original broken Connection.

**Noncompliant Code Example**
```java
 <bean id="singleCF" class="org.springframework.jms.connection.SingleConnectionFactory">  <!-- Noncompliant -->
   <constructor-arg ref="dummyConnectionFactory" />
 </bean>


```
**Compliant Solution**
```java
 <bean id="singleCF" class="org.springframework.jms.connection.SingleConnectionFactory" p:reconnectOnException="true">
   <constructor-arg ref="dummyConnectionFactory" />
 </bean>


or

 <bean id="singleCF" class="org.springframework.jms.connection.SingleConnectionFactory">
   <constructor-arg ref="dummyConnectionFactory" />
   <property name="reconnectOnException"><value>true</value></property>
 </bean>
```
#### Rule 148: Value-based classes should not be used for locking
##### Quality Category: Bug
According to the documentation,

A program may produce unpredictable results if it attempts to distinguish two references to equal values of a value-based class, whether directly via reference equality or indirectly via an appeal to synchronization...

This is because value-based classes are intended to be wrappers for value types, which will be primitive-like collections of data (similar to structs in other languages) that will come in future versions of Java.

Instances of a value-based class ...

 do not have accessible constructors, but are instead instantiated through factory methods which make no committment as to the identity of returned instances;

Which means that you can't be sure you're the only one trying to lock on any given instance of a value-based class, opening your code up to contention and deadlock issues.

Under Java 8 breaking this rule may not actually break your code, but there are no guarantees of the behavior beyond that.

This rule raises an issue when a known value-based class is used for synchronization. That includes all the classes in the java.time package except Clock; the date classes for alternate calendars, HijrahDate, JapaneseDate, MinguoDate, ThaiBuddhistDate; and the optional classes: Optional, OptionalDouble, OptionalLong, OptionalInt.

Note that this rule is automatically disabled when the project's sonar.java.source is lower than 8.

**Noncompliant Code Example**
```java
Optional<Foo> fOpt = doSomething();
synchronized (fOpt) {  // Noncompliant
  // ...
}


*See*

Value-based classes
#### Rule 149: Expressions used in "assert" should not produce side effects
##### Quality Category: Bug
Since assert statements aren't executed by default (they must be enabled with JVM flags) developers should never rely on their execution the evaluation of any logic required for correct program function.

**Noncompliant Code Example**
```java
assert myList.remove(myList.get(0));  // Noncompliant


```
**Compliant Solution**
```java
boolean removed = myList.remove(myList.get(0));
assert removed;


*See*

CERT, EXP06-J. - Expressions used in assertions must not produce side effects
#### Rule 150: "volatile" variables should not be used with compound operators
##### Quality Category: Bug
Using compound operators as well as increments and decrements (and toggling, in the case of booleans) on primitive fields are not atomic operations. That is, they don't happen in a single step. For instance, when a volatile primitive field is incremented or decremented you run the risk of data loss if threads interleave in the steps of the update. Instead, use a guaranteed-atomic class such as AtomicInteger, or synchronize the access.

**Noncompliant Code Example**
```java
private volatile int count = 0;
private volatile boolean boo = false;

public void incrementCount() {
  count++;  // Noncompliant
}

public void toggleBoo(){
  boo = !boo;  // Noncompliant
}


```
**Compliant Solution**
```java
private AtomicInteger count = 0;
private boolean boo = false;

public void incrementCount() {
  count.incrementAndGet();
}

public synchronized void toggleBoo() {
  boo = !boo;
}


*See*

CERT, VNA02-J. - Ensure that compound operations on shared variables are atomic
#### Rule 151: "getClass" should not be used for synchronization
##### Quality Category: Bug
getClass should not be used for synchronization in non-final classes because child classes will synchronize on a different object than the parent or each other, allowing multiple threads into the code block at once, despite the synchronized keyword.

Instead, hard code the name of the class on which to synchronize or make the class final.

**Noncompliant Code Example**
```java
public class MyClass {
  public void doSomethingSynchronized(){
    synchronized (this.getClass()) {  // Noncompliant
      // ...
    }
  }


```
**Compliant Solution**
```java
public class MyClass {
  public void doSomethingSynchronized(){
    synchronized (MyClass.class) {
      // ...
    }
  }


*See*

CERT, LCK02-J. - Do not synchronize on the class object returned by getClass()
#### Rule 152: Min and max used in combination should not always return the same value
##### Quality Category: Bug
When using Math.min() and Math.max() together for bounds checking, it's important to feed the right operands to each method. Math.min() should be used with the upper end of the range being checked, and Math.max() should be used with the lower end of the range. Get it backwards, and the result will always be the same end of the range.

**Noncompliant Code Example**
```java
  private static final int UPPER = 20;
  private static final int LOWER = 0;

  public int doRangeCheck(int num) {    // Let's say num = 12
    int result = Math.min(LOWER, num);  // result = 0
    return Math.max(UPPER, result);     // Noncompliant; result is now 20: even though 12 was in the range
  }


```
**Compliant Solution**
```java

Swapping method min() and max() invocations without changing parameters.

  private static final int UPPER = 20;
  private static final int LOWER = 0;

  public int doRangeCheck(int num) {    // Let's say num = 12
    int result = Math.max(LOWER, num);  // result = 12
    return Math.min(UPPER, result);     // Compliant; result is still 12
  }


or swapping bounds UPPER and LOWER used as parameters without changing the invoked methods.

  private static final int UPPER = 20;
  private static final int LOWER = 0;

  public int doRangeCheck(int num) {    // Let's say num = 12
    int result = Math.min(UPPER, num);  // result = 12
    return Math.max(LOWER, result);     // Compliant; result is still 12
  }
```
#### Rule 153: Raw byte values should not be used in bitwise operations in combination with shifts
##### Quality Category: Bug
When reading bytes in order to build other primitive values such as ints or longs, the byte values are automatically promoted, but that promotion can have unexpected results.

For instance, the binary representation of the integer 640 is 0b0000_0010_1000_0000, which can also be written with the array of (unsigned) bytes [2, 128]. However, since Java uses two's complement, the representation of the integer in signed bytes will be [2, -128] (because the byte 0b1000_0000 is promoted to the int 0b1111_1111_1111_1111_1111_1111_1000_0000). Consequently, trying to reconstruct the initial integer by shifting and adding the values of the bytes without taking care of the sign will not produce the expected result.

To prevent such accidental value conversion, use bitwise and (&) to combine the byte value with 0xff (255) and turn all the higher bits back off.

This rule raises an issue any time a byte value is used as an operand without & 0xff, when combined with shifts.

**Noncompliant Code Example**
```java
  int intFromBuffer() {
    int result = 0;
    for (int i = 0; i < 4; i++) {
      result = (result << 8) | readByte(); // Noncompliant
    }
    return result;
  }


```
**Compliant Solution**
```java
  int intFromBuffer() {
    int result = 0;
    for (int i = 0; i < 4; i++) {
      result = (result << 8) | (readByte() & 0xff);
    }
    return result;
  }


*See*

CERT, NUM52-J. - Be aware of numeric promotion behavior
#### Rule 154: Getters and setters should be synchronized in pairs
##### Quality Category: Bug
When one part of a getter/setter pair is synchronized the other part should be too. Failure to synchronize both sides of a pair may result in inconsistent behavior at runtime as callers access an inconsistent method state.

This rule raises an issue when either the method or the contents of one method in a getter/setter pair are synchrnoized but the other is not.

**Noncompliant Code Example**
```java
public class Person {
  String name;
  int age;

  public synchronized void setName(String name) {
    this.name = name;
  }

  public String getName() {  // Noncompliant
    return this.name;
  }

  public void setAge(int age) {  // Noncompliant
    this.age = age;
  }

  public int getAge() {
    synchronized (this) {
      return this.age;
    }
  }
}


```
**Compliant Solution**
```java
public class Person {
  String name;
  int age;

  public synchronized void setName(String name) {
    this.name = name;
  }

  public synchronized String getName() {
    return this.name;
  }

  public void setAge(int age) {
    synchronized (this) {
      this.age = age;
   }
  }

  public int getAge() {
    synchronized (this) {
      return this.age;
    }
  }
}


*See*

CERT, VNA01-J. - Ensure visibility of shared references to immutable objects
#### Rule 155: Non-thread-safe fields should not be static
##### Quality Category: Bug
Not all classes in the standard Java library were written to be thread-safe. Using them in a multi-threaded manner is highly likely to cause data problems or exceptions at runtime.

This rule raises an issue when an instance of Calendar, DateFormat, javax.xml.xpath.XPath, or javax.xml.validation.SchemaFactory is marked static.

**Noncompliant Code Example**
```java
public class MyClass {
  private static SimpleDateFormat format = new SimpleDateFormat("HH-mm-ss");  // Noncompliant
  private static Calendar calendar = Calendar.getInstance();  // Noncompliant


```
**Compliant Solution**
```java
public class MyClass {
  private SimpleDateFormat format = new SimpleDateFormat("HH-mm-ss");
  private Calendar calendar = Calendar.getInstance();
```
#### Rule 156: "null" should not be used with "Optional"
##### Quality Category: Bug
The concept of Optional is that it will be used when null could cause errors. In a way, it replaces null, and when Optional is in use, there should never be a question of returning or receiving null from a call.

**Noncompliant Code Example**
```java
public void doSomething () {
  Optional<String> optional = getOptional();
  if (optional != null) {  // Noncompliant
    // do something with optional...
  }
}

@Nullable // Noncompliant
public Optional<String> getOptional() {
  // ...
  return null;  // Noncompliant
}


```
**Compliant Solution**
```java
public void doSomething () {
  Optional<String> optional = getOptional();
  optional.ifPresent(
    // do something with optional...
  );
}

public Optional<String> getOptional() {
  // ...
  return Optional.empty();
}
```
#### Rule 157: Unary prefix operators should not be repeated
##### Quality Category: Bug
The needless repetition of an operator is usually a typo. There is no reason to write !!!i when !i will do.

On the other hand, the repetition of increment and decrement operators may have been done on purpose, but doing so obfuscates the meaning, and should be simplified.

This rule raises an issue for sequences of: !, ~, -, and +.

**Noncompliant Code Example**
```java
int i = 1;

int j = - - -i;  // Noncompliant; just use -i
int k = ~~~i;    // Noncompliant; same as i
int m = + +i;    // Noncompliant; operators are useless here

boolean b = false;
boolean c = !!!b;   // Noncompliant


```
**Compliant Solution**
```java
int i =  1;

int j = -i;
int k = ~i;
int m =  i;

boolean b = false;
boolean c = !b;


```
**Exceptions**
```java

Overflow handling for GWT compilation using ~~ is ignored.
```
#### Rule 158: "=+" should not be used instead of "+="
##### Quality Category: Bug
The use of operators pairs ( =+, =- or =! ) where the reversed, single operator was meant (+=, -= or !=) will compile and run, but not produce the expected results.

This rule raises an issue when =+, =-, or =! is used without any spacing between the two operators and when there is at least one whitespace character after.

**Noncompliant Code Example**
```java
int target = -5;
int num = 3;

target =- num;  // Noncompliant; target = -3. Is that really what's meant?
target =+ num; // Noncompliant; target = 3


```
**Compliant Solution**
```java
int target = -5;
int num = 3;

target = -num;  // Compliant; intent to assign inverse value of num is clear
target += num;
```
#### Rule 159: "read" and "readLine" return values should be used
##### Quality Category: Bug
When a method is called that returns data read from some data source, that data should be stored rather than thrown away. Any other course of action is surely a bug.

This rule raises an issue when the return value of any of the following is ignored or merely null-checked: BufferedReader.readLine(), Reader.read(), and these methods in any child classes.

**Noncompliant Code Example**
```java
public void doSomethingWithFile(String fileName) {
  BufferedReader buffReader = null;
  try {
    buffReader = new BufferedReader(new FileReader(fileName));
    while (buffReader.readLine() != null) { // Noncompliant
      // ...
    }
  } catch (IOException e) {
    // ...
  }
}


```
**Compliant Solution**
```java
public void doSomethingWithFile(String fileName) {
  BufferedReader buffReader = null;
  try {
    buffReader = new BufferedReader(new FileReader(fileName));
    String line = null;
    while ((line = buffReader.readLine()) != null) {
      // ...
    }
  } catch (IOException e) {
    // ...
  }
}
```
#### Rule 160: Inappropriate regular expressions should not be used
##### Quality Category: Bug
Regular expressions are powerful but tricky, and even those long used to using them can make mistakes.

The following should not be used as regular expressions:

. - matches any single character. Used in replaceAll, it matches everything
| - normally used as an option delimiter. Used stand-alone, it matches the space between characters
File.separator - matches the platform-specific file path delimiter. On Windows, this will be taken as an escape character
**Noncompliant Code Example**
```java
String str = "/File|Name.txt";

String clean = str.replaceAll(".",""); // Noncompliant; probably meant to remove only dot chars, but returns an empty string
String clean2 = str.replaceAll("|","_"); // Noncompliant; yields _/_F_i_l_e_|_N_a_m_e_._t_x_t_
String clean3 = str.replaceAll(File.separator,""); // Noncompliant; exception on Windows

String clean4 = str.replaceFirst(".",""); // Noncompliant;
String clean5 = str.replaceFirst("|","_"); // Noncompliant;
String clean6 = str.replaceFirst(File.separator,""); // Noncompliant;
```
#### Rule 161: Conditionally executed blocks should be reachable
##### Quality Category: Bug
Conditional expressions which are always true or false can lead to dead code. Such code is always buggy and should never be used in production.

**Noncompliant Code Example**
```java
a = false;
if (a) { // Noncompliant
  doSomething(); // never executed
}

if (!a || b) { // Noncompliant; "!a" is always "true", "b" is never evaluated
  doSomething();
} else {
  doSomethingElse(); // never executed
}


```
**Exceptions**
```java

This rule will not raise an issue in either of these cases:

 When the condition is a single final boolean
final boolean debug = false;
//...
if (debug) {
  // Print something
}

 When the condition is literally true or false.
if (true) {
  // do something
}


In these cases it is obvious the code is as intended.


*See*

 MISRA C:2004, 13.7 - Boolean operations whose results are invariant shall not be permitted.
 MISRA C:2012, 14.3 - Controlling expressions shall not be invariant
MITRE, CWE-570 - Expression is Always False
MITRE, CWE-571 - Expression is Always True
CERT, MSC12-C. - Detect and remove code that has no effect or is never executed

#### Rule 162: "notifyAll" should be used
##### Quality Category: Bug
notify and notifyAll both wake up sleeping threads, but notify only rouses one, while notifyAll rouses all of them. Since notify might not wake up the right thread, notifyAll should be used instead.

**Noncompliant Code Example**
```java
class MyThread extends Thread{

  @Override
  public void run(){
    synchronized(this){
      // ...
      notify();  // Noncompliant
    }
  }
}


```
**Compliant Solution**
```java
class MyThread extends Thread{

  @Override
  public void run(){
    synchronized(this){
      // ...
      notifyAll();
    }
  }
}


*See*

CERT, THI02-J. - Notify all waiting threads rather than a single thread
#### Rule 163: Blocks should be synchronized on "private final" fields
##### Quality Category: Bug
Synchronizing on a class field synchronizes not on the field itself, but on the object assigned to it. So synchronizing on a non-final field makes it possible for the field's value to change while a thread is in a block synchronized on the old value. That would allow a second thread, synchronized on the new value, to enter the block at the same time.

The story is very similar for synchronizing on parameters; two different threads running the method in parallel could pass two different object instances in to the method as parameters, completely undermining the synchronization.

**Noncompliant Code Example**
```java
private String color = "red";

private void doSomething(){
  synchronized(color) {  // Noncompliant; lock is actually on object instance "red" referred to by the color variable
    //...
    color = "green"; // other threads now allowed into this block
    // ...
  }
  synchronized(new Object()) { // Noncompliant this is a no-op.
     // ...
  }
}


```
**Compliant Solution**
```java
private String color = "red";
private final Object lockObj = new Object();

private void doSomething(){
  synchronized(lockObj) {
    //...
    color = "green";
    // ...
  }
}


*See*

MITRE, CWE-412 - Unrestricted Externally Accessible Lock
MITRE, CWE-413 - Improper Resource Locking
CERT, LCK00-J. - Use private final lock objects to synchronize classes that may interact with untrusted code
#### Rule 164: Non-serializable objects should not be stored in "HttpSession" objects
##### Quality Category: Bug
If you have no intention of writting an HttpSession object to file, then storing non-serializable objects in it may not seem like a big deal. But whether or not you explicitly serialize the session, it may be written to disk anyway, as the server manages its memory use in a process called "passivation". Further, some servers automatically write their active sessions out to file at shutdown & deserialize any such sessions at startup.

The point is, that even though HttpSession does not extend Serializable, you must nonetheless assume that it will be serialized, and understand that if you've stored non-serializable objects in the session, errors will result.

**Noncompliant Code Example**
```java
public class Address {
  //...
}

//...
HttpSession session = request.getSession();
session.setAttribute("address", new Address());  // Noncompliant; Address isn't serializable


*See*

MITRE, CWE-579 - J2EE Bad Practices: Non-serializable Object Stored in Session
#### Rule 165: "wait", "notify" and "notifyAll" should only be called when a lock is obviously held on an object
##### Quality Category: Bug
By contract, the method Object.wait(...), Object.notify() and Object.notifyAll() should be called by a thread that is the owner of the object's monitor. If this is not the case an IllegalMonitorStateException exception is thrown. This rule reinforces this constraint by making it mandatory to call one of these methods only inside a synchronized method or statement.

**Noncompliant Code Example**
```java
private void removeElement() {
  while (!suitableCondition()){
    obj.wait();
  }
  ... // Perform removal
}


or

private void removeElement() {
  while (!suitableCondition()){
    wait();
  }
  ... // Perform removal
}


```
**Compliant Solution**
```java
private void removeElement() {
  synchronized(obj) {
    while (!suitableCondition()){
      obj.wait();
    }
    ... // Perform removal
  }
}


or

private synchronized void removeElement() {
  while (!suitableCondition()){
    wait();
  }
  ... // Perform removal
}
```
#### Rule 166: Null pointers should not be dereferenced
##### Quality Category: Bug
A reference to null should never be dereferenced/accessed. Doing so will cause a NullPointerException to be thrown. At best, such an exception will cause abrupt program termination. At worst, it could expose debugging information that would be useful to an attacker, or it could allow an attacker to bypass security measures.

Note that when they are present, this rule takes advantage of @CheckForNull and @Nonnull annotations defined in JSR-305 to understand which values are and are not nullable except when @Nonnull is used on the parameter to equals, which by contract should always work with null.

**Noncompliant Code Example**
```java
@CheckForNull
String getName(){...}

public boolean isNameEmpty() {
  return getName().length() == 0; // Noncompliant; the result of getName() could be null, but isn't null-checked
}

Connection conn = null;
Statement stmt = null;
try{
  conn = DriverManager.getConnection(DB_URL,USER,PASS);
  stmt = conn.createStatement();
  // ...

}catch(Exception e){
  e.printStackTrace();
}finally{
  stmt.close();   // Noncompliant; stmt could be null if an exception was thrown in the try{} block
  conn.close();  // Noncompliant; conn could be null if an exception was thrown
}

private void merge(@Nonnull Color firstColor, @Nonnull Color secondColor){...}

public  void append(@CheckForNull Color color) {
    merge(currentColor, color);  // Noncompliant; color should be null-checked because merge(...) doesn't accept nullable parameters
}

void paint(Color color) {
  if(color == null) {
    System.out.println("Unable to apply color " + color.toString());  // Noncompliant; NullPointerException will be thrown
    return;
  }
  ...
}


*See*

MITRE, CWE-476 - NULL Pointer Dereference
CERT, EXP34-C. - Do not dereference null pointers
CERT, EXP01-J. - Do not use a null in a case where an object is required
#### Rule 167: Loop conditions should be true at least once
##### Quality Category: Bug
If a for loop's condition is false before the first loop iteration, the loop will never be executed. Such loops are almost always bugs, particularly when the initial value and stop conditions are hard-coded.

**Noncompliant Code Example**
```java
for (int i = 10; i < 10; i++) {  // Noncompliant
  // ...
```
#### Rule 168: A "for" loop update clause should move the counter in the right direction
##### Quality Category: Bug
A for loop with a counter that moves in the wrong direction is not an infinite loop. Because of wraparound, the loop will eventually reach its stop condition, but in doing so, it will run many, many more times than anticipated, potentially causing unexpected behavior.

**Noncompliant Code Example**
```java
public void doSomething(String [] strings) {
  for (int i = 0; i < strings.length; i--) { // Noncompliant;
    String string = strings[i];  // ArrayIndexOutOfBoundsException when i reaches -1
    //...
  }


```
**Compliant Solution**
```java
public void doSomething(String [] strings) {
  for (int i = 0; i < strings.length; i++) {
    String string = strings[i];
    //...
  }


*See*

CERT, MSC54-J. - Avoid inadvertent wrapping of loop counters
#### Rule 169: Non-public methods should not be "@Transactional"
##### Quality Category: Bug
Marking a non-public method @Transactional is both useless and misleading because Spring doesn't "see" non-public methods, and so makes no provision for their proper invocation. Nor does Spring make provision for the methods invoked by the method it called.

Therefore marking a private method, for instance, @Transactional can only result in a runtime error or exception if the method is actually written to be @Transactional.

**Noncompliant Code Example**
```java
@Transactional  // Noncompliant
private void doTheThing(ArgClass arg) {
  // ...
}
```
#### Rule 170: Servlets should not have mutable instance fields
##### Quality Category: Bug
By contract, a servlet container creates one instance of each servlet and then a dedicated thread is attached to each new incoming HTTP request to process the request. So all threads share the servlet instances and by extension their instance fields. To prevent any misunderstanding and unexpected behavior at runtime, all servlet fields should then be either static and/or final, or simply removed.

With Struts 1.X, the same constraint exists on org.apache.struts.action.Action.

**Noncompliant Code Example**
```java
public class MyServlet extends HttpServlet {
  private String userName;  //As this field is shared by all users, it's obvious that this piece of information should be managed differently
  ...
}


or

public class MyAction extends Action {
  private String userName;  //Same reason
  ...
}


*See*

CERT, MSC11-J. - Do not let session information leak within a servlet
#### Rule 171: "toString()" and "clone()" methods should not return null
##### Quality Category: Bug
Calling toString() or clone() on an object should always return a string or an object. Returning null instead contravenes the method's implicit contract.

**Noncompliant Code Example**
```java
public String toString () {
  if (this.collection.isEmpty()) {
    return null; // Noncompliant
  } else {
    // ...
 {code}


```
**Compliant Solution**
```java
public String toString () {
  if (this.collection.isEmpty()) {
    return "";
  } else {
    // ...


*See*

MITRE CWE-476 - NULL Pointer Dereference
CERT, EXP01-J. - Do not use a null in a case where an object is required
#### Rule 172: ".equals()" should not be used to test the values of "Atomic" classes
##### Quality Category: Bug
AtomicInteger, and AtomicLong extend Number, but they're distinct from Integer and Long and should be handled differently. AtomicInteger and AtomicLong are designed to support lock-free, thread-safe programming on single variables. As such, an AtomicInteger will only ever be "equal" to itself. Instead, you should .get() the value and make comparisons on it.

This applies to all the atomic, seeming-primitive wrapper classes: AtomicInteger, AtomicLong, and AtomicBoolean.

**Noncompliant Code Example**
```java
AtomicInteger aInt1 = new AtomicInteger(0);
AtomicInteger aInt2 = new AtomicInteger(0);

if (aInt1.equals(aInt2)) { ... }  // Noncompliant


```
**Compliant Solution**
```java
AtomicInteger aInt1 = new AtomicInteger(0);
AtomicInteger aInt2 = new AtomicInteger(0);

if (aInt1.get() == aInt2.get()) { ... }
```
#### Rule 173: Return values from functions without side effects should not be ignored
##### Quality Category: Bug
When the call to a function doesn't have any side effects, what is the point of making the call if the results are ignored? In such case, either the function call is useless and should be dropped or the source code doesn't behave as expected.

To prevent generating any false-positives, this rule triggers an issue only on the following predefined list of immutable classes in the Java API :

java.lang.String
java.lang.Boolean
java.lang.Integer
java.lang.Double
java.lang.Float
java.lang.Byte
java.lang.Character
java.lang.Short
java.lang.StackTraceElement
java.time.DayOfWeek
java.time.Duration
java.time.Instant
java.time.LocalDate
java.time.LocalDateTime
java.time.LocalTime
java.time.Month
java.time.MonthDay
java.time.OffsetDateTime
java.time.OffsetTime
java.time.Period
java.time.Year
java.time.YearMonth
java.time.ZonedDateTime
java.math.BigInteger
java.math.BigDecimal
java.util.Optional

and also on ConcurrentMap.putIfAbsent calls ignored return value.

**Noncompliant Code Example**
```java
public void handle(String command){
  command.toLowerCase(); // Noncompliant; result of method thrown away
  ...
}


```
**Compliant Solution**
```java
public void handle(String command){
  String formattedCommand = command.toLowerCase();
  ...
}


```
**Exceptions**
```java

This rule will not raise an issue when both these conditions are met:

 The method call is in a try block with an associated catch clause.
 The method name starts with "parse", "format", "decode" or "valueOf" or the method is String.getBytes(Charset).
private boolean textIsInteger(String textToCheck) {

    try {
        Integer.parseInt(textToCheck, 10); // OK
        return true;
    } catch (NumberFormatException ignored) {
        return false;
    }
}


*See*

 MISRA C:2012, 17.7 - The value returned by a function having non-void return type shall be used
CERT, EXP12-C. - Do not ignore values returned by functions
CERT, EXP00-J. - Do not ignore values returned by methods

#### Rule 174: Child class methods named for parent class methods should be overrides
##### Quality Category: Bug
When a method in a child class has the same signature as a method in a parent class, it is assumed to be an override. However, that's not the case when:

 the parent class method is static and the child class method is not.
 the arguments or return types of the child method are in different packages than those of the parent method.
 the parent class method is private.

Typically, these things are done unintentionally; the private parent class method is overlooked, the static keyword in the parent declaration is overlooked, or the wrong class is imported in the child. But if the intent is truly for the child class method to be different, then the method should be renamed to prevent confusion.

**Noncompliant Code Example**
```java
// Parent.java
import computer.Pear;
public class Parent {

  public void doSomething(Pear p) {
    //,,,
  }

  public static void doSomethingElse() {
    //...
  }
}

// Child.java
import fruit.Pear;
public class Child extends Parent {

  public void doSomething(Pear p) {  // Noncompliant; this is not an override
    // ...
  }


  public void doSomethingElse() {  // Noncompliant; parent method is static
    //...
  }
}


```
**Compliant Solution**
```java
// Parent.java
import computer.Pear;
public class Parent {

  public void doSomething(Pear p) {
    //,,,
  }

  public static void doSomethingElse() {
    //...
  }
}

// Child.java
import computer.Pear;  // import corrected
public class Child extends Parent {

  public void doSomething(Pear p) {  // true override (see import)
    //,,,
  }

  public static void doSomethingElse() {
    //...
  }
}
```
#### Rule 175: Inappropriate "Collection" calls should not be made
##### Quality Category: Bug
A couple Collection methods can be called with arguments of an incorrect type, but doing so is pointless and likely the result of using the wrong argument. This rule will raise an issue when the type of the argument to List.contains or List.remove is unrelated to the type used for the list declaration.

**Noncompliant Code Example**
```java
List<String> list = new ArrayList<String>();
Integer integer = Integer.valueOf(1);

if (list.contains(integer)) {  // Noncompliant. Always false.
  list.remove(integer); // Noncompliant. list.add(integer) doesn't compile, so this will always return false
}


*See*

CERT, EXP04-J. - Do not pass arguments to certain Java Collections Framework methods that are a different type than the collection parameter type
#### Rule 176: Silly equality checks should not be made
##### Quality Category: Bug
Comparisons of dissimilar types will always return false. The comparison and all its dependent code can simply be removed. This includes:

 comparing an object with null
 comparing an object with an unrelated primitive (E.G. a string with an int)
 comparing unrelated classes
 comparing an unrelated class and interface
 comparing unrelated interface types
 comparing an array to a non-array
 comparing two arrays

Specifically in the case of arrays, since arrays don't override Object.equals(), calling equals on two arrays is the same as comparing their addresses. This means that array1.equals(array2) is equivalent to array1==array2.

However, some developers might expect Array.equals(Object obj) to do more than a simple memory address comparison, comparing for instance the size and content of the two arrays. Instead, the == operator or Arrays.equals(array1, array2) should always be used with arrays.

**Noncompliant Code Example**
```java
interface KitchenTool { ... };
interface Plant {...}

public class Spatula implements KitchenTool { ... }
public class Tree implements Plant { ...}
//...

Spatula spatula = new Spatula();
KitchenTool tool = spatula;
KitchenTool [] tools = {tool};

Tree tree = new Tree();
Plant plant = tree;
Tree [] trees = {tree};


if (spatula.equals(tree)) { // Noncompliant; unrelated classes
  // ...
}
else if (spatula.equals(plant)) { // Noncompliant; unrelated class and interface
  // ...
}
else if (tool.equals(plant)) { // Noncompliant; unrelated interfaces
  // ...
}
else if (tool.equals(tools)) { // Noncompliant; array & non-array
  // ...
}
else if (trees.equals(tools)) {  // Noncompliant; incompatible arrays
  // ...
}
else if (tree.equals(null)) {  // Noncompliant
  // ...
}


*See*

CERT, EXP02-J. - Do not use the Object.equals() method to compare two arrays
#### Rule 177: Dissimilar primitive wrappers should not be used with the ternary operator without explicit casting
##### Quality Category: Bug
If wrapped primitive values (e.g. Integers and Floats) are used in a ternary operator (e.g. a?b:c), both values will be unboxed and coerced to a common type, potentially leading to unexpected results. To avoid this, add an explicit cast to a compatible type.

**Noncompliant Code Example**
```java
Integer i = 123456789;
Float f = 1.0f;
Number n = condition ? i : f;  // Noncompliant; i is coerced to float. n = 1.23456792E8


```
**Compliant Solution**
```java
Integer i = 123456789;
Float f = 1.0f;
Number n = condition ? (Number) i : f;  // n = 123456789
```
#### Rule 178: "InterruptedException" should not be ignored
##### Quality Category: Bug
Interrupted
```
**Exceptions**
```java should never be ignored in the code, and simply logging the exception counts in this case as "ignoring". The throwing of the InterruptedException clears the interrupted state of the Thread, so if the exception is not handled properly the fact that the thread was interrupted will be lost. Instead, Interrupted
```
**Exceptions**
```java should either be rethrown - immediately or after cleaning up the method's state - or the thread should be re-interrupted by calling Thread.interrupt() even if this is supposed to be a single-threaded application. Any other course of action risks delaying thread shutdown and loses the information that the thread was interrupted - probably without finishing its task.

Similarly, the ThreadDeath exception should also be propagated. According to its JavaDoc:

If ThreadDeath is caught by a method, it is important that it be rethrown so that the thread actually dies.

**Noncompliant Code Example**
```java
public void run () {
  try {
    while (true) {
      // do stuff
    }
  }catch (InterruptedException e) { // Noncompliant; logging is not enough
    LOGGER.log(Level.WARN, "Interrupted!", e);
  }
}


```
**Compliant Solution**
```java
public void run () {
  try {
    while (true) {
      // do stuff
    }
  }catch (InterruptedException e) {
    LOGGER.log(Level.WARN, "Interrupted!", e);
    // Restore interrupted state...
    Thread.currentThread().interrupt();
  }
}


*See*

MITRE, CWE-391 - Unchecked Error Condition
Dealing with InterruptedException

#### Rule 179: Classes extending java.lang.Thread should override the "run" method
##### Quality Category: Bug
According to the Java API documentation:

There are two ways to create a new thread of execution. One is to declare a class to be a subclass of Thread. This subclass should override the run method of class Thread. An instance of the subclass can then be allocated and started...

The other way to create a thread is to declare a class that implements the Runnable interface. That class then implements the run method. An instance of the class can then be allocated, passed as an argument when creating Thread, and started.

By definition, extending the Thread class without overriding the run method doesn't make sense, and implies that the contract of the Thread class is not well understood.

**Noncompliant Code Example**
```java
public class MyRunner extends Thread { // Noncompliant; run method not overridden

  public void doSometing() {...}
}


```
**Exceptions**
```java

If run() is not overridden in a class extending Thread, it means that starting the thread will actually call Thread.run(). However, Thread.run() does nothing if it has not been fed with a target Runnable. The rule consequently ignore classes extending Thread if they are calling, in their constructors, the super(...) constructor with a proper Runnable target.

class MyThread extends Thread { // Compliant - calling super constructor with a Runnable
  MyThread(Runnable target) {
    super(target); // calling super constructor with a Runnable, which will be used for when Thread.run() is executed
    // ...
  }
}

```
#### Rule 180: "Double.longBitsToDouble" should not be used for "int"
##### Quality Category: Bug
Double.longBitsToDouble expects a 64-bit, long argument. Pass it a smaller value, such as an int and the mathematical conversion into a double simply won't work as anticipated because the layout of the bits will be interpreted incorrectly, as if a child were trying to use an adult's gloves.

**Noncompliant Code Example**
```java
int i = 42;
double d = Double.longBitsToDouble(i);  // Noncompliant
```
#### Rule 181: Values should not be uselessly incremented
##### Quality Category: Bug
A value that is incremented or decremented and then not stored is at best wasted code and at worst a bug.

**Noncompliant Code Example**
```java
public int pickNumber() {
  int i = 0;
  int j = 0;

  i = i++; // Noncompliant; i is still zero

  return j++; // Noncompliant; 0 returned
}


```
**Compliant Solution**
```java
public int pickNumber() {
  int i = 0;
  int j = 0;

  i++;
  return ++j;
}
```
#### Rule 182: Non-serializable classes should not be written
##### Quality Category: Bug
Nothing in a non-serializable class will be written out to file, and attempting to serialize such a class will result in an exception being thrown. Only a class that implements Serializable or one that extends such a class can successfully be serialized (or de-serialized).

**Noncompliant Code Example**
```java
public class Vegetable {  // neither implements Serializable nor extends a class that does
  //...
}

public class Menu {
  public void meal() throws IOException {
    Vegetable veg;
    //...
    FileOutputStream fout = new FileOutputStream(veg.getName());
    ObjectOutputStream oos = new ObjectOutputStream(fout);
    oos.writeObject(veg);  // Noncompliant. Nothing will be written
  }
}


```
**Compliant Solution**
```java
public class Vegetable implements Serializable {  // can now be serialized
  //...
}

public class Menu {
  public void meal() throws IOException {
    Vegetable veg;
    //...
    FileOutputStream fout = new FileOutputStream(veg.getName());
    ObjectOutputStream oos = new ObjectOutputStream(fout);
    oos.writeObject(veg);
  }
}
```
#### Rule 183: "hashCode" and "toString" should not be called on array instances
##### Quality Category: Bug
While hashCode and toString are available on arrays, they are largely useless. hashCode returns the array's "identity hash code", and toString returns nearly the same value. Neither method's output actually reflects the array's contents. Instead, you should pass the array to the relevant static Arrays method.

**Noncompliant Code Example**
```java
public static void main( String[] args )
{
    String argStr = args.toString(); // Noncompliant
    int argHash = args.hashCode(); // Noncompliant



```
**Compliant Solution**
```java
public static void main( String[] args )
{
    String argStr = Arrays.toString(args);
    int argHash = Arrays.hashCode(args);

```
#### Rule 184: Collections should not be passed as arguments to their own methods
##### Quality Category: Bug
Passing a collection as an argument to the collection's own method is either an error - some other argument was intended - or simply nonsensical code.

Further, because some methods require that the argument remain unmodified during the execution, passing a collection to itself can result in undefined behavior.

**Noncompliant Code Example**
```java
List <Object> objs = new ArrayList<Object>();
objs.add("Hello");

objs.add(objs); // Noncompliant; StackOverflowException if objs.hashCode() called
objs.addAll(objs); // Noncompliant; behavior undefined
objs.containsAll(objs); // Noncompliant; always true
objs.removeAll(objs); // Noncompliant; confusing. Use clear() instead
objs.retainAll(objs); // Noncompliant; NOOP
```
#### Rule 185: "BigDecimal(double)" should not be used
##### Quality Category: Bug
Because of floating point imprecision, you're unlikely to get the value you expect from the BigDecimal(double) constructor.

From the JavaDocs:

The results of this constructor can be somewhat unpredictable. One might assume that writing new BigDecimal(0.1) in Java creates a BigDecimal which is exactly equal to 0.1 (an unscaled value of 1, with a scale of 1), but it is actually equal to 0.1000000000000000055511151231257827021181583404541015625. This is because 0.1 cannot be represented exactly as a double (or, for that matter, as a binary fraction of any finite length). Thus, the value that is being passed in to the constructor is not exactly equal to 0.1, appearances notwithstanding.

Instead, you should use BigDecimal.valueOf, which uses a string under the covers to eliminate floating point rounding errors, or the constructor that takes a String argument.

**Noncompliant Code Example**
```java
double d = 1.1;

BigDecimal bd1 = new BigDecimal(d); // Noncompliant; see comment above
BigDecimal bd2 = new BigDecimal(1.1); // Noncompliant; same result


```
**Compliant Solution**
```java
double d = 1.1;

BigDecimal bd1 = BigDecimal.valueOf(d);
BigDecimal bd2 = new BigDecimal("1.1"); // using String constructor will result in precise value


*See*

CERT, NUM10-J. - Do not construct BigDecimal objects from floating-point literals
#### Rule 186: Invalid "Date" values should not be used
##### Quality Category: Bug
Whether the valid value ranges for Date fields start with 0 or 1 varies by field. For instance, month starts at 0, and day of month starts at 1. Enter a date value that goes past the end of the valid range, and the date will roll without error or exception. For instance, enter 12 for month, and you'll get January of the following year.

This rule checks for bad values used in conjunction with java.util.Date, java.sql.Date, and java.util.Calendar. Specifically, values outside of the valid ranges:

Field	Valid
month	0-11
date (day)	0-31
hour	0-23
minute	0-60
second	0-61

Note that this rule does not check for invalid leap years, leap seconds (second = 61), or invalid uses of the 31st day of the month.

**Noncompliant Code Example**
```java
Date d = new Date();
d.setDate(25);
d.setYear(2014);
d.setMonth(12);  // Noncompliant; rolls d into the next year

Calendar c = new GregorianCalendar(2014, 12, 25);  // Noncompliant
if (c.get(Calendar.MONTH) == 12) {  // Noncompliant; invalid comparison
  // ...
}


```
**Compliant Solution**
```java
Date d = new Date();
d.setDate(25);
d.setYear(2014);
d.setMonth(11);

Calendar c = new Gregorian Calendar(2014, 11, 25);
if (c.get(Calendar.MONTH) == 11) {
  // ...
}
```
#### Rule 187: Reflection should not be used to check non-runtime annotations
##### Quality Category: Bug
The writer of an annotation can set one of three retention policies for it:

RetentionPolicy.SOURCE - these annotations are dropped during compilation, E.G. @Override, @SuppressWarnings.
RetentionPolicy.CLASS - these annotations are present in a compiled class but not loaded into the JVM at runtime. This is the default.
RetentionPolicy.RUNTIME - these annotations are present in the class file and loaded into the JVM.

Only annotations that have been given a RUNTIME retention policy will be available to reflection. Testing for annotations with any other retention policy is simply an error, since the test will always return false.

This rule checks that reflection is not used to detect annotations that do not have RUNTIME retention.

**Noncompliant Code Example**
```java
Method m = String.class.getMethod("getBytes", new Class[] {int.class,
int.class, byte[].class, int.class});
if (m.isAnnotationPresent(Override.class)) {  // Noncompliant; test will always return false, even when @Override is present in the code
```
#### Rule 188: Custom serialization method signatures should meet requirements
##### Quality Category: Bug
Writers of Serializable classes can choose to let Java's automatic mechanisms handle serialization and deserialization, or they can choose to handle it themselves by implementing specific methods. However, if the signatures of those methods are not exactly what is expected, they will be ignored and the default serialization mechanisms will kick back in.

**Noncompliant Code Example**
```java
public class Watermelon implements Serializable {
  // ...
  void writeObject(java.io.ObjectOutputStream out)// Noncompliant; not private
        throws IOException
  {...}

  private void readObject(java.io.ObjectInputStream in)
  {...}

  public void readObjectNoData()  // Noncompliant; not private
  {...}

  static Object readResolve() throws ObjectStreamException  // Noncompliant; this method may have any access modifier, may not be static

  Watermelon writeReplace() throws ObjectStreamException // Noncompliant; this method may have any access modifier, but must return Object
  {...}
}


```
**Compliant Solution**
```java
public class Watermelon implements Serializable {
  // ...
  private void writeObject(java.io.ObjectOutputStream out)
        throws IOException
  {...}

  private void readObject(java.io.ObjectInputStream in)
        throws IOException, ClassNotFoundException
  {...}

  private void readObjectNoData()
        throws ObjectStreamException
  {...}

  protected Object readResolve() throws ObjectStreamException
  {...}

  private Object writeReplace() throws ObjectStreamException
  {...}


*See*

CERT, SER01-J. - Do not deviate from the proper signatures of serialization methods
#### Rule 189: "Externalizable" classes should have no-arguments constructors
##### Quality Category: Bug
An Externalizable class is one which handles its own Serialization and deserialization. During deserialization, the first step in the process is a default instantiation using the class' no-argument constructor. Therefore an Externalizable class without a no-arg constructor cannot be deserialized.

**Noncompliant Code Example**
```java
public class Tomato implements Externalizable {  // Noncompliant; no no-arg constructor

  public Tomato (String color, int weight) { ... }
}


```
**Compliant Solution**
```java
public class Tomato implements Externalizable {

  public Tomato() { ... }
  public Tomato (String color, int weight) { ... }
}
```
#### Rule 190: Classes should not be compared by name
##### Quality Category: Bug
There is no requirement that class names be unique, only that they be unique within a package. Therefore trying to determine an object's type based on its class name is an exercise fraught with danger. One of those dangers is that a malicious user will send objects of the same name as the trusted class and thereby gain trusted access.

Instead, the instanceof operator or the Class.isAssignableFrom() method should be used to check the object's underlying type.

**Noncompliant Code Example**
```java
package computer;
class Pear extends Laptop { ... }

package food;
class Pear extends Fruit { ... }

class Store {

  public boolean hasSellByDate(Object item) {
    if ("Pear".equals(item.getClass().getSimpleName())) {  // Noncompliant
      return true;  // Results in throwing away week-old computers
    }
    return false;
  }

  public boolean isList(Class<T> valueClass) {
    if (List.class.getName().equals(valueClass.getName())) {  // Noncompliant
      return true;
    }
    return false;
  }
}


```
**Compliant Solution**
```java
class Store {

  public boolean hasSellByDate(Object item) {
    if (item instanceof food.Pear) {
      return true;
    }
    return false;
  }

  public boolean isList(Class<T> valueClass) {
    if (valueClass.isAssignableFrom(List.class)) {
      return true;
    }
    return false;
  }
}


*See*

MITRE, CWE-486 - Comparison of Classes by Name
CERT, OBJ09-J. - Compare classes and not class names
#### Rule 191: Related "if/else if" statements should not have the same condition
##### Quality Category: Bug
A chain of if/else if statements is evaluated from top to bottom. At most, only one branch will be executed: the first one with a condition that evaluates to true.

Therefore, duplicating a condition automatically leads to dead code. Usually, this is due to a copy/paste error. At best, it's simply dead code and at worst, it's a bug that is likely to induce further bugs as the code is maintained, and obviously it could lead to unexpected behavior.

**Noncompliant Code Example**
```java
if (param == 1)
  openWindow();
else if (param == 2)
  closeWindow();
else if (param == 1)  // Noncompliant
  moveWindowToTheBackground();
}


```
**Compliant Solution**
```java
if (param == 1)
  openWindow();
else if (param == 2)
  closeWindow();
else if (param == 3)
  moveWindowToTheBackground();
}



*See*

CERT, MSC12-C. - Detect and remove code that has no effect or is never executed
#### Rule 192: Synchronization should not be based on Strings or boxed primitives
##### Quality Category: Bug
Objects which are pooled and potentially reused should not be used for synchronization. If they are, it can cause unrelated threads to deadlock with unhelpful stacktraces. Specifically, String literals, and boxed primitives such as Integers should not be used as lock objects because they are pooled and reused. The story is even worse for Boolean objects, because there are only two instances of Boolean, Boolean.TRUE and Boolean.FALSE and every class that uses a Boolean will be referring to one of the two.

**Noncompliant Code Example**
```java
private static final Boolean bLock = Boolean.FALSE;
private static final Integer iLock = Integer.valueOf(0);
private static final String sLock = "LOCK";

public void doSomething() {

  synchronized(bLock) {  // Noncompliant
    // ...
  }
  synchronized(iLock) {  // Noncompliant
    // ...
  }
  synchronized(sLock) {  // Noncompliant
    // ...
  }


```
**Compliant Solution**
```java
private static final Object lock1 = new Object();
private static final Object lock2 = new Object();
private static final Object lock3 = new Object();

public void doSomething() {

  synchronized(lock1) {
    // ...
  }
  synchronized(lock2) {
    // ...
  }
  synchronized(lock3) {
    // ...
  }


*See*

CERT, LCK01-J. - Do not synchronize on objects that may be reused
#### Rule 193: "Iterator.hasNext()" should not call "Iterator.next()"
##### Quality Category: Bug
Calling Iterator.hasNext() is not supposed to have any side effects, and therefore should not change the state of the iterator. Iterator.next() advances the iterator by one item. So calling it inside Iterator.hasNext(), breaks the hasNext() contract, and will lead to unexpected behavior in production.

**Noncompliant Code Example**
```java
public class FibonacciIterator implements Iterator<Integer>{
...
@Override
public boolean hasNext() {
  if(next() != null) {
    return true;
  }
  return false;
}
...
}
```
#### Rule 194: Identical expressions should not be used on both sides of a binary operator
##### Quality Category: Bug
Using the same value on either side of a binary operator is almost always a mistake. In the case of logical operators, it is either a copy/paste error and therefore a bug, or it is simply wasted code, and should be simplified. In the case of bitwise operators and most binary mathematical operators, having the same value on both sides of an operator yields predictable results, and should be simplified.

**Noncompliant Code Example**
```java
if ( a == a ) { // always true
  doZ();
}
if ( a != a ) { // always false
  doY();
}
if ( a == b && a == b ) { // if the first one is true, the second one is too
  doX();
}
if ( a == b || a == b ) { // if the first one is true, the second one is too
  doW();
}

int j = 5 / 5; //always 1
int k = 5 - 5; //always 0

c.equals(c); //always true


```
**Exceptions**
```java
 This rule ignores *, +, and =.
 The specific case of testing a floating point value against itself is a valid test for NaN and is therefore ignored.
 Similarly, left-shifting 1 onto 1 is common in the construction of bit masks, and is ignored.
float f;
if(f != f) { //test for NaN value
  System.out.println("f is NaN");
}

int i = 1 << 1; // Compliant
int j = a << a; // Noncompliant


*See*

CERT, MSC12-C. - Detect and remove code that has no effect or is never executed
 {rule:squid:S1656} - Implements a check on =.

#### Rule 195: Loops with at most one iteration should be refactored
##### Quality Category: Bug
A loop with at most one iteration is equivalent to the use of an if statement to conditionally execute one piece of code. No developer expects to find such a use of a loop statement. If the initial intention of the author was really to conditionally execute one piece of code, an if statement should be used instead.

At worst that was not the initial intention of the author and so the body of the loop should be fixed to use the nested return, break or throw statements in a more appropriate way.

**Noncompliant Code Example**
```java
for (int i = 0; i < 10; i++) { // noncompliant, loop only executes once
  printf("i is %d", i);
  break;
}
...
for (int i = 0; i < 10; i++) { // noncompliant, loop only executes once
  if(i == x) {
    break;
  } else {
    printf("i is %d", i);
    return;
  }
}


```
**Compliant Solution**
```java
for (int i = 0; i < 10; i++) {
  printf("i is %d", i);
}
...
for (int i = 0; i < 10; i++) {
  if(i == x) {
    break;
  } else {
    printf("i is %d", i);
  }
}
```
#### Rule 196: Variables should not be self-assigned
##### Quality Category: Bug
There is no reason to re-assign a variable to itself. Either this statement is redundant and should be removed, or the re-assignment is a mistake and some other value or variable was intended for the assignment instead.

**Noncompliant Code Example**
```java
public void setName(String name) {
  name = name;
}


```
**Compliant Solution**
```java
public void setName(String name) {
  this.name = name;
}


*See*

CERT, MSC12-C. - Detect and remove code that has no effect or is never executed
#### Rule 197: "StringBuilder" and "StringBuffer" should not be instantiated with a character
##### Quality Category: Bug
Instantiating a StringBuilder or a StringBuffer with a character is misleading because most Java developers would expect the character to be the initial value of the StringBuffer.

What actually happens is that the int representation of the character is used to determine the initial size of the StringBuffer.

**Noncompliant Code Example**
```java
StringBuffer foo = new StringBuffer('x');   //equivalent to StringBuffer foo = new StringBuffer(120);


```
**Compliant Solution**
```java
StringBuffer foo = new StringBuffer("x");
```
#### Rule 198: Methods should not be named "tostring", "hashcode" or "equal"
##### Quality Category: Bug
Naming a method tostring, hashcode() or equal is either:

 A bug in the form of a typo. Overriding toString, Object.hashCode() (note the camelCasing) or Object.equals (note the 's' on the end) was meant, and the application does not behave as expected.
 Done on purpose. The name however will confuse every other developer, who may not notice the naming difference, or who will think it is a bug.

In both cases, the method should be renamed.

**Noncompliant Code Example**
```java
public int hashcode() { /* ... */ }  // Noncompliant

public String tostring() { /* ... */ } // Noncompliant

public boolean equal(Object obj) { /* ... */ }  // Noncompliant


```
**Compliant Solution**
```java
@Override
public int hashCode() { /* ... */ }

@Override
public String toString() { /* ... */ }

@Override
public boolean equals(Object obj) { /* ... */ }
```
#### Rule 199: "Thread.run()" should not be called directly
##### Quality Category: Bug
The purpose of the Thread.run() method is to execute code in a separate, dedicated thread. Calling this method directly doesn't make sense because it causes its code to be executed in the current thread.

To get the expected behavior, call the Thread.start() method instead.

**Noncompliant Code Example**
```java
Thread myThread = new Thread(runnable);
myThread.run(); // Noncompliant


```
**Compliant Solution**
```java
Thread myThread = new Thread(runnable);
myThread.start(); // Compliant


*See*

MITRE, CWE-572 - Call to Thread run() instead of start()
CERT THI00-J. - Do not invoke Thread.run()
#### Rule 200: "equals" method overrides should accept "Object" parameters
##### Quality Category: Bug
"equals" as a method name should be used exclusively to override Object.equals(Object) to prevent any confusion.

It is tempting to overload the method to take a specific class instead of Object as parameter, to save the class comparison check. However, this will not work as expected when that is the only override.

**Noncompliant Code Example**
```java
class MyClass {
  private int foo = 1;

  public boolean equals(MyClass o) {  // Noncompliant; does not override Object.equals(Object)
    return o != null && o.foo == this.foo;
  }

  public static void main(String[] args) {
    MyClass o1 = new MyClass();
    Object o2 = new MyClass();
    System.out.println(o1.equals(o2));  // Prints "false" because o2 an Object not a MyClass
  }
}

class MyClass2 {
  public boolean equals(MyClass2 o) {  // Ignored; `boolean equals(Object)` also present
    //..
  }

  public boolean equals(Object o) {
    //...
  }
}


```
**Compliant Solution**
```java
class MyClass {
  private int foo = 1;

  @Override
  public boolean equals(Object o) {
    if (this == o) {
        return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    MyClass other = (MyClass)o;
    return this.foo == other.foo;
  }

  /* ... */
}

class MyClass2 {
  public boolean equals(MyClass2 o) {
    //..
  }

  public boolean equals(Object o) {
    //...
  }
}
```
#### Rule 201: "Class.forName()" should not load JDBC 4.0+ drivers
##### Quality Category: Code Smell
In the past, it was required to load a JDBC driver before creating a java.sql.Connection. Nowadays, when using JDBC 4.0 drivers, this is no longer required and Class.forName() can be safely removed because JDBC 4.0 (JDK 6) drivers available in the classpath are automatically loaded.

This rule raises an issue when Class.forName() is used with one of the following values:

com.mysql.jdbc.Driver
oracle.jdbc.driver.OracleDriver
com.ibm.db2.jdbc.app.DB2Driver
com.ibm.db2.jdbc.net.DB2Driver
com.sybase.jdbc.SybDriver
com.sybase.jdbc2.jdbc.SybDriver
com.teradata.jdbc.TeraDriver
com.microsoft.sqlserver.jdbc.SQLServerDriver
org.postgresql.Driver
sun.jdbc.odbc.JdbcOdbcDriver
org.hsqldb.jdbc.JDBCDriver
org.h2.Driver
org.firebirdsql.jdbc.FBDriver
net.sourceforge.jtds.jdbc.Driver
**Noncompliant Code Example**
```java
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class Demo {
  private static final String DRIVER_CLASS_NAME = "org.postgresql.Driver";
  private final Connection connection;

  public Demo(String serverURI) throws SQLException, ClassNotFoundException {
    Class.forName(DRIVER_CLASS_NAME); // Noncompliant; no longer required to load the JDBC Driver using Class.forName()
    connection = DriverManager.getConnection(serverURI);
  }
}


```
**Compliant Solution**
```java
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class Demo {
    private final Connection connection;

    public Demo(String serverURI) throws SQLException {
        connection = DriverManager.getConnection(serverURI);
    }
}
```
#### Rule 202: Java 8 features should be preferred to Guava
##### Quality Category: Code Smell
Some Guava features were really useful for Java 7 application because Guava was bringing APIs missing in the JDK. Java 8 fixed these limitations. When migrating an application to Java 8 or even when starting a new one, it's recommended to prefer Java 8 APIs over Guava ones to ease its maintenance: developers don't need to learn how to use two APIs and can stick to the standard one.

This rule raises an issue when the following Guava APIs are used:

Guava API	Java 8 API
com.google.common.io.BaseEncoding#base64()	java.util.Base64
com.google.common.io.BaseEncoding#base64Url()	java.util.Base64
com.google.common.base.Joiner.on()	java.lang.String#join() or java.util.stream.Collectors#joining()
com.google.common.base.Optional#of()	java.util.Optional#of()
com.google.common.base.Optional#absent()	java.util.Optional#empty()
com.google.common.base.Optional#fromNullable()	java.util.Optional#ofNullable()
com.google.common.base.Optional	java.util.Optional
com.google.common.base.Predicate	java.util.function.Predicate
com.google.common.base.Function	java.util.function.Function
com.google.common.base.Supplier	java.util.function.Supplier
#### Rule 203: Nullness of parameters should be guaranteed
##### Quality Category: Code Smell
When using null-related annotations at global scope level, for instance using javax.annotation.ParametersAreNonnullByDefault (from JSR-305) at package level, it means that all the parameters to all the methods included in the package will, or should, be considered Non-null. It is equivalent to annotating every parameter in every method with non-null annotations (such as @Nonnull).

The rule raises an issue every time a parameter could be null for a method invocation, where the method is annotated as forbidding null parameters.

**Noncompliant Code Example**
```java
@javax.annotation.ParametersAreNonnullByDefault
class A {

  void foo() {
    bar(getValue()); // Noncompliant - method 'bar' do not expect 'null' values as parameter
  }

  void bar(Object o) { // 'o' is by contract expected never to be null
    // ...
  }

  @javax.annotation.CheckForNull
  abstract Object getValue();
}


```
**Compliant Solution**
```java

Two solutions are possible:

 The signature of the method is correct, and null check should be done prior to the call.
 The signature of the method is not coherent and should be annotated to allow null values being passed as parameter
@javax.annotation.ParametersAreNonnullByDefault
abstract class A {

  void foo() {
      Object o = getValue();
      if (o != null) {
        bar(); // Compliant - 'o' can not be null
      }
  }

  void bar(Object o) {
    // ...
  }

  @javax.annotation.CheckForNull
  abstract Object getValue();
}


or

@javax.annotation.ParametersAreNonnullByDefault
abstract class A {

  void foo() {
    bar(getValue());
  }

  void bar(@javax.annotation.Nullable Object o) { // annotation was missing
    // ...
  }

  @javax.annotation.CheckForNull
  abstract Object getValue();
}
```
#### Rule 204: "Integer.toHexString" should not be used to build hexadecimal strings
##### Quality Category: Code Smell
Using Integer.toHexString is a common mistake when converting sequences of bytes into hexadecimal string representations. The problem is that the method trims leading zeroes, which can lead to wrong conversions. For instance a two bytes value of 0x4508 would be converted into 45 and 8 which once concatenated would give 0x458.

This is particularly damaging when converting hash-codes and could lead to a security vulnerability.

This rule raises an issue when Integer.toHexString is used in any kind of string concatenations.

**Noncompliant Code Example**
```java
MessageDigest md = MessageDigest.getInstance("SHA-256");
byte[] bytes = md.digest(password.getBytes("UTF-8"));

StringBuilder sb = new StringBuilder();
for (byte b : bytes) {
    sb.append(Integer.toHexString( b & 0xFF )); // Noncompliant
}


```
**Compliant Solution**
```java
MessageDigest md = MessageDigest.getInstance("SHA-256");
byte[] bytes = md.digest(password.getBytes("UTF-8"));

StringBuilder sb = new StringBuilder();
for (byte b : bytes) {
    sb.append(String.format("%02X", b));
}


*See*

MITRE, CWE-704 - Incorrect Type Conversion or Cast
 Derived from FindSecBugs rule BAD_HEXA_CONVERSION
#### Rule 205: Asserts should not be used to check the parameters of a public method
##### Quality Category: Code Smell
An assert is inappropriate for parameter validation because assertions can be disabled at runtime in the JVM, meaning that a bad operational setting would completely eliminate the intended checks. Further, asserts that fail throw AssertionErrors, rather than throwing some type of Exception. Throwing Errors is completely outside of the normal realm of expected catch/throw behavior in normal programs.

This rule raises an issue when a public method uses one or more of its parameters with asserts.

**Noncompliant Code Example**
```java
 public void setPrice(int price) {
  assert price >= 0 && price <= MAX_PRICE;
  // Set the price
 }


```
**Compliant Solution**
```java
 public void setPrice(int price) {
  if (price < 0 || price > MAX_PRICE) {
    throw new IllegalArgumentException("Invalid price: " + price);
  }
  // Set the price
 }


*See*


Programming With Assertions
#### Rule 206: Assignments should not be redundant
##### Quality Category: Code Smell
The transitive property says that if a == b and b == c, then a == c. In such cases, there's no point in assigning a to c or vice versa because they're already equivalent.

This rule raises an issue when an assignment is useless because the assigned-to variable already holds the value on all execution paths.

**Noncompliant Code Example**
```java
a = b;
c = a;
b = c; // Noncompliant: c and b are already the same


```
**Compliant Solution**
```java
a = b;
c = a;
```
#### Rule 207: Methods should not have identical implementations
##### Quality Category: Code Smell
When two methods have the same implementation, either it was a mistake - something else was intended - or the duplication was intentional, but may be confusing to maintainers. In the latter case, one implementation should invoke the other. Numerical and string literals are not taken into account.

**Noncompliant Code Example**
```java
private final static String CODE = "bounteous";

public String calculateCode() {
  doTheThing();
  return CODE;
}

public String getName() {  // Noncompliant
  doTheThing();
  return CODE;
}


```
**Compliant Solution**
```java
private final static String CODE = "bounteous";

public String getCode() {
  doTheThing();
  return CODE;
}

public String getName() {
  return getCode();
}


```
**Exceptions**
```java

Methods that are not accessors (getters and setters), with fewer than 2 statements are ignored.
```
#### Rule 208: "java.nio.Files#delete" should be preferred
##### Quality Category: Code Smell
When java.io.File#delete fails, this boolean method simply returns false with no indication of the cause. On the other hand, when java.nio.Files#delete fails, this void method returns one of a series of exception types to better indicate the cause of the failure. And since more information is generally better in a debugging situation, java.nio.Files#delete is the preferred option.

**Noncompliant Code Example**
```java
public void cleanUp(Path path) {
  File file = new File(path);
  if (!file.delete()) {  // Noncompliant
    //...
  }
}


```
**Compliant Solution**
```java
public void cleanUp(Path path) throws NoSuchFileException, DirectoryNotEmptyException, IOException{
  Files.delete(path);
}
```
#### Rule 209: Unused "private" classes should be removed
##### Quality Category: Code Smell
private classes that are never used are dead code: unnecessary, inoperative code that should be removed. Cleaning out dead code decreases the size of the maintained codebase, making it easier to understand the program and preventing bugs from being introduced.

**Noncompliant Code Example**
```java
public class Foo
{
  ...
  private class MyUnusedPrivateClass {...} // Noncompliant
}
```
#### Rule 210: "Stream.peek" should be used with caution
##### Quality Category: Code Smell
According to its JavaDocs, java.util.Stream.peek() “exists mainly to support debugging” purposes. Although this does not mean that using it for other purposes is discouraged, relying on peek() without careful consideration can lead to error-prone code such as:

 If the stream pipeline does not include a terminal operation, no elements will be consumed and the peek() action will not be invoked at all.
 As long as a stream implementation can reach the final step, it can freely optimize processing by only producing some elements or even none at all (e.g. relying on other collection methods for counting elements). Accordingly, the peek() action will be invoked for fewer elements or not at all.

This rule raises an issue for each use of peek() to be sure that it is challenged and validated by the team to be meant for production debugging/logging purposes.

**Noncompliant Code Example**
```java
Stream.of("one", "two", "three", "four")
         .filter(e -> e.length() > 3)
         .peek(e -> System.out.println("Filtered value: " + e)); // Noncompliant


*See*

Java 8 API Documentation
 4comprehension: Idiomatic Peeking with Java Stream API
 Data Geekery: 10 Subtle Mistakes When Using the Streams API
#### Rule 211: "Map.get" and value test should be replaced with single method call
##### Quality Category: Code Smell
It's a common pattern to test the result of a java.util.Map.get() against null before proceeding with adding or changing the value in the map. However the java.util.Map API offers a significantly better alternative in the form of the computeIfPresent() and computeIfAbsent() methods. Using these instead leads to cleaner and more readable code.

Note that this rule is automatically disabled when the project's sonar.java.source is not 8.

**Noncompliant Code Example**
```java
V value = map.get(key);
if (value == null) {  // Noncompliant
  value = V.createFor(key);
  if (value != null) {
    map.put(key, value);
  }
}
return value;


```
**Compliant Solution**
```java
return map.computeIfAbsent(key, k -> V.createFor(k));
```
#### Rule 212: Java 8's "Files.exists" should not be used
##### Quality Category: Code Smell
The Files.exists method has noticeably poor performance in JDK 8, and can slow an application significantly when used to check files that don't actually exist.

The same goes for Files.notExists, Files.isDirectory and Files.isRegularFile.

Note that this rule is automatically disabled when the project's sonar.java.source is not 8.

**Noncompliant Code Example**
```java
Path myPath;
if(java.nio.Files.exists(myPath)) {  // Noncompliant
 // do something
}


```
**Compliant Solution**
```java
Path myPath;
if(myPath.toFile().exists())) {
 // do something
}


*See*

https://bugs.openjdk.java.net/browse/JDK-8153414
https://bugs.openjdk.java.net/browse/JDK-8154077
#### Rule 213: "Arrays.stream" should be used for primitive arrays
##### Quality Category: Code Smell
For arrays of objects, Arrays.asList(T ... a).stream() and Arrays.stream(array) are basically equivalent in terms of performance. However, for arrays of primitives, using Arrays.asList will force the construction of a list of boxed types, and then use that list as a stream. On the other hand, Arrays.stream uses the appropriate primitive stream type (IntStream, LongStream, DoubleStream) when applicable, with much better performance.

**Noncompliant Code Example**
```java
Arrays.asList("a1", "a2", "b1", "c2", "c1").stream()
    .filter(...)
    .forEach(...);

Arrays.asList(1, 2, 3, 4).stream() // Noncompliant
    .filter(...)
    .forEach(...);


```
**Compliant Solution**
```java
Arrays.asList("a1", "a2", "b1", "c2", "c1").stream()
    .filter(...)
    .forEach(...);

int[] intArray = new int[]{1, 2, 3, 4};
Arrays.stream(intArray)
    .filter(...)
    .forEach(...);
```
#### Rule 214: Printf-style format strings should be used correctly
##### Quality Category: Code Smell
Because printf-style format strings are interpreted at runtime, rather than validated by the compiler, they can contain errors that result in the wrong strings being created. This rule statically validates the correlation of printf-style format strings to their arguments when calling the format(...) methods of java.util.Formatter, java.lang.String, java.io.PrintStream, MessageFormat, and java.io.PrintWriter classes and the printf(...) methods of java.io.PrintStream or java.io.PrintWriter classes.

**Noncompliant Code Example**
```java
String.format("First {0} and then {1}", "foo", "bar");  //Noncompliant. Looks like there is a confusion with the use of {{java.text.MessageFormat}}, parameters "foo" and "bar" will be simply ignored here
String.format("Display %3$d and then %d", 1, 2, 3);   //Noncompliant; the second argument '2' is unused
String.format("Too many arguments %d and %d", 1, 2, 3);  //Noncompliant; the third argument '3' is unused
String.format("First Line\n");   //Noncompliant; %n should be used in place of \n to produce the platform-specific line separator
String.format("Is myObject null ? %b", myObject);   //Noncompliant; when a non-boolean argument is formatted with %b, it prints true for any nonnull value, and false for null. Even if intended, this is misleading. It's better to directly inject the boolean value (myObject == null in this case)
String.format("value is " + value); // Noncompliant
String s = String.format("string without arguments"); // Noncompliant

MessageFormat.format("Result '{0}'.", value); // Noncompliant; String contains no format specifiers. (quote are discarding format specifiers)
MessageFormat.format("Result {0}.", value, value);  // Noncompliant; 2nd argument is not used
MessageFormat.format("Result {0}.", myObject.toString()); // Noncompliant; no need to call toString() on objects

java.util.Logger logger;
logger.log(java.util.logging.Level.SEVERE, "Result {0}.", myObject.toString()); // Noncompliant; no need to call toString() on objects
logger.log(java.util.logging.Level.SEVERE, "Result.", new Exception()); // compliant, parameter is an exception
logger.log(java.util.logging.Level.SEVERE, "Result '{0}'", 14); // Noncompliant {{String contains no format specifiers.}}

org.slf4j.Logger slf4jLog;
org.slf4j.Marker marker;

slf4jLog.debug(marker, "message {}");
slf4jLog.debug(marker, "message ", 1); // Noncompliant {{String contains no format specifiers.}}


```
**Compliant Solution**
```java
String.format("First %s and then %s", "foo", "bar");
String.format("Display %2$d and then %d", 1, 3);
String.format("Too many arguments %d %d", 1, 2);
String.format("First Line%n");
String.format("Is myObject null ? %b", myObject == null);
String.format("value is %d", value);
String s = "string without arguments";

MessageFormat.format("Result {0}.", value);
MessageFormat.format("Result '{0}'  =  {0}", value);
MessageFormat.format("Result {0}.", myObject);

java.util.Logger logger;
logger.log(java.util.logging.Level.SEVERE, "Result {0}.", myObject);
logger.log(java.util.logging.Level.SEVERE, "Result {0}'", 14);


org.slf4j.Logger slf4jLog;
org.slf4j.Marker marker;

slf4jLog.debug(marker, "message {}");
slf4jLog.debug(marker, "message {}", 1);


*See*

CERT, FIO47-C. - Use valid format strings
#### Rule 215: Assertion arguments should be passed in the correct order
##### Quality Category: Code Smell
The standard assertions library methods such as org.junit.Assert.assertEquals, and org.junit.Assert.assertSame expect the first argument to be the expected value and the second argument to be the actual value. Swap them, and your test will still have the same outcome (succeed/fail when it should) but the error messages will be confusing.

This rule raises an issue when the second argument to an assertions library method is a hard-coded value and the first argument is not.

**Noncompliant Code Example**
```java
org.junit.Assert.assertEquals(runner.exitCode(), 0, "Unexpected exit code");  // Noncompliant; Yields error message like: Expected:<-1>. Actual:<0>.


```
**Compliant Solution**
```java
org.junit.Assert.assertEquals(0, runner.exitCode(), "Unexpected exit code");
```
#### Rule 216: Ternary operators should not be nested
##### Quality Category: Code Smell
Just because you can do something, doesn't mean you should, and that's the case with nested ternary operations. Nesting ternary operators results in the kind of code that may seem clear as day when you write it, but six months later will leave maintainers (or worse - future you) scratching their heads and cursing.

Instead, err on the side of clarity, and use another line to express the nested operation as a separate statement.

**Noncompliant Code Example**
```java
public String getTitle(Person p) {
  return p.gender == Person.MALE ? "Mr. " : p.isMarried() ? "Mrs. " : "Miss ";  // Noncompliant
}


```
**Compliant Solution**
```java
public String getTitle(Person p) {
  if (p.gender == Person.MALE) {
    return "Mr. ";
  }
  return p.isMarried() ? "Mrs. " : "Miss ";
}
```
#### Rule 217: "writeObject" should not be the only "synchronized" code in a class
##### Quality Category: Code Smell
The purpose of synchronization is to ensure that only one thread executes a given block of code at a time. There's no real problem with marking writeObject synchronized, but it's highly suspicious if this serialization-related method is the only synchronized code in a class.

**Noncompliant Code Example**
```java
public class RubberBall {

  private Color color;
  private int diameter;

  public RubberBall(Color color, int diameter) {
    // ...
  }

  public void bounce(float angle, float velocity) {
    // ...
  }

  private synchronized void writeObject(ObjectOutputStream stream) throws IOException { // Noncompliant
    // ...
  }
}


```
**Compliant Solution**
```java
public class RubberBall {

  private Color color;
  private int diameter;

   public RubberBall(Color color, int diameter) {
    // ...
  }

  public void bounce(float angle, float velocity) {
    // ...
  }

  private void writeObject(ObjectOutputStream stream) throws IOException {
    // ...
  }
}
```
#### Rule 218: String function use should be optimized for single characters
##### Quality Category: Code Smell
An indexOf or lastIndexOf call with a single letter String can be made more performant by switching to a call with a char argument.

**Noncompliant Code Example**
```java
String myStr = "Hello World";
// ...
int pos = myStr.indexOf("W");  // Noncompliant
// ...
int otherPos = myStr.lastIndexOf("r"); // Noncompliant
// ...


```
**Compliant Solution**
```java
String myStr = "Hello World";
// ...
int pos = myStr.indexOf('W');
// ...
int otherPos = myStr.lastIndexOf('r');
// ...
```
#### Rule 219: Static fields should not be updated in constructors
##### Quality Category: Code Smell
Assigning a value to a static field in a constructor could cause unreliable behavior at runtime since it will change the value for all instances of the class.

Instead remove the field's static modifier, or initialize it statically.

**Noncompliant Code Example**
```java
public class Person {
  static Date dateOfBirth;
  static int expectedFingers;

  public Person(date birthday) {
    dateOfBirth = birthday;  // Noncompliant; now everyone has this birthday
    expectedFingers = 10;  // Noncompliant
  }
}


```
**Compliant Solution**
```java
public class Person {
  Date dateOfBirth;
  static int expectedFingers = 10;

  public Person(date birthday) {
    dateOfBirth = birthday;
  }
}
```
#### Rule 220: "Thread.sleep" should not be used in tests
##### Quality Category: Code Smell
Using Thread.sleep in a test is just generally a bad idea. It creates brittle tests that can fail unpredictably depending on environment ("Passes on my machine!") or load. Don't rely on timing (use mocks) or use libraries such as Awaitility for asynchroneous testing.

**Noncompliant Code Example**
```java
@Test
public void testDoTheThing(){

  MyClass myClass = new MyClass();
  myClass.doTheThing();

  Thread.sleep(500);  // Noncompliant
  // assertions...
}


```
**Compliant Solution**
```java
@Test
public void testDoTheThing(){

  MyClass myClass = new MyClass();
  myClass.doTheThing();

  await().atMost(2, Duration.SECONDS).until(didTheThing());  // Compliant
  // assertions...
}

private Callable<Boolean> didTheThing() {
  return new Callable<Boolean>() {
    public Boolean call() throws Exception {
      // check the condition that must be fulfilled...
    }
  };
}
```
#### Rule 221: "entrySet()" should be iterated when both the key and value are needed
##### Quality Category: Code Smell
When only the keys from a map are needed in a loop, iterating the keySet makes sense. But when both the key and the value are needed, it's more efficient to iterate the entrySet, which will give access to both the key and value, instead.

**Noncompliant Code Example**
```java
public void doSomethingWithMap(Map<String,Object> map) {
  for (String key : map.keySet()) {  // Noncompliant; for each key the value is retrieved
    Object value = map.get(key);
    // ...
  }
}


```
**Compliant Solution**
```java
public void doSomethingWithMap(Map<String,Object> map) {
  for (Map.Entry<String,Object> entry : map.entrySet()) {
    String key = entry.getKey();
    Object value = entry.getValue();
    // ...
  }
}
```
#### Rule 222: "DateUtils.truncate" from Apache Commons Lang library should not be used
##### Quality Category: Code Smell
The use of the ZonedDateTime class introduced in Java 8 to truncate a date can be significantly faster than the DateUtils class from Commons Lang.

Note that this rule is automatically disabled when the project's sonar.java.source is lower than 8.

**Noncompliant Code Example**
```java
public Date trunc(Date date) {
  return DateUtils.truncate(date, Calendar.SECOND);  // Noncompliant
}


```
**Compliant Solution**
```java
public Date trunc(Date date) {
  Instant instant = date.toInstant();
  ZonedDateTime zonedDateTime = instant.atZone(ZoneId.systemDefault());
  ZonedDateTime truncatedZonedDateTime = zonedDateTime.truncatedTo(ChronoUnit.SECONDS);
  Instant truncatedInstant = truncatedZonedDateTime.toInstant();
  return Date.from(truncatedInstant);
}
```
#### Rule 223: Multiline blocks should be enclosed in curly braces
##### Quality Category: Code Smell
Curly braces can be omitted from a one-line block, such as with an if statement or for loop, but doing so can be misleading and induce bugs.

This rule raises an issue when the whitespacing of the lines after a one line block indicates an intent to include those lines in the block, but the omission of curly braces means the lines will be unconditionally executed once.

**Noncompliant Code Example**
```java
if (condition)
  firstActionInBlock();
  secondAction();  // Noncompliant; executed unconditionally
thirdAction();

if (condition) firstActionInBlock(); secondAction();  // Noncompliant; secondAction executed unconditionally

if (condition) firstActionInBlock();  // Noncompliant
  secondAction();  // Executed unconditionally

if (condition); secondAction();  // Noncompliant; secondAction executed unconditionally

String str = null;
for (int i = 0; i < array.length; i++)
  str = array[i];
  doTheThing(str);  // Noncompliant; executed only on last array element


```
**Compliant Solution**
```java
if (condition) {
  firstActionInBlock();
  secondAction();
}
thirdAction();

String str = null;
for (int i = 0; i < array.length; i++) {
  str = array[i];
  doTheThing(str);
}


*See*

MITRE, CWE-483 - Incorrect Block Delimitation
CERT, EXP52-J. - Use braces for the body of an if, for, or while statement
#### Rule 224: "readObject" should not be "synchronized"
##### Quality Category: Code Smell
A readObject method is written when a Serializable object needs special handling to be rehydrated from file. It should be the case that the object being created by readObject is only visible to the thread that invoked the method, and the synchronized keyword is not needed, and using synchronized anyway is just confusing. If this is not the case, the method should be refactored to make it the case.

**Noncompliant Code Example**
```java
private synchronized void readObject(java.io.ObjectInputStream in)
     throws IOException, ClassNotFoundException { // Noncompliant
  //...
}


```
**Compliant Solution**
```java
private void readObject(java.io.ObjectInputStream in)
     throws IOException, ClassNotFoundException { // Compliant
  //...
}
```
#### Rule 225: "Preconditions" and logging arguments should not require evaluation
##### Quality Category: Code Smell
Passing message arguments that require further evaluation into a Guava com.google.common.base.Preconditions check can result in a performance penalty. That's because whether or not they're needed, each argument must be resolved before the method is actually called.

Similarly, passing concatenated strings into a logging method can also incur a needless performance hit because the concatenation will be performed every time the method is called, whether or not the log level is low enough to show the message.

Instead, you should structure your code to pass static or pre-computed values into Preconditions conditions check and logging calls.

Specifically, the built-in string formatting should be used instead of string concatenation, and if the message is the result of a method call, then Preconditions should be skipped altoghether, and the relevant exception should be conditionally thrown instead.

**Noncompliant Code Example**
```java
logger.log(Level.DEBUG, "Something went wrong: " + message);  // Noncompliant; string concatenation performed even when log level too high to show DEBUG messages

logger.fine("An exception occurred with message: " + message); // Noncompliant

LOG.error("Unable to open file " + csvPath, e);  // Noncompliant

Preconditions.checkState(a > 0, "Arg must be positive, but got " + a);  // Noncompliant. String concatenation performed even when a > 0

Preconditions.checkState(condition, formatMessage());  // Noncompliant. formatMessage() invoked regardless of condition

Preconditions.checkState(condition, "message: %s", formatMessage());  // Noncompliant


```
**Compliant Solution**
```java
logger.log(Level.SEVERE, "Something went wrong: {0} ", message);  // String formatting only applied if needed

logger.fine("An exception occurred with message: {}", message);  // SLF4J, Log4j

logger.log(Level.SEVERE, () -> "Something went wrong: " + message); // since Java 8, we can use Supplier , which will be evaluated lazily

LOG.error("Unable to open file {0}", csvPath, e);

if (LOG.isDebugEnabled() {
  LOG.debug("Unable to open file " + csvPath, e);  // this is compliant, because it will not evaluate if log level is above debug.
}

Preconditions.checkState(arg > 0, "Arg must be positive, but got %d", a);  // String formatting only applied if needed

if (!condition) {
  throw new IllegalStateException(formatMessage());  // formatMessage() only invoked conditionally
}

if (!condition) {
  throw new IllegalStateException("message: " + formatMessage());
}


```
**Exceptions**
```java

catch blocks are ignored, because the performance penalty is unimportant on exceptional paths (catch block should not be a part of standard program flow). Getters are ignored as well as methods called on annotations which can be considered as getters. This rule accounts for explicit test-level testing with SLF4J methods isXXXEnabled and ignores the bodies of such if statements.
```
#### Rule 226: Boolean expressions should not be gratuitous
##### Quality Category: Code Smell
If a boolean expression doesn't change the evaluation of the condition, then it is entirely unnecessary, and can be removed. If it is gratuitous because it does not match the programmer's intent, then it's a bug and the expression should be fixed.

**Noncompliant Code Example**
```java
a = true;
if (a) { // Noncompliant
  doSomething();
}

if (b && a) { // Noncompliant; "a" is always "true"
  doSomething();
}

if (c || !a) { // Noncompliant; "!a" is always "false"
  doSomething();
}


```
**Compliant Solution**
```java
a = true;
if (foo(a)) {
  doSomething();
}

if (b) {
  doSomething();
}

if (c) {
  doSomething();
}


*See*

 MISRA C:2004, 13.7 - Boolean operations whose results are invariant shall not be permitted.
 MISRA C:2012, 14.3 - Controlling expressions shall not be invariant
MITRE, CWE-571 - Expression is Always True
MITRE, CWE-570 - Expression is Always False
MITRE, CWE-489 - Leftover Debug Code
CERT, MSC12-C. - Detect and remove code that has no effect or is never executed
#### Rule 227: "Lock" objects should not be "synchronized"
##### Quality Category: Code Smell
java.util.concurrent.locks.Lock offers far more powerful and flexible locking operations than are available with synchronized blocks. So synchronizing on a Lock throws away the power of the object, and is just silly. Instead, such objects should be locked and unlocked using tryLock() and unlock().

**Noncompliant Code Example**
```java
Lock lock = new MyLockImpl();
synchronized(lock) {  // Noncompliant
  //...
}


```
**Compliant Solution**
```java
Lock lock = new MyLockImpl();
lock.tryLock();
//...


*See*

CERT, LCK03-J. - Do not synchronize on the intrinsic locks of high-level concurrency objects
#### Rule 228: Classes with only "static" methods should not be instantiated
##### Quality Category: Code Smell
static methods can be accessed without an instance of the enclosing class, so there's no reason to instantiate a class that has only static methods.

**Noncompliant Code Example**
```java
public class TextUtils {
  public static String stripHtml(String source) {
    return source.replaceAll("<[^>]+>", "");
  }
}

public class TextManipulator {

  // ...

  public void cleanText(String source) {
    TextUtils textUtils = new TextUtils(); // Noncompliant

    String stripped = textUtils.stripHtml(source);

    //...
  }
}


```
**Compliant Solution**
```java
public class TextUtils {
  public static String stripHtml(String source) {
    return source.replaceAll("<[^>]+>", "");
  }
}

public class TextManipulator {

  // ...

  public void cleanText(String source) {
    String stripped = TextUtils.stripHtml(source);

    //...
  }
}


*See*
 Also
 {rule:squid:S1118} - Utility classes should not have public constructors
#### Rule 229: "Threads" should not be used where "Runnables" are expected
##### Quality Category: Code Smell
While it is technically correct to use a Thread where a Runnable is called for, the semantics of the two objects are different, and mixing them is a bad practice that will likely lead to headaches in the future.

The crux of the issue is that Thread is a larger concept than Runnable. A Runnable is an object whose running should be managed. A Thread expects to manage the running of itself or other Runnables.

**Noncompliant Code Example**
```java
	public static void main(String[] args) {
		Thread r =new Thread() {
			int p;
			@Override
			public void run() {
				while(true)
					System.out.println("a");
			}
		};
		new Thread(r).start();  // Noncompliant


```
**Compliant Solution**
```java
	public static void main(String[] args) {
		Runnable r =new Runnable() {
			int p;
			@Override
			public void run() {
				while(true)
					System.out.println("a");
			}
		};
		new Thread(r).start();
```
#### Rule 230: Inner class calls to super class methods should be unambiguous
##### Quality Category: Code Smell
When an inner class extends another class, and both its outer class and its parent class have a method with the same name, calls to that method can be confusing. The compiler will resolve the call to the superclass method, but maintainers may be confused, so the superclass method should be called explicitly, using super..

**Noncompliant Code Example**
```java
public class Parent {
  public void foo() { ... }
}

public class Outer {

  public void foo() { ... }

  public class Inner extends Parent {

    public void doTheThing() {
      foo();  // Noncompliant; was Outer.this.foo() intended instead?
      // ...
    }
  }
}


```
**Compliant Solution**
```java
public class Parent {
  public void foo() { ... }
}

public class Outer {

  public void foo() { ... }

  public class Inner extends Parent {

    public void doTheThing() {
      super.foo();
      // ...
    }
  }
}
```
#### Rule 231: Unused type parameters should be removed
##### Quality Category: Code Smell
Type parameters that aren't used are dead code, which can only distract and possibly confuse developers during maintenance. Therefore, unused type parameters should be removed.

**Noncompliant Code Example**
```java
int <T> Add(int a, int b) // Noncompliant; <T> is ignored
{
  return a + b;
}


```
**Compliant Solution**
```java
int Add(int a, int b)
{
  return a + b;
}
```
#### Rule 232: Parameters should be passed in the correct order
##### Quality Category: Code Smell
When the names of parameters in a method call match the names of the method arguments, it contributes to clearer, more readable code. However, when the names match, but are passed in a different order than the method arguments, it indicates a mistake in the parameter order which will likely lead to unexpected results.

**Noncompliant Code Example**
```java
public double divide(int divisor, int dividend) {
  return divisor/dividend;
}

public void doTheThing() {
  int divisor = 15;
  int dividend = 5;

  double result = divide(dividend, divisor);  // Noncompliant; operation succeeds, but result is unexpected
  //...
}


```
**Compliant Solution**
```java
public double divide(int divisor, int dividend) {
  return divisor/dividend;
}

public void doTheThing() {
  int divisor = 15;
  int dividend = 5;

  double result = divide(divisor, dividend);
  //...
}
```
#### Rule 233: "ResultSet.isLast()" should not be used
##### Quality Category: Code Smell
There are several reasons to avoid ResultSet.isLast(). First, support for this method is optional for TYPE_FORWARD_ONLY result sets. Second, it can be expensive (the driver may need to fetch the next row to answer the question). Finally, the specification is not clear on what should be returned when the ResultSet is empty, so some drivers may return the opposite of what is expected.

**Noncompliant Code Example**
```java
stmt.executeQuery("SELECT name, address FROM PERSON");
ResultSet rs = stmt.getResultSet();
while (! rs.isLast()) { // Noncompliant
  // process row
}


```
**Compliant Solution**
```java
ResultSet rs = stmt.executeQuery("SELECT name, address FROM PERSON");
while (! rs.next()) {
  // process row
}
```
#### Rule 234: "static" members should be accessed statically
##### Quality Category: Code Smell
While it is possible to access static members from a class instance, it's bad form, and considered by most to be misleading because it implies to the readers of your code that there's an instance of the member per class instance.

**Noncompliant Code Example**
```java
public class A {
  public static int counter = 0;
}

public class B {
  private A first = new A();
  private A second = new A();

  public void runUpTheCount() {
    first.counter ++;  // Noncompliant
    second.counter ++;  // Noncompliant. A.counter is now 2, which is perhaps contrary to expectations
  }
}


```
**Compliant Solution**
```java
public class A {
  public static int counter = 0;
}

public class B {
  private A first = new A();
  private A second = new A();

  public void runUpTheCount() {
    A.counter ++;  // Compliant
    A.counter ++;  // Compliant
  }
}
```
#### Rule 235: Silly math should not be performed
##### Quality Category: Code Smell
Certain math operations are just silly and should not be performed because their results are predictable.

In particular, anyValue % 1 is silly because it will always return 0.

Casting a non-floating-point value to floating-point and then passing it to Math.round, Math.ceil, or Math.floor is silly because the result will always be the original value.

These operations are silly with any constant value: Math.abs, Math.ceil, Math.floor, Math.rint, Math.round.

And these oprations are silly with certain constant values:

Operation	Value
acos	0.0 or 1.0
asin	0.0 or 1.0
atan	0.0 or 1.0
atan2	0.0
cbrt	0.0 or 1.0
cos	0.0
cosh	0.0
exp	0.0 or 1.0
expm1	0.0
log	0.0 or 1.0
log10	0.0 or 1.0
sin	0.0
sinh	0.0
sqrt	0.0 or 1.0
tan	0.0
tanh	0.0
toDegrees	0.0 or 1.0
toRadians	0.0
**Noncompliant Code Example**
```java
public void doMath(int a) {
  double floor = Math.floor((double)a); // Noncompliant
  double ceiling = Math.ceil(4.2);  // Noncompliant
  double arcTan = Math.atan(0.0);  // Noncompliant
}
```
#### Rule 236: Classes named like "Exception" should extend "Exception" or a subclass
##### Quality Category: Code Smell
Clear, communicative naming is important in code. It helps maintainers and API users understand the intentions for and uses of a unit of code. Using "exception" in the name of a class that does not extend Exception or one of its subclasses is a clear violation of the expectation that a class' name will indicate what it is and/or does.

**Noncompliant Code Example**
```java
public class FruitException {  // Noncompliant; this has nothing to do with Exception
  private Fruit expected;
  private String unusualCharacteristics;
  private boolean appropriateForCommercialExploitation;
  // ...
}

public class CarException {  // Noncompliant; the extends clause was forgotten?
  public CarException(String message, Throwable cause) {
  // ...


```
**Compliant Solution**
```java
public class FruitSport {
  private Fruit expected;
  private String unusualCharacteristics;
  private boolean appropriateForCommercialExploitation;
  // ...
}

public class CarException extends Exception {
  public CarException(String message, Throwable cause) {
  // ...
```
#### Rule 237: Exceptions should be either logged or rethrown but not both
##### Quality Category: Code Smell
In applications where the accepted practice is to log an Exception and then rethrow it, you end up with miles-long logs that contain multiple instances of the same exception. In multi-threaded applications debugging this type of log can be particularly hellish because messages from other threads will be interwoven with the repetitions of the logged-and-thrown Exception. Instead, exceptions should be either logged or rethrown, not both.

**Noncompliant Code Example**
```java
catch (SQLException e) {
  ...
  LOGGER.log(Level.ERROR,  contextInfo, e);
  throw new MySQLException(contextInfo, e);
}


```
**Compliant Solution**
```java
catch (SQLException e) {
  ...
  throw new MySQLException(contextInfo, e);
}


or

catch (SQLException e) {
  ...
  LOGGER.log(Level.ERROR,  contextInfo, e);
  // handle exception...
}
```
#### Rule 238: Objects should not be created only to "getClass"
##### Quality Category: Code Smell
Creating an object for the sole purpose of calling getClass on it is a waste of memory and cycles. Instead, simply use the class' .class property.

**Noncompliant Code Example**
```java
MyObject myOb = new MyObject();  // Noncompliant
Class c = myOb.getClass();


```
**Compliant Solution**
```java
Class c = MyObject.class;
```
#### Rule 239: Primitives should not be boxed just for "String" conversion
##### Quality Category: Code Smell
"Boxing" is the process of putting a primitive value into a primitive-wrapper object. When that's done purely to use the wrapper class' toString method, it's a waste of memory and cycles because those methods are static, and can therefore be used without a class instance. Similarly, using the static method valueOf in the primitive-wrapper classes with a non-String argument should be avoided.

**Noncompliant Code Example**
```java
int myInt = 4;
String myIntString = (new Integer(myInt)).toString(); // Noncompliant; creates & discards an Integer object
myIntString = Integer.valueOf(myInt).toString(); // Noncompliant


```
**Compliant Solution**
```java
int myInt = 4;
String myIntString = Integer.toString(myInt);
```
#### Rule 240: Constructors should not be used to instantiate "String", "BigInteger", "BigDecimal" and primitive-wrapper classes
##### Quality Category: Code Smell
Constructors for String, BigInteger, BigDecimal and the objects used to wrap primitives should never be used. Doing so is less clear and uses more memory than simply using the desired value in the case of strings, and using valueOf for everything else.

**Noncompliant Code Example**
```java
String empty = new String(); // Noncompliant; yields essentially "", so just use that.
String nonempty = new String("Hello world"); // Noncompliant
Double myDouble = new Double(1.1); // Noncompliant; use valueOf
Integer integer = new Integer(1); // Noncompliant
Boolean bool = new Boolean(true); // Noncompliant
BigInteger bigInteger1 = new BigInteger("3"); // Noncompliant
BigInteger bigInteger2 = new BigInteger("9223372036854775807"); // Noncompliant
BigInteger bigInteger3 = new BigInteger("111222333444555666777888999"); // Compliant, greater than Long.MAX_VALUE


```
**Compliant Solution**
```java
String empty = "";
String nonempty = "Hello world";
Double myDouble = Double.valueOf(1.1);
Integer integer = Integer.valueOf(1);
Boolean bool = Boolean.valueOf(true);
BigInteger bigInteger1 = BigInteger.valueOf(3);
BigInteger bigInteger2 = BigInteger.valueOf(9223372036854775807L);
BigInteger bigInteger3 = new BigInteger("111222333444555666777888999");


```
**Exceptions**
```java

BigDecimal constructor with double argument is ignored as using valueOf instead might change resulting value. 
*See*
 {rule:squid:S2111}.

#### Rule 241: "URL.hashCode" and "URL.equals" should be avoided
##### Quality Category: Code Smell
The equals and hashCode methods of java.net.URL both may trigger a name service (usually DNS) lookup to resolve the host name or IP address. Depending on the configuration, and network status, that can take a long time. URI on the other hand makes no such calls and should be used instead unless the specific URL functionality is required.

In general it is better to use the URI class until access to the resource is actually needed, at which point you can just convert the URI to a URL using URI.toURL().

This rule checks for uses of URL 's in Map and Set , and for explicit calls to the equals and hashCode methods.

**Noncompliant Code Example**
```java
public void checkUrl(URL url) {
  Set<URL> sites = new HashSet<URL>();  // Noncompliant

  URL homepage = new URL("http://sonarsource.com");  // Compliant
  if (homepage.equals(url)) { // Noncompliant
    // ...
  }
}


```
**Compliant Solution**
```java
public void checkUrl(URL url) {
  Set<URI> sites = new HashSet<URI>();  // Compliant

  URI homepage = new URI("http://sonarsource.com");  // Compliant
  URI uri = url.toURI();
  if (homepage.equals(uri)) {  // Compliant
    // ...
  }
}
```
#### Rule 242: Two branches in a conditional structure should not have exactly the same implementation
##### Quality Category: Code Smell
Having two cases in a switch statement or two branches in an if chain with the same implementation is at best duplicate code, and at worst a coding error. If the same logic is truly needed for both instances, then in an if chain they should be combined, or for a switch, one should fall through to the other.

**Noncompliant Code Example**
```java
switch (i) {
  case 1:
    doFirstThing();
    doSomething();
    break;
  case 2:
    doSomethingDifferent();
    break;
  case 3:  // Noncompliant; duplicates case 1's implementation
    doFirstThing();
    doSomething();
    break;
  default:
    doTheRest();
}

if (a >= 0 && a < 10) {
  doFirstThing();
  doTheThing();
}
else if (a >= 10 && a < 20) {
  doTheOtherThing();
}
else if (a >= 20 && a < 50) {
  doFirstThing();
  doTheThing();  // Noncompliant; duplicates first condition
}
else {
  doTheRest();
}


```
**Exceptions**
```java

Blocks in an if chain that contain a single line of code are ignored, as are blocks in a switch statement that contain a single line of code with or without a following break.

if(a == 1) {
  doSomething();  //no issue, usually this is done on purpose to increase the readability
} else if (a == 2) {
  doSomethingElse();
} else {
  doSomething();
}


But this exception does not apply to if chains without else-s, or to switch-es without default clauses when all branches have the same single line of code. In case of if chains with else-s, or of switch-es with default clauses, rule {rule:squid:S3923} raises a bug.

if(a == 1) {
  doSomething();  //Noncompliant, this might have been done on purpose but probably not
} else if (a == 2) {
  doSomething();
}

```
#### Rule 243: Dead stores should be removed
##### Quality Category: Code Smell
A dead store happens when a local variable is assigned a value that is not read by any subsequent instruction. Calculating or retrieving a value only to then overwrite it or throw it away, could indicate a serious error in the code. Even if it's not an error, it is at best a waste of resources. Therefore all calculated values should be used.

**Noncompliant Code Example**
```java
i = a + b; // Noncompliant; calculation result not used before value is overwritten
i = compute();


```
**Compliant Solution**
```java
i = a + b;
i += compute();


```
**Exceptions**
```java

This rule ignores initializations to -1, 0, 1, null, true, false and "".


*See*

MITRE, CWE-563 - Assignment to Variable without Use ('Unused Variable')
CERT, MSC13-C. - Detect and remove unused values
CERT, MSC56-J. - Detect and remove superfluous code and values

#### Rule 244: "Object.wait(...)" should never be called on objects that implement "java.util.concurrent.locks.Condition"
##### Quality Category: Code Smell
From the Java API documentation:

Condition factors out the Object monitor methods (wait, notify and notifyAll) into distinct objects to give the effect of having multiple wait-sets per object, by combining them with the use of arbitrary Lock implementations. Where a Lock replaces the use of synchronized methods and statements, a Condition replaces the use of the Object monitor methods.

The purpose of implementing the Condition interface is to gain access to its more nuanced await methods. Therefore, calling the method Object.wait(...) on a class implementing the Condition interface is silly and confusing.

**Noncompliant Code Example**
```java
final Lock lock = new ReentrantLock();
final Condition notFull  = lock.newCondition();
...
notFull.wait();


```
**Compliant Solution**
```java
final Lock lock = new ReentrantLock();
final Condition notFull  = lock.newCondition();
...
notFull.await();
```
#### Rule 245: A field should not duplicate the name of its containing class
##### Quality Category: Code Smell
It's confusing to have a class member with the same name (case differences aside) as its enclosing class. This is particularly so when you consider the common practice of naming a class instance for the class itself.

Best practice dictates that any field or member with the same name as the enclosing class be renamed to be more descriptive of the particular aspect of the class it represents or holds.

**Noncompliant Code Example**
```java
public class Foo {
  private String foo;

  public String getFoo() { }
}

Foo foo = new Foo();
foo.getFoo() // what does this return?


```
**Compliant Solution**
```java
public class Foo {
  private String name;

  public String getName() { }
}

//...

Foo foo = new Foo();
foo.getName()



```
**Exceptions**
```java

When the type of the field is the containing class and that field is static, no issue is raised to allow singletons named like the type.

public class Foo {
  ...
  private static Foo foo;
  public Foo getInstance() {
    if(foo==null) {
      foo = new Foo();
    }
    return foo;
  }
  ...
}

```
#### Rule 246: Tests should not be ignored
##### Quality Category: Code Smell
When a test fails due, for example, to infrastructure issues, you might want to ignore it temporarily. But without some kind of notation about why the test is being ignored, it may never be reactivated. Such tests are difficult to address without comprehensive knowledge of the project, and end up polluting their projects.

This rule raises an issue for each ignored test that does not have a notation about why it is being skipped.

**Noncompliant Code Example**
```java
@Ignore  // Noncompliant
@Test
public void testDoTheThing() {
  // ...


```
**Compliant Solution**
```java
@Test
public void testDoTheThing() {
  // ...


```
**Exceptions**
```java

The rule doesn't raise an issue if there is a comment in the @Ignore annotation
```
#### Rule 247: Anonymous inner classes containing only one method should become lambdas
##### Quality Category: Code Smell
Before Java 8, the only way to partially support closures in Java was by using anonymous inner classes. But the syntax of anonymous classes may seem unwieldy and unclear.

With Java 8, most uses of anonymous inner classes should be replaced by lambdas to highly increase the readability of the source code.

Note that this rule is automatically disabled when the project's sonar.java.source is lower than 8.

**Noncompliant Code Example**
```java
myCollection.stream().map(new Mapper<String,String>() {
  public String map(String input) {
    return new StringBuilder(input).reverse().toString();
  }
});

Predicate<String> isEmpty = new Predicate<String> {
    boolean test(String myString) {
        return myString.isEmpty();
    }
}


```
**Compliant Solution**
```java
myCollection.stream().map(input -> new StringBuilder(input).reverse().toString());

Predicate<String> isEmpty = myString -> myString.isEmpty();
```
#### Rule 248: "switch" statements should not have too many "case" clauses
##### Quality Category: Code Smell
When switch statements have large sets of case clauses, it is usually an attempt to map two sets of data. A real map structure would be more readable and maintainable, and should be used instead.


```
**Exceptions**
```java

This rule ignores switches over Enums and empty, fall-through cases.
```
#### Rule 249: "for" loop stop conditions should be invariant
##### Quality Category: Code Smell
A for loop stop condition should test the loop counter against an invariant value (i.e. one that is true at both the beginning and ending of every loop iteration). Ideally, this means that the stop condition is set to a local variable just before the loop begins.

Stop conditions that are not invariant are slightly less efficient, as well as being difficult to understand and maintain, and likely lead to the introduction of errors in the future.

This rule tracks three types of non-invariant stop conditions:

 When the loop counters are updated in the body of the for loop
 When the stop condition depend upon a method call
 When the stop condition depends on an object property, since such properties could change during the execution of the loop.
**Noncompliant Code Example**
```java
for (int i = 0; i < 10; i++) {
  ...
  i = i - 1; // Noncompliant; counter updated in the body of the loop
  ...
}


```
**Compliant Solution**
```java
for (int i = 0; i < 10; i++) {...}


*See*

 MISRA C:2004, 13.6 - Numeric variables being used within a for loop for iteration counting shall not be modified in the body of the loop.
 MISRA C++:2008, 6-5-3 - The loop-counter shall not be modified within condition or statement.
#### Rule 250: Sections of code should not be commented out
##### Quality Category: Code Smell
Programmers should not comment out code as it bloats programs and reduces readability.

Unused code should be deleted and can be retrieved from source control history if required.


*See*

 MISRA C:2004, 2.4 - Sections of code should not be "commented out".
 MISRA C++:2008, 2-7-2 - Sections of code shall not be "commented out" using C-style comments.
 MISRA C++:2008, 2-7-3 - Sections of code should not be "commented out" using C++ comments.
 MISRA C:2012, Dir. 4.4 - Sections of code should not be "commented out"
#### Rule 251: Non-constructor methods should not have the same name as the enclosing class
##### Quality Category: Code Smell
Having a class and some of its methods sharing the same name is misleading, and leaves others to wonder whether it was done that way on purpose, or was the methods supposed to be a constructor.

**Noncompliant Code Example**
```java
public class Foo {
   public Foo() {...}
   public void Foo(String label) {...}  // Noncompliant
}


```
**Compliant Solution**
```java
public class Foo {
   public Foo() {...}
   public void foo(String label) {...}  // Compliant
}
```
#### Rule 252: Exception types should not be tested using "instanceof" in catch blocks
##### Quality Category: Code Smell
Multiple catch blocks of the appropriate type should be used instead of catching a general exception, and then testing on the type.

**Noncompliant Code Example**
```java
try {
  /* ... */
} catch (Exception e) {
  if(e instanceof IOException) { /* ... */ }         // Noncompliant
  if(e instanceof NullPointerException{ /* ... */ }  // Noncompliant
}


```
**Compliant Solution**
```java
try {
  /* ... */
} catch (IOException e) { /* ... */ }                // Compliant
} catch (NullPointerException e) { /* ... */ }       // Compliant


*See*

CERT, ERR51-J. - Prefer user-defined exceptions over more general exception types
#### Rule 253: Classes from "sun.*" packages should not be used
##### Quality Category: Code Smell
Classes in the sun.* or com.sun.* packages are considered implementation details, and are not part of the Java API.

They can cause problems when moving to new versions of Java because there is no backwards compatibility guarantee. Similarly, they can cause problems when moving to a different Java vendor, such as OpenJDK.

Such classes are almost always wrapped by Java API classes that should be used instead.

**Noncompliant Code Example**
```java
import com.sun.jna.Native;     // Noncompliant
import sun.misc.BASE64Encoder; // Noncompliant
```
#### Rule 254: Throwable and Error should not be caught
##### Quality Category: Code Smell
Throwable is the superclass of all errors and exceptions in Java. Error is the superclass of all errors, which are not meant to be caught by applications.

Catching either Throwable or Error will also catch OutOfMemoryError and InternalError, from which an application should not attempt to recover.

**Noncompliant Code Example**
```java
try { /* ... */ } catch (Throwable t) { /* ... */ }
try { /* ... */ } catch (Error e) { /* ... */ }


```
**Compliant Solution**
```java
try { /* ... */ } catch (RuntimeException e) { /* ... */ }
try { /* ... */ } catch (MyException e) { /* ... */ }


*See*

MITRE, CWE-396 - Declaration of Catch for Generic Exception
CERT, ERR08-J. - Do not catch NullPointerException or any of its ancestors
#### Rule 255: Unused method parameters should be removed
##### Quality Category: Code Smell
Unused parameters are misleading. Whatever the values passed to such parameters, the behavior will be the same.

**Noncompliant Code Example**
```java
void doSomething(int a, int b) {     // "b" is unused
  compute(a);
}


```
**Compliant Solution**
```java
void doSomething(int a) {
  compute(a);
}


```
**Exceptions**
```java

The rule will not raise issues for unused parameters:

 that are annotated with @javax.enterprise.event.Observes
 in overrides and implementation methods
 in interface default methods
 in non-private methods that only throw or that have empty bodies
 in annotated methods, unless the annotation is @SuppressWarning("unchecked") or @SuppressWarning("rawtypes"), in which case the annotation will be ignored
 in overridable methods (non-final, or not member of a final class, non-static, non-private), if the parameter is documented with a proper javadoc.
@Override
void doSomething(int a, int b) {     // no issue reported on b
  compute(a);
}

public void foo(String s) {
  // designed to be extended but noop in standard case
}

protected void bar(String s) {
  //open-closed principle
}

public void qix(String s) {
  throw new UnsupportedOperationException("This method should be implemented in subclasses");
}

/**
 * @param s This string may be use for further computation in overriding classes
 */
protected void foobar(int a, String s) { // no issue, method is overridable and unused parameter has proper javadoc
  compute(a);
}


*See*

 MISRA C++:2008, 0-1-11 - There shall be no unused parameters (named or unnamed) in nonvirtual functions.
 MISRA C:2012, 2.7 - There should be no unused parameters in functions
CERT, MSC12-C. - Detect and remove code that has no effect or is never executed

#### Rule 256: Only static class initializers should be used
##### Quality Category: Code Smell
Non-static initializers are rarely used, and can be confusing for most developers because they only run when new class instances are created. When possible, non-static initializers should be refactored into standard constructors or field initializers.

**Noncompliant Code Example**
```java
class MyClass {
  private static final Map<String, String> MY_MAP = new HashMap<String, String>() {

    // Noncompliant - HashMap should be extended only to add behavior, not for initialization
    {
      put("a", "b");
    }

  };
}


```
**Compliant Solution**
```java
class MyClass {
  private static final Map<String, String> MY_MAP = new HashMap<String, String>();

  static {
    MY_MAP.put("a", "b");
  }
}


or using Guava:

class MyClass {
  // Compliant
  private static final Map<String, String> MY_MAP = ImmutableMap.of("a", "b");
}
```
#### Rule 257: Empty arrays and collections should be returned instead of null
##### Quality Category: Code Smell
Returning null instead of an actual array or collection forces callers of the method to explicitly test for nullity, making them more complex and less readable.

Moreover, in many cases, null is used as a synonym for empty.

**Noncompliant Code Example**
```java
public static List<Result> getResults() {
  return null;                             // Noncompliant
}

public static Result[] getResults() {
  return null;                             // Noncompliant
}

public static void main(String[] args) {
  Result[] results = getResults();

  if (results != null) {                   // Nullity test required to prevent NPE
    for (Result result: results) {
      /* ... */
    }
  }
}



```
**Compliant Solution**
```java
public static List<Result> getResults() {
  return Collections.emptyList();          // Compliant
}

public static Result[] getResults() {
  return new Result[0];
}

public static void main(String[] args) {
  for (Result result: getResults()) {
    /* ... */
  }
}


*See*

CERT, MSC19-C. - For functions that return an array, prefer returning an empty array over a null value
CERT, MET55-J. - Return an empty array or collection instead of a null value for methods that return an array or collection
#### Rule 258: "@Override" should be used on overriding and implementing methods
##### Quality Category: Code Smell
Using the @Override annotation is useful for two reasons :

 It elicits a warning from the compiler if the annotated method doesn't actually override anything, as in the case of a misspelling.
 It improves the readability of the source code by making it obvious that methods are overridden.
**Noncompliant Code Example**
```java
class ParentClass {
  public boolean doSomething(){...}
}
class FirstChildClass extends ParentClass {
  public boolean doSomething(){...}  // Noncompliant
}


```
**Compliant Solution**
```java
class ParentClass {
  public boolean doSomething(){...}
}
class FirstChildClass extends ParentClass {
  @Override
  public boolean doSomething(){...}  // Compliant
}


```
**Exceptions**
```java

This rule is relaxed when overriding a method from the Object class like toString(), hashCode(), ...
```
#### Rule 259: Enumeration should not be implemented
##### Quality Category: Code Smell
From the official Oracle Javadoc:

NOTE: The functionality of this Enumeration interface is duplicated by the Iterator interface. In addition, Iterator adds an optional remove operation, and has shorter method names. New implementations should consider using Iterator in preference to Enumeration.

**Noncompliant Code Example**
```java
public class MyClass implements Enumeration {  // Non-Compliant
  /* ... */
}


```
**Compliant Solution**
```java
public class MyClass implements Iterator {     // Compliant
  /* ... */
}
```
#### Rule 260: Synchronized classes Vector, Hashtable, Stack and StringBuffer should not be used
##### Quality Category: Code Smell
Early classes of the Java API, such as Vector, Hashtable and StringBuffer, were synchronized to make them thread-safe. Unfortunately, synchronization has a big negative impact on performance, even when using these collections from a single thread.

It is better to use their new unsynchronized replacements:

ArrayList or LinkedList instead of Vector
Deque instead of Stack
HashMap instead of Hashtable
StringBuilder instead of StringBuffer
**Noncompliant Code Example**
```java
Vector cats = new Vector();


```
**Compliant Solution**
```java
ArrayList cats = new ArrayList();


```
**Exceptions**
```java

Use of those synchronized classes is ignored in the signatures of overriding methods.

@Override
public Vector getCats() {...}

```
#### Rule 261: Unused "private" methods should be removed
##### Quality Category: Code Smell
private methods that are never executed are dead code: unnecessary, inoperative code that should be removed. Cleaning out dead code decreases the size of the maintained codebase, making it easier to understand the program and preventing bugs from being introduced.

Note that this rule does not take reflection into account, which means that issues will be raised on private methods that are only accessed using the reflection API.

**Noncompliant Code Example**
```java
public class Foo implements Serializable
{
  private Foo(){}     //Compliant, private empty constructor intentionally used to prevent any direct instantiation of a class.
  public static void doSomething(){
    Foo foo = new Foo();
    ...
  }
  private void unusedPrivateMethod(){...}
  private void writeObject(ObjectOutputStream s){...}  //Compliant, relates to the java serialization mechanism
  private void readObject(ObjectInputStream in){...}  //Compliant, relates to the java serialization mechanism
}


```
**Compliant Solution**
```java
public class Foo implements Serializable
{
  private Foo(){}     //Compliant, private empty constructor intentionally used to prevent any direct instantiation of a class.
  public static void doSomething(){
    Foo foo = new Foo();
    ...
  }

  private void writeObject(ObjectOutputStream s){...}  //Compliant, relates to the java serialization mechanism

  private void readObject(ObjectInputStream in){...}  //Compliant, relates to the java serialization mechanism
}


```
**Exceptions**
```java

This rule doesn't raise any issue on annotated methods.
```
#### Rule 262: Try-catch blocks should not be nested
##### Quality Category: Code Smell
Nesting try/catch blocks severely impacts the readability of source code because it makes it too difficult to understand which block will catch which exception.
#### Rule 263: Track uses of "FIXME" tags
##### Quality Category: Code Smell
FIXME tags are commonly used to mark places where a bug is suspected, but which the developer wants to deal with later.

Sometimes the developer will not have the time or will simply forget to get back to that tag.

This rule is meant to track those tags and to ensure that they do not go unnoticed.

**Noncompliant Code Example**
```java
int divide(int numerator, int denominator) {
  return numerator / denominator;              // FIXME denominator value might be  0
}


*See*

MITRE, CWE-546 - Suspicious Comment
#### Rule 264: Deprecated elements should have both the annotation and the Javadoc tag
##### Quality Category: Code Smell
Deprecation should be marked with both the @Deprecated annotation and @deprecated Javadoc tag. The annotation enables tools such as IDEs to warn about referencing deprecated elements, and the tag can be used to explain when it was deprecated, why, and how references should be refactored.

Further, Java 9 adds two additional arguments to the annotation:

since allows you to describe when the deprecation took place
forRemoval, indicates whether the deprecated element will be removed at some future date

If your compile level is Java 9 or higher, you should be using one or both of these arguments.

**Noncompliant Code Example**
```java
class MyClass {

  @Deprecated
  public void foo1() {
  }

  /**
    * @deprecated
    */
  public void foo2() {    // Noncompliant
  }

}


```
**Compliant Solution**
```java
class MyClass {

  /**
    * @deprecated (when, why, refactoring advice...)
    */
  @Deprecated
  public void foo1() {
  }

  /**
    * Java >= 9
    * @deprecated (when, why, refactoring advice...)
    */
  @Deprecated(since="5.1")
  public void foo2() {
  }

  /**
    * Java >= 9
    * @deprecated (when, why, refactoring advice...)
    */
  @Deprecated(since="4.2", forRemoval=true)
  public void foo3() {
  }

}


```
**Exceptions**
```java

The members and methods of a deprecated class or interface are ignored by this rule. The classes and interfaces themselves are still subject to it.

/**
 * @deprecated (when, why, etc...)
 */
@Deprecated
class Qix  {

  public void foo() {} // Compliant; class is deprecated

}

/**
 * @deprecated (when, why, etc...)
 */
@Deprecated
interface Plop {

  void bar();

}

```
#### Rule 265: Assignments should not be made from within sub-expressions
##### Quality Category: Code Smell
Assignments within sub-expressions are hard to spot and therefore make the code less readable. Ideally, sub-expressions should not have side-effects.

**Noncompliant Code Example**
```java
if ((str = cont.substring(pos1, pos2)).isEmpty()) {  // Noncompliant
  //...


```
**Compliant Solution**
```java
str = cont.substring(pos1, pos2);
if (str.isEmpty()) {
  //...


```
**Exceptions**
```java

Assignments in while statement conditions, and assignments enclosed in relational expressions are ignored.

BufferedReader br = new BufferedReader(/* ... */);
String line;
while ((line = br.readLine()) != null) {...}


Chained assignments, including compound assignments, are ignored.

int i = j = 0;
int k = (j += 1);
result = (bresult = new byte[len]);


*See*

 MISRA C:2004, 13.1 - Assignment operators shall not be used in expressions that yield a Boolean value
 MISRA C++:2008, 6-2-1 - Assignment operators shall not be used in sub-expressions
 MISRA C:2012, 13.4 - The result of an assignment operator should not be used
MITRE, CWE-481 - Assigning instead of Comparing
CERT, EXP45-C. - Do not perform assignments in selection statements
CERT, EXP51-J. - Do not perform assignments in conditional expressions

#### Rule 266: Generic exceptions should never be thrown
##### Quality Category: Code Smell
Using such generic exceptions as Error, RuntimeException, Throwable, and Exception prevents calling methods from handling true, system-generated exceptions differently than application-generated errors.

**Noncompliant Code Example**
```java
public void foo(String bar) throws Throwable {  // Noncompliant
  throw new RuntimeException("My Message");     // Noncompliant
}


```
**Compliant Solution**
```java
public void foo(String bar) {
  throw new MyOwnRuntimeException("My Message");
}


```
**Exceptions**
```java

Generic exceptions in the signatures of overriding methods are ignored, because overriding method has to follow signature of the throw declaration in the superclass. The issue will be raised on superclass declaration of the method (or won't be raised at all if superclass is not part of the analysis).

@Override
public void myMethod() throws Exception {...}


Generic exceptions are also ignored in the signatures of methods that make calls to methods that throw generic exceptions.

public void myOtherMethod throws Exception {
  doTheThing();  // this method throws Exception
}


*See*

MITRE, CWE-397 - Declaration of Throws for Generic Exception
CERT, ERR07-J. - Do not throw RuntimeException, Exception, or Throwable

#### Rule 267: Utility classes should not have public constructors
##### Quality Category: Code Smell
Utility classes, which are collections of static members, are not meant to be instantiated. Even abstract utility classes, which can be extended, should not have public constructors.

Java adds an implicit public constructor to every class which does not define at least one explicitly. Hence, at least one non-public constructor should be defined.

**Noncompliant Code Example**
```java
class StringUtils { // Noncompliant

  public static String concatenate(String s1, String s2) {
    return s1 + s2;
  }

}


```
**Compliant Solution**
```java
class StringUtils { // Compliant

  private StringUtils() {
    throw new IllegalStateException("Utility class");
  }

  public static String concatenate(String s1, String s2) {
    return s1 + s2;
  }

}


```
**Exceptions**
```java

When class contains public static void main(String[] args) method it is not considered as utility class and will be ignored by this rule.
```
#### Rule 268: Local variables should not shadow class fields
##### Quality Category: Code Smell
Shadowing fields with a local variable is a bad practice that reduces code readability: it makes it confusing to know whether the field or the variable is being used.

**Noncompliant Code Example**
```java
class Foo {
  public int myField;

  public void doSomething() {
    int myField = 0;
    ...
  }
}


*See*

CERT, DCL51-J. - Do not shadow or obscure identifiers in subscopes
#### Rule 269: Redundant pairs of parentheses should be removed
##### Quality Category: Code Smell
The use of parentheses, even those not required to enforce a desired order of operations, can clarify the intent behind a piece of code. But redundant pairs of parentheses could be misleading, and should be removed.

**Noncompliant Code Example**
```java
int x = (y / 2 + 1);   //Compliant even if the parenthesis are ignored by the compiler

if (a && ((x+y > 0))) {  // Noncompliant
  //...
}

return ((x + 1));  // Noncompliant


```
**Compliant Solution**
```java
int x = (y / 2 + 1);

if (a && (x+y > 0)) {
  //...
}

return (x + 1);
```
#### Rule 270: Inheritance tree of classes should not be too deep
##### Quality Category: Code Smell
Inheritance is certainly one of the most valuable concepts in object-oriented programming. It's a way to compartmentalize and reuse code by creating collections of attributes and behaviors called classes which can be based on previously created classes. But abusing this concept by creating a deep inheritance tree can lead to very complex and unmaintainable source code. Most of the time a too deep inheritance tree is due to bad object oriented design which has led to systematically use 'inheritance' when for instance 'composition' would suit better.

This rule raises an issue when the inheritance tree, starting from Object has a greater depth than is allowed.
#### Rule 271: Nested blocks of code should not be left empty
##### Quality Category: Code Smell
Most of the time a block of code is empty when a piece of code is really missing. So such empty block must be either filled or removed.

**Noncompliant Code Example**
```java
for (int i = 0; i < 42; i++){}  // Empty on purpose or missing piece of code ?


```
**Exceptions**
```java

When a block contains a comment, this block is not considered to be empty unless it is a synchronized block. synchronized blocks are still considered empty even with comments because they can still affect program flow.
```
#### Rule 272: Methods should not have too many parameters
##### Quality Category: Code Smell
A long parameter list can indicate that a new structure should be created to wrap the numerous parameters or that the function is doing too many things.

**Noncompliant Code Example**
```java

With a maximum number of 4 parameters:

public void doSomething(int param1, int param2, int param3, String param4, long param5) {
...
}


```
**Compliant Solution**
```java
public void doSomething(int param1, int param2, int param3, String param4) {
...
}


```
**Exceptions**
```java

Methods annotated with Spring's @RequestMapping (and related shortcut annotations, like @GetRequest) or @JsonCreator may have a lot of parameters, encapsulation being possible. Such methods are therefore ignored.
```
#### Rule 273: Unused "private" fields should be removed
##### Quality Category: Code Smell
If a private field is declared but not used in the program, it can be considered dead code and should therefore be removed. This will improve maintainability because developers will not wonder what the variable is used for.

Note that this rule does not take reflection into account, which means that issues will be raised on private fields that are only accessed using the reflection API.

**Noncompliant Code Example**
```java
public class MyClass {
  private int foo = 42;

  public int compute(int a) {
    return a * 42;
  }

}


```
**Compliant Solution**
```java
public class MyClass {
  public int compute(int a) {
    return a * 42;
  }
}


```
**Exceptions**
```java

The Java serialization runtime associates with each serializable class a version number, called serialVersionUID, which is used during deserialization to verify that the sender and receiver of a serialized object have loaded classes for that object that are compatible with respect to serialization.

A serializable class can declare its own serialVersionUID explicitly by declaring a field named serialVersionUID that must be static, final, and of type long. By definition those serialVersionUID fields should not be reported by this rule:

public class MyClass implements java.io.Serializable {
  private static final long serialVersionUID = 42L;
}


Moreover, this rule doesn't raise any issue on annotated fields.
```
#### Rule 274: Collapsible "if" statements should be merged
##### Quality Category: Code Smell
Merging collapsible if statements increases the code's readability.

**Noncompliant Code Example**
```java
if (file != null) {
  if (file.isFile() || file.isDirectory()) {
    /* ... */
  }
}


```
**Compliant Solution**
```java
if (file != null && isFileOrDirectory(file)) {
  /* ... */
}

private static boolean isFileOrDirectory(File file) {
  return file.isFile() || file.isDirectory();
}
```
#### Rule 275: Unused labels should be removed
##### Quality Category: Code Smell
If a label is declared but not used in the program, it can be considered as dead code and should therefore be removed.

This will improve maintainability as developers will not wonder what this label is used for.

**Noncompliant Code Example**
```java
void foo() {
  outer: //label is not used.
  for(int i = 0; i<10; i++) {
    break;
  }
}


```
**Compliant Solution**
```java
void foo() {
  for(int i = 0; i<10; i++) {
    break;
  }
}


*See*

 MISRA C:2012, 2.6 - A function should not contain unused label declarations
CERT, MSC12-C. - Detect and remove code that has no effect or is never executed
#### Rule 276: Standard outputs should not be used directly to log anything
##### Quality Category: Code Smell
When logging a message there are several important requirements which must be fulfilled:

 The user must be able to easily retrieve the logs
 The format of all logged message must be uniform to allow the user to easily read the log
 Logged data must actually be recorded
 Sensitive data must only be logged securely

If a program directly writes to the standard outputs, there is absolutely no way to comply with those requirements. That's why defining and using a dedicated logger is highly recommended.

**Noncompliant Code Example**
```java
System.out.println("My Message");  // Noncompliant


```
**Compliant Solution**
```java
logger.log("My Message");


*See*

CERT, ERR02-J. - Prevent exceptions while logging data
#### Rule 277: Return values should not be ignored when they contain the operation status code
##### Quality Category: Vulnerability
When the return value of a function call contain the operation status code, this value should be tested to make sure the operation completed successfully.

This rule raises an issue when the return values of the following are ignored:

java.io.File operations that return a status code (except mkdirs)
Iterator.hasNext()
Enumeration.hasMoreElements()
Lock.tryLock()
 non-void Condition.await* methods
CountDownLatch.await(long, TimeUnit)
Semaphore.tryAcquire
BlockingQueue: offer, remove
**Noncompliant Code Example**
```java
public void doSomething(File file, Lock lock) {
  file.delete();  // Noncompliant
  // ...
  lock.tryLock(); // Noncompliant
}


```
**Compliant Solution**
```java
public void doSomething(File file, Lock lock) {
  if (!lock.tryLock()) {
    // lock failed; take appropriate action
  }
  if (!file.delete()) {
    // file delete failed; take appropriate action
  }
}


*See*

 MISRA C:2004, 16.10 - If a function returns error information, then that error information shall be tested
 MISRA C++:2008, 0-1-7 - The value returned by a function having a non-void return type that is not an overloaded operator shall always be used.
 MISRA C:2012, Dir. 4.7 - If a function returns error information, then that error information shall be tested
 MISRA C:2012, 17.7 - The value returned by a function having non-void return type shall be used
CERT, ERR33-C. - Detect and handle standard library errors
CERT, POS54-C. - Detect and handle POSIX library errors
CERT, EXP00-J. - Do not ignore values returned by methods
CERT, EXP12-C. - Do not ignore values returned by functions
CERT, FIO02-J. - Detect and handle file-related errors
MITRE, CWE-754 - Improper Check for Unusual Exceptional Conditions
#### Rule 278: Logging should not be vulnerable to injection attacks
##### Quality Category: Vulnerability
User provided data, such as URL parameters, POST data payloads or cookies, should always be considered untrusted and tainted. Applications logging tainted data could enable an attacker to inject characters that would break the log file pattern. This could be used to block monitors and SIEM (Security Information and Event Management) systems from detecting other malicious events.

This problem could be mitigated by sanitizing the user provided data before logging it.

**Noncompliant Code Example**
```java
protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
  String param1 = req.getParameter("param1");
  Logger.info("Param1: " + param1 + " " + Logger.getName()); // Noncompliant
  // ...
}


```
**Compliant Solution**
```java
protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
  String param1 = req.getParameter("param1");

  // Replace pattern-breaking characters
  param1 = param1.replaceAll("[\n|\r|\t]", "_");

  Logger.info("Param1: " + param1 + " " + Logger.getName());
  // ...
}


*See*

OWASP Cheat Sheet - Logging
OWASP Attack Category - Log Injection
OWASP Top 10 2017 - Category A1 - Injection
MITRE, CWE-117 - Improper Output Neutralization for Logs
SANS Top 25 - Insecure Interaction Between Components
#### Rule 279: "enum" fields should not be publicly mutable
##### Quality Category: Vulnerability
enums are generally thought of as constant, but an enum with a public field or public setter is not only non-constant, but also vulnerable to malicious code. Ideally fields in an enum are private and set in the constructor, but if that's not possible, their visibility should be reduced as much as possible.

**Noncompliant Code Example**
```java
public enum Continent {

  NORTH_AMERICA (23, 24709000),
  // ...
  EUROPE (50, 39310000);

  public int countryCount;  // Noncompliant
  private int landMass;

  Continent(int countryCount, int landMass) {
    // ...
  }

  public void setLandMass(int landMass) {  // Noncompliant
    this.landMass = landMass;
  }


```
**Compliant Solution**
```java
public enum Continent {

  NORTH_AMERICA (23, 24709000),
  // ...
  EUROPE (50, 39310000);

  private int countryCount;
  private int landMass;

  Continent(int countryCount, int landMass) {
    // ...
  }
```
#### Rule 280: Mutable fields should not be "public static"
##### Quality Category: Vulnerability
There is no good reason to have a mutable object as the public (by default), static member of an interface. Such variables should be moved into classes and their visibility lowered.

Similarly, mutable static members of classes and enumerations which are accessed directly, rather than through getters and setters, should be protected to the degree possible. That can be done by reducing visibility or making the field final if appropriate.

Note that making a mutable field, such as an array, final will keep the variable from being reassigned, but doing so has no effect on the mutability of the internal state of the array (i.e. it doesn't accomplish the goal).

This rule raises issues for public static array, Collection, Date, and awt.Point members.

**Noncompliant Code Example**
```java
public interface MyInterface {
  public static String [] strings; // Noncompliant
}

public class A {
  public static String [] strings1 = {"first","second"};  // Noncompliant
  public static String [] strings2 = {"first","second"};  // Noncompliant
  public static List<String> strings3 = new ArrayList<>();  // Noncompliant
  // ...
}


*See*

MITRE, CWE-582 - Array Declared Public, Final, and Static
MITRE, CWE-607 - Public Static Final Field References Mutable Object
CERT, OBJ01-J. - Limit accessibility of fields
CERT, OBJ13-J. - Ensure that references to mutable objects are not exposed
#### Rule 281: Exceptions should not be thrown from servlet methods
##### Quality Category: Vulnerability
Even though the signatures for methods in a servlet include throws IOException, ServletException, it's a bad idea to let such exceptions be thrown. Failure to catch exceptions in a servlet could leave a system in a vulnerable state, possibly resulting in denial-of-service attacks, or the exposure of sensitive information because when a servlet throws an exception, the servlet container typically sends debugging information back to the user. And that information could be very valuable to an attacker.

This rule checks all exceptions in methods named "do*" are explicitly handled in servlet classes.

**Noncompliant Code Example**
```java
public void doGet(HttpServletRequest request, HttpServletResponse response)
  throws IOException, ServletException {
  String ip = request.getRemoteAddr();
  InetAddress addr = InetAddress.getByName(ip); // Noncompliant; getByName(String) throws UnknownHostException
  //...
}


```
**Compliant Solution**
```java
public void doGet(HttpServletRequest request, HttpServletResponse response)
  throws IOException, ServletException {
  try {
    String ip = request.getRemoteAddr();
    InetAddress addr = InetAddress.getByName(ip);
    //...
  }
  catch (UnknownHostException uhex) {
    //...
  }
}


*See*

MITRE, CWE-600 - Uncaught Exception in Servlet
CERT, ERR01-J. - Do not allow exceptions to expose sensitive information
 OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
#### Rule 282: "public static" fields should be constant
##### Quality Category: Vulnerability
There is no good reason to declare a field "public" and "static" without also declaring it "final". Most of the time this is a kludge to share a state among several objects. But with this approach, any object can do whatever it wants with the shared state, such as setting it to null.

**Noncompliant Code Example**
```java
public class Greeter {
  public static Foo foo = new Foo();
  ...
}


```
**Compliant Solution**
```java
public class Greeter {
  public static final Foo FOO = new Foo();
  ...
}


*See*

MITRE, CWE-500 - Public Static Field Not Marked Final
CERT OBJ10-J. - Do not use public static nonfinal fields
#### Rule 283: Throwable.printStackTrace(...) should not be called
##### Quality Category: Vulnerability
Throwable.printStackTrace(...) prints a Throwable and its stack trace to some stream. By default that stream System.Err, which could inadvertently expose sensitive information.

Loggers should be used instead to print Throwables, as they have many advantages:

 Users are able to easily retrieve the logs.
 The format of log messages is uniform and allow users to browse the logs easily.

This rule raises an issue when printStackTrace is used without arguments, i.e. when the stack trace is printed to the default stream.

**Noncompliant Code Example**
```java
try {
  /* ... */
} catch(Exception e) {
  e.printStackTrace();        // Noncompliant
}


```
**Compliant Solution**
```java
try {
  /* ... */
} catch(Exception e) {
  LOGGER.log("context", e);
}


*See*

MITRE, CWE-489 - Leftover Debug Code
 OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
#### Rule 284: Double Brace Initialization should not be used
##### Quality Category: Bug
Because Double Brace Initialization (DBI) creates an anonymous class with a reference to the instance of the owning object, its use can lead to memory leaks if the anonymous inner class is returned and held by other objects. Even when there's no leak, DBI is so obscure that it's bound to confuse most maintainers.

For collections, use Arrays.asList instead, or explicitly add each item directly to the collection.

**Noncompliant Code Example**
```java
Map source = new HashMap(){{ // Noncompliant
    put("firstName", "John");
    put("lastName", "Smith");
}};


```
**Compliant Solution**
```java
Map source = new HashMap();
// ...
source.put("firstName", "John");
source.put("lastName", "Smith");
// ...
```
#### Rule 285: Non-primitive fields should not be "volatile"
##### Quality Category: Bug
Marking an array volatile means that the array itself will always be read fresh and never thread cached, but the items in the array will not be. Similarly, marking a mutable object field volatile means the object reference is volatile but the object itself is not, and other threads may not see updates to the object state.

This can be salvaged with arrays by using the relevant AtomicArray class, such as AtomicIntegerArray, instead. For mutable objects, the volatile should be removed, and some other method should be used to ensure thread-safety, such as synchronization, or ThreadLocal storage.

**Noncompliant Code Example**
```java
private volatile int [] vInts;  // Noncompliant
private volatile MyObj myObj;  // Noncompliant


```
**Compliant Solution**
```java
private AtomicIntegerArray vInts;
private MyObj myObj;


*See*

CERT, CON50-J. - Do not assume that declaring a reference volatile guarantees safe publication of the members of the referenced object
#### Rule 286: "toArray" should be passed an array of the proper type
##### Quality Category: Bug
Given no arguments, the Collections.toArray method returns an Object [], which will cause a ClassCastException at runtime if you try to cast it to an array of the proper class. Instead, pass an array of the correct type in to the call.

**Noncompliant Code Example**
```java
public String [] getStringArray(List<String> strings) {
  return (String []) strings.toArray();  // Noncompliant; ClassCastException thrown
}


```
**Compliant Solution**
```java
public String [] getStringArray(List<String> strings) {
  return strings.toArray(new String[0]);
}
```
#### Rule 287: Neither "Math.abs" nor negation should be used on numbers that could be "MIN_VALUE"
##### Quality Category: Bug
It is possible for a call to hashCode to return Integer.MIN_VALUE. Take the absolute value of such a hashcode and you'll still have a negative number. Since your code is likely to assume that it's a positive value instead, your results will be unreliable.

Similarly, Integer.MIN_VALUE could be returned from Random.nextInt() or any object's compareTo method, and Long.MIN_VALUE could be returned from Random.nextLong(). Calling Math.abs on values returned from these methods is similarly ill-advised.

**Noncompliant Code Example**
```java
public void doSomething(String str) {
  if (Math.abs(str.hashCode()) > 0) { // Noncompliant
    // ...
  }
}


```
**Compliant Solution**
```java
public void doSomething(String str) {
  if (str.hashCode() != 0) {
    // ...
  }
}
```
#### Rule 288: The value returned from a stream read should be checked
##### Quality Category: Bug
You cannot assume that any given stream reading call will fill the byte[] passed in to the method. Instead, you must check the value returned by the read method to see how many bytes were read. Fail to do so, and you introduce bug that is both harmful and difficult to reproduce.

Similarly, you cannot assume that InputStream.skip will actually skip the requested number of bytes, but must check the value returned from the method.

This rule raises an issue when an InputStream.read method that accepts a byte[] is called, but the return value is not checked, and when the return value of InputStream.skip is not checked. The rule also applies to InputStream child classes.

**Noncompliant Code Example**
```java
public void doSomething(String fileName) {
  try {
    InputStream is = new InputStream(file);
    byte [] buffer = new byte[1000];
    is.read(buffer);  // Noncompliant
    // ...
  } catch (IOException e) { ... }
}


```
**Compliant Solution**
```java
public void doSomething(String fileName) {
  try {
    InputStream is = new InputStream(file);
    byte [] buffer = new byte[1000];
    int count = 0;
    while (count = is.read(buffer) > 0) {
      // ...
    }
  } catch (IOException e) { ... }
}


*See*

CERT, FIO10-J. - Ensure the array is filled when using read() to fill an array
#### Rule 289: "@NonNull" values should not be set to null
##### Quality Category: Bug
Fields, parameters and return values marked @NotNull, @NonNull, or @Nonnull are assumed to have non-null values and are not typically null-checked before use. Therefore setting one of these values to null, or failing to set such a class field in a constructor, could cause NullPointer
```
**Exceptions**
```java at runtime.

**Noncompliant Code Example**
```java
public class MainClass {

  @Nonnull
  private String primary;
  private String secondary;

  public MainClass(String color) {
    if (color != null) {
      secondary = null;
    }
    primary = color;  // Noncompliant; "primary" is Nonnull but could be set to null here
  }

  public MainClass() { // Noncompliant; "primary" Nonnull" but is not initialized
  }

  @Nonnull
  public String indirectMix() {
    String mix = null;
    return mix;  // Noncompliant; return value is Nonnull, but null is returned.}}
  }


*See*

MITRE CWE-476 - NULL Pointer Dereference
CERT, EXP01-J. - Do not use a null in a case where an object is required

#### Rule 290: "Iterator.next()" methods should throw "NoSuchElementException"
##### Quality Category: Bug
By contract, any implementation of the java.util.Iterator.next() method should throw a NoSuchElementException exception when the iteration has no more elements. Any other behavior when the iteration is done could lead to unexpected behavior for users of this Iterator.

**Noncompliant Code Example**
```java
public class MyIterator implements Iterator<String>{
  ...
  public String next(){
    if(!hasNext()){
      return null;
    }
    ...
  }
}


```
**Compliant Solution**
```java
public class MyIterator implements Iterator<String>{
  ...
  public String next(){
    if(!hasNext()){
      throw new NoSuchElementException();
    }
    ...
  }
}
```
#### Rule 291: "compareTo" results should not be checked for specific values
##### Quality Category: Bug
While most compareTo methods return -1, 0, or 1, some do not, and testing the result of a compareTo against a specific value other than 0 could result in false negatives.

**Noncompliant Code Example**
```java
if (myClass.compareTo(arg) == -1) {  // Noncompliant
  // ...
}


```
**Compliant Solution**
```java
if (myClass.compareTo(arg) < 0) {
  // ...
}
```
#### Rule 292: Math operands should be cast before assignment
##### Quality Category: Bug
When arithmetic is performed on integers, the result will always be an integer. You can assign that result to a long, double, or float with automatic type conversion, but having started as an int or long, the result will likely not be what you expect.

For instance, if the result of int division is assigned to a floating-point variable, precision will have been lost before the assignment. Likewise, if the result of multiplication is assigned to a long, it may have already overflowed before the assignment.

In either case, the result will not be what was expected. Instead, at least one operand should be cast or promoted to the final type before the operation takes place.

**Noncompliant Code Example**
```java
float twoThirds = 2/3; // Noncompliant; int division. Yields 0.0
long millisInYear = 1_000*3_600*24*365; // Noncompliant; int multiplication. Yields 1471228928
long bigNum = Integer.MAX_VALUE + 2; // Noncompliant. Yields -2147483647
long bigNegNum =  Integer.MIN_VALUE-1; //Noncompliant, gives a positive result instead of a negative one.
Date myDate = new Date(seconds * 1_000); //Noncompliant, won't produce the expected result if seconds > 2_147_483
...
public long compute(int factor){
  return factor * 10_000;  //Noncompliant, won't produce the expected result if factor > 214_748
}

public float compute2(long factor){
  return factor / 123;  //Noncompliant, will be rounded to closest long integer
}


```
**Compliant Solution**
```java
float twoThirds = 2f/3; // 2 promoted to float. Yields 0.6666667
long millisInYear = 1_000L*3_600*24*365; // 1000 promoted to long. Yields 31_536_000_000
long bigNum = Integer.MAX_VALUE + 2L; // 2 promoted to long. Yields 2_147_483_649
long bigNegNum =  Integer.MIN_VALUE-1L; // Yields -2_147_483_649
Date myDate = new Date(seconds * 1_000L);
...
public long compute(int factor){
  return factor * 10_000L;
}

public float compute2(long factor){
  return factor / 123f;
}


or

float twoThirds = (float)2/3; // 2 cast to float
long millisInYear = (long)1_000*3_600*24*365; // 1_000 cast to long
long bigNum = (long)Integer.MAX_VALUE + 2;
long bigNegNum =  (long)Integer.MIN_VALUE-1;
Date myDate = new Date((long)seconds * 1_000);
...
public long compute(long factor){
  return factor * 10_000;
}

public float compute2(float factor){
  return factor / 123;
}


*See*

 MISRA C++:2008, 5-0-8 - An explicit integral or floating-point conversion shall not increase the size of the underlying type of a cvalue expression.
MITRE, CWE-190 - Integer Overflow or Wraparound
CERT, NUM50-J. - Convert integers to floating point for floating-point operations
CERT, INT18-C. - Evaluate integer expressions in a larger size before comparing or assigning to that size
SANS Top 25 - Risky Resource Management
#### Rule 293: Ints and longs should not be shifted by zero or more than their number of bits-1
##### Quality Category: Bug
Since an int is a 32-bit variable, shifting by more than +/-31 is confusing at best and an error at worst. When the runtime shifts 32-bit integers, it uses the lowest 5 bits of the shift count operand. In other words, shifting an int by 32 is the same as shifting it by 0, and shifting it by 33 is the same as shifting it by 1.

Similarly, when shifting 64-bit integers, the runtime uses the lowest 6 bits of the shift count operand and shifting long by 64 is the same as shifting it by 0, and shifting it by 65 is the same as shifting it by 1.

**Noncompliant Code Example**
```java
public int shift(int a) {
  int x = a >> 32; // Noncompliant
  return a << 48;  // Noncompliant
}


```
**Compliant Solution**
```java
public int shift(int a) {
  int x = a >> 31;
  return a << 16;
}


```
**Exceptions**
```java

This rule doesn't raise an issue when the shift by zero is obviously for cosmetic reasons:

 When the value shifted is a literal.
 When there is a similar shift at the same position on line before or after. E.g.:
bytes[loc+0] = (byte)(value >> 8);
bytes[loc+1] = (byte)(value >> 0);

```
#### Rule 294: "compareTo" should not return "Integer.MIN_VALUE"
##### Quality Category: Bug
It is the sign, rather than the magnitude of the value returned from compareTo that matters. Returning Integer.MIN_VALUE does not convey a higher degree of inequality, and doing so can cause errors because the return value of compareTo is sometimes inversed, with the expectation that negative values become positive. However, inversing Integer.MIN_VALUE yields Integer.MIN_VALUE rather than Integer.MAX_VALUE.

**Noncompliant Code Example**
```java
public int compareTo(MyClass) {
  if (condition) {
    return Integer.MIN_VALUE;  // Noncompliant
  }


```
**Compliant Solution**
```java
public int compareTo(MyClass) {
  if (condition) {
    return -1;
  }
```
#### Rule 295: Boxing and unboxing should not be immediately reversed
##### Quality Category: Bug
Boxing is the process of putting a primitive value into an analogous object, such as creating an Integer to hold an int value. Unboxing is the process of retrieving the primitive value from such an object.

Since the original value is unchanged during boxing and unboxing, there's no point in doing either when not needed. This also applies to autoboxing and auto-unboxing (when Java implicitly handles the primitive/object transition for you).

**Noncompliant Code Example**
```java
public void examineInt(int a) {
  //...
}

public void examineInteger(Integer a) {
  // ...
}

public void func() {
  int i = 0;
  Integer iger1 = Integer.valueOf(0);
  double d = 1.0;

  int dIntValue = new Double(d).intValue(); // Noncompliant

  examineInt(new Integer(i).intValue()); // Noncompliant; explicit box/unbox
  examineInt(Integer.valueOf(i));  // Noncompliant; boxed int will be auto-unboxed

  examineInteger(i); // Compliant; value is boxed but not then unboxed
  examineInteger(iger1.intValue()); // Noncompliant; unboxed int will be autoboxed

  Integer iger2 = new Integer(iger1); // Noncompliant; unnecessary unboxing, value can be reused
}


```
**Compliant Solution**
```java
public void examineInt(int a) {
  //...
}

public void examineInteger(Integer a) {
  // ...
}

public void func() {
  int i = 0;
  Integer iger1 = Integer.valueOf(0);
  double d = 1.0;

  int dIntValue = (int) d;

  examineInt(i);

  examineInteger(i);
  examineInteger(iger1);
}
```
#### Rule 296: "equals(Object obj)" should test argument type
##### Quality Category: Bug
Because the equals method takes a generic Object as a parameter, any type of object may be passed to it. The method should not assume it will only be used to test objects of its class type. It must instead check the parameter's type.

**Noncompliant Code Example**
```java
public boolean equals(Object obj) {
  MyClass mc = (MyClass)obj;  // Noncompliant
  // ...
}


```
**Compliant Solution**
```java
public boolean equals(Object obj) {
  if (obj == null)
    return false;

  if (this.getClass() != obj.getClass())
    return false;

  MyClass mc = (MyClass)obj;
  // ...
}
```
#### Rule 297: "Serializable" inner classes of non-serializable classes should be "static"
##### Quality Category: Bug
Serializing a non-static inner class will result in an attempt at serializing the outer class as well. If the outer class is not serializable, then serialization will fail, resulting in a runtime error.

Making the inner class static (i.e. "nested") avoids this problem, therefore inner classes should be static if possible. However, you should be aware that there are semantic differences between an inner class and a nested one:

 an inner class can only be instantiated within the context of an instance of the outer class.
 a nested (static) class can be instantiated independently of the outer class.
**Noncompliant Code Example**
```java
public class Pomegranate {
  // ...

  public class 
*See*
d implements Serializable {  // Noncompliant; serialization will fail
    // ...
  }
}


```
**Compliant Solution**
```java
public class Pomegranate {
  // ...

  public static class 
*See*
d implements Serializable {
    // ...
  }
}


*See*

CERT SER05-J. - Do not serialize instances of inner classes
#### Rule 298: The non-serializable super class of a "Serializable" class should have a no-argument constructor
##### Quality Category: Bug
When a Serializable object has a non-serializable ancestor in its inheritance chain, object deserialization (re-instantiating the object from file) starts at the first non-serializable class, and proceeds down the chain, adding the properties of each subsequent child class, until the final object has been instantiated.

In order to create the non-serializable ancestor, its no-argument constructor is called. Therefore the non-serializable ancestor of a Serializable class must have a no-arg constructor. Otherwise the class is Serializable but not deserializable.

**Noncompliant Code Example**
```java
public class Fruit {
  private Season ripe;

  public Fruit (Season ripe) {...}
  public void setRipe(Season ripe) {...}
  public Season getRipe() {...}
}

public class Raspberry extends Fruit
        implements Serializable {  // Noncompliant; nonserializable ancestor doesn't have no-arg constructor
  private static final long serialVersionUID = 1;

  private String variety;

  public Raspberry(Season ripe, String variety) { ...}
  public void setVariety(String variety) {...}
  public String getVarity() {...}
}


```
**Compliant Solution**
```java
public class Fruit {
  private Season ripe;

  public Fruit () {...};  // Compliant; no-arg constructor added to ancestor
  public Fruit (Season ripe) {...}
  public void setRipe(Season ripe) {...}
  public Season getRipe() {...}
}

public class Raspberry extends Fruit
        implements Serializable {
  private static final long serialVersionUID = 1;

  private String variety;

  public Raspberry(Season ripe, String variety) {...}
  public void setVariety(String variety) {...}
  public String getVarity() {...}
}
```
#### Rule 299: Method parameters, caught exceptions and foreach variables' initial values should not be ignored
##### Quality Category: Bug
While it is technically correct to assign to parameters from within method bodies, doing so before the parameter value is read is likely a bug. Instead, initial values of parameters, caught exceptions, and foreach parameters should be, if not treated as final, then at least read before reassignment.

**Noncompliant Code Example**
```java
public void doTheThing(String str, int i, List<String> strings) {
  str = Integer.toString(i); // Noncompliant

  for (String s : strings) {
    s = "hello world"; // Noncompliant
  }
}


*See*

 MISRA C:2012, 17.8 - A function parameter should not be modified
#### Rule 300: "equals(Object obj)" and "hashCode()" should be overridden in pairs
##### Quality Category: Bug
According to the Java Language Specification, there is a contract between equals(Object) and hashCode():

If two objects are equal according to the equals(Object) method, then calling the hashCode method on each of the two objects must produce the same integer result.

It is not required that if two objects are unequal according to the equals(java.lang.Object) method, then calling the hashCode method on each of the two objects must produce distinct integer results.

However, the programmer should be aware that producing distinct integer results for unequal objects may improve the performance of hashtables.

In order to comply with this contract, those methods should be either both inherited, or both overridden.

**Noncompliant Code Example**
```java
class MyClass {    // Noncompliant - should also override "hashCode()"

  @Override
  public boolean equals(Object obj) {
    /* ... */
  }

}


```
**Compliant Solution**
```java
class MyClass {    // Compliant

  @Override
  public boolean equals(Object obj) {
    /* ... */
  }

  @Override
  public int hashCode() {
    /* ... */
  }

}


*See*

MITRE, CWE-581 - Object Model Violation: Just One of Equals and Hashcode Defined
CERT, MET09-J. - Classes that define an equals() method must also define a hashCode() method
#### Rule 301: Enabling Cross-Origin Resource Sharing is security-sensitive
##### Quality Category: Security Hotspot
Enabling Cross-Origin Resource Sharing (CORS) is security-sensitive. For example, it has led in the past to the following vulnerabilities:

CVE-2018-0269
CVE-2017-14460

Applications that enable CORS will effectively relax the same-origin policy in browsers, which is in place to prevent AJAX requests to hosts other than the one showing in the browser address bar. Being too permissive, CORS can potentially allow an attacker to gain access to sensitive information.

This rule flags code that enables CORS or specifies any HTTP response headers associated with CORS. The goal is to guide security code reviews.

Ask Yourself Whether
 Any URLs responding with Access-Control-Allow-Origin: * include sensitive content.
 Any domains specified in Access-Control-Allow-Origin headers are checked against a whitelist.
Recommended Secure Coding Practices
 The Access-Control-Allow-Origin header should be set only on specific URLs that require access from other domains. Don't enable the header on the entire domain.
 Don't rely on the Origin header blindly without validation as it could be spoofed by an attacker. Use a whitelist to check that the Origin domain (including protocol) is allowed before returning it back in the Access-Control-Allow-Origin header.
 Use Access-Control-Allow-Origin: * only if your application absolutely requires it, for example in the case of an open/public API. For such endpoints, make sure that there is no sensitive content or information included in the response.
Questionable Code Example
// === Java Servlet ===
@Override
protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
  resp.setHeader("Content-Type", "text/plain; charset=utf-8");
  resp.setHeader("Access-Control-Allow-Origin", "http://localhost:8080"); // Questionable
  resp.setHeader("Access-Control-Allow-Credentials", "true"); // Questionable
  resp.setHeader("Access-Control-Allow-Methods", "GET"); // Questionable
  resp.getWriter().write("response");
}

// === Spring MVC Controller annotation ===
@CrossOrigin(origins = "http://domain1.com") // Questionable
@RequestMapping("")
public class TestController {
    public String home(ModelMap model) {
        model.addAttribute("message", "ok ");
        return "view";
    }

    @CrossOrigin(origins = "http://domain2.com") // Questionable
    @RequestMapping(value = "/test1")
    public ResponseEntity<String> test1() {
        return ResponseEntity.ok().body("ok");
    }
}


*See*

OWASP Top 10 2017 - Category A6 - Security Misconfiguration
OWASP HTML5 Security Cheat Sheet - Cross Origin Resource Sharing
OWASP CORS OriginHeaderScrutiny
OWASP CORS RequestPreflighScrutiny
SANS Top 25 - Porous Defenses
MITRE, CWE-346 - Origin Validation Error
MITRE, CWE-942 - Overly Permissive Cross-domain Whitelist
#### Rule 302: Using cookies is security-sensitive
##### Quality Category: Security Hotspot
Using cookies is security-sensitive. It has led in the past to the following vulnerabilities:

CVE-2018-7772
CVE-2018-10085
CVE-2016-6537

Attackers can use widely-available tools to read and modify cookies, thus:

 sensitive information written by the server will be exposed.
 cookies sent by the client can be crafted to attack server vulnerabilities.

This rule flags code that reads or writes cookies.

Ask Yourself Whether
 sensitive information is stored inside the cookie.
 cookie values are used without being first sanitized.

You are at risk if you answered yes to any of those questions.

Recommended Secure Coding Practices

Cookies should only be used to manage the user session. The best practice is to keep all user-related information server-side and link them to the user session, never sending them to the client. In a very few corner cases, cookies can be used for non-sensitive information that need to live longer than the user session.

Do not try to encode sensitive information in a non human-readable format before writing them in a cookie. The encoding can be reverted and the original information will be exposed.

Sanitize every information read from a cookie before using them.

Using cookies only for session IDs doesn't make them secure. Follow OWASP best practices when you configure your cookies.

Questionable Code Example
// === javax.servlet ===
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequest;

public class JavaxServlet {
    void aServiceMethodSettingCookie(HttpServletRequest request, HttpServletResponse response, String acctID) {
        Cookie cookie = new Cookie("userAccountID", acctID);  // Questionable
        response.addCookie(cookie);  // Questionable

        cookie.getValue();  // Questionable. Check how the value is used.
    }
}

// === javax.ws ===
import java.util.Date;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.NewCookie;

class JavaxWs {
    void jaxRsCookie(String comment, int maxAge, boolean secure, Date expiry, boolean httpOnly, String name,
            String value, String path, String domain, int version) {
        Cookie cookie= new Cookie("name", "value");  // Questionable
        cookie.getValue();  // Questionable

        new NewCookie(cookie);  // Questionable
        new NewCookie(cookie, comment, maxAge, secure);
        new NewCookie(cookie, comment, maxAge, expiry, secure, httpOnly);
        new NewCookie(name, value);
        new NewCookie(name, value, path, domain, version, comment, maxAge, secure);
        new NewCookie(name, value, path, domain, version, comment, maxAge, expiry, secure, httpOnly);
        new NewCookie(name, value, path, domain, comment, maxAge, secure);
        new NewCookie(name, value, path, domain, comment, maxAge, secure, httpOnly);
    }
}

// === java.net ===
import java.net.HttpCookie;

class JavaNet {
    void httpCookie(HttpCookie hc) {
        HttpCookie cookie = new HttpCookie("name", "value");  // Questionable
        cookie.setValue("value");  // Questionable
        cookie.getValue();  // Questionable
    }
}

// === apache.shiro ===
import org.apache.shiro.web.servlet.SimpleCookie;

class ApacheShiro {

    void shiroCookie(SimpleCookie cookie) {
        SimpleCookie sc = new SimpleCookie(cookie);  // Questionable
        cookie.setValue("value");  // Questionable
        cookie.getValue();  // Questionable
    }
}

// === spring ===
import org.springframework.security.web.savedrequest.SavedCookie;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestMapping;
import javax.servlet.http.Cookie;

class Spring {
    @RequestMapping("/mypage.html")
    // Questionable. “myCookie” value is read from a cookie.
    public String myPage(@CookieValue("cookieName") String myCookie) {
        return "test";
    }

    void springCookie(Cookie cookie) {
        SavedCookie savedCookie = new SavedCookie(cookie); // Questionable
        cookie.getValue(); // Questionable
    }
}

// === Play ===
import play.mvc.Http.Cookie;
import play.mvc.Http.CookieBuilder;
import scala.language;


class Play {
    void playCookie(Cookie cookie) {
        cookie.value();  // Questionable

        CookieBuilder builder = Cookie.builder("name", "value");  // Questionable
        builder.withName("name")
          .withValue("value")  // Questionable
          .build();

    }
}


*See*

MITRE, CWE-312 - Cleartext Storage of Sensitive Information
MITRE, CWE-315 - Cleartext Storage of Sensitive Information in a Cookie
MITRE CWE-565 - Reliance on Cookies without Validation and Integrity Checking
 OWASP Top 10 2017 Category A1 - Injection
 OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
CERT, FIO52-J. - Do not store unencrypted sensitive information on the client side
 Derived from FindSecBugs rule COOKIE_USAGE
#### Rule 303: Creating cookies without the "secure" flag is security-sensitive
##### Quality Category: Security Hotspot
The "secure" attribute prevents cookies from being sent over plaintext connections such as HTTP, where they would be easily eavesdropped upon. Instead, cookies with the secure attribute are only sent over encrypted HTTPS connections.

Recommended Secure Coding Practices
 call setSecure(true) on the Cookie object
**Noncompliant Code Example**
```java
Cookie c = new Cookie(SECRET, secret);  // Noncompliant; cookie is not secure
response.addCookie(c);


```
**Compliant Solution**
```java
Cookie c = new Cookie(SECRET, secret);
c.setSecure(true);
response.addCookie(c);


*See*

MITRE, CWE-311 - Missing Encryption of Sensitive Data
MITRE, CWE-315 - Cleartext Storage of Sensitive Information in a Cookie
MITRE, CWE-614 - Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
 OWASP Top 10 2017 Category A2 - Broken Authentication
 OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
SANS Top 25 - Porous Defenses
#### Rule 304: Using hardcoded IP addresses is security-sensitive
##### Quality Category: Security Hotspot
Hardcoding IP addresses is security-sensitive. It has led in the past to the following vulnerabilities:

CVE-2006-5901
CVE-2005-3725

Today's services have an ever-changing architecture due to their scaling and redundancy needs. It is a mistake to think that a service will always have the same IP address. When it does change, the hardcoded IP will have to be modified too. This will have an impact on the product development, delivery and deployment:

 The developers will have to do a rapid fix every time this happens, instead of having an operation team change a configuration file.
 It forces the same address to be used in every environment (dev, sys, qa, prod).

Last but not least it has an effect on application security. Attackers might be able to decompile the code and thereby discover a potentially sensitive address. They can perform a Denial of Service attack on the service at this address or spoof the IP address. Such an attack is always possible, but in the case of a hardcoded IP address the fix will be much slower, which will increase an attack's impact.

Recommended Secure Coding Practices
 make the IP address configurable.
**Noncompliant Code Example**
```java
String ip = "192.168.12.42"; // Noncompliant
Socket socket = new Socket(ip, 6667);


```
**Exceptions**
```java

No issue is reported for the following cases because they are not considered sensitive:

 Loopback addresses 127.0.0.0/8 in CIDR notation (from 127.0.0.0 to 127.255.255.255)
 Broadcast address 255.255.255.255
 Non routable address 0.0.0.0
 Strings of the form 2.5.<number>.<number> as they often match Object Identifiers (OID).

*See*

 OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
CERT, MSC03-J. - Never hard code sensitive information

#### Rule 305: "read(byte[],int,int)" should be overridden
##### Quality Category: Code Smell
When directly subclassing java.io.InputStream or java.io.FilterInputStream, the only requirement is that you implement the method read(). However most uses for such streams don't read a single byte at a time and the default implementation for read(byte[],int,int) will call read(int) for every single byte in the array which can create a lot of overhead and is utterly inefficient. It is therefore strongly recommended that subclasses provide an efficient implementation of read(byte[],int,int).

This rule raises an issue when a direct subclass of java.io.InputStream or java.io.FilterInputStream doesn't provide an override of read(byte[],int,int).

**Noncompliant Code Example**
```java
public class MyInputStream extends java.io.InputStream {
  private FileInputStream fin;

  public MyInputStream(File file) throws IOException {
    fin = new FileInputStream(file);
  }

  @Override
  public int read() throws IOException {
    return fin.read();
  }
}


```
**Compliant Solution**
```java
public class MyInputStream extends java.io.InputStream {
  private FileInputStream fin;

  public MyInputStream(File file) throws IOException {
    fin = new FileInputStream(file);
  }

  @Override
  public int read() throws IOException {
    return fin.read();
  }

  @Override
  public int read(byte[] b, int off, int len) throws IOException {
    return fin.read(b, off, len);
  }
}


```
**Exceptions**
```java

This rule doesn't raise an issue when the class is declared abstract.
```
#### Rule 306: An iteration on a Collection should be performed on the type handled by the Collection
##### Quality Category: Code Smell
This rule raises an issue when an iteration over the items of a Collection is performed on a super-type of the type handled by the Collection.

Relying on Object or any classes between Object and the real class handled by the Collection is not recommended. While it's accepted by the language, this practice reduces readability of the code and forces to down-cast the item of the Collection to be able to call a method on it while simply using the correct type in the iteration makes things more clear and simple.

**Noncompliant Code Example**
```java
public Collection<Person> getPersons() { ... }

for (Object item : getPersons()) { // Noncompliant
  Person person = (Person) item; // Noncompliant; it's required to down-cast to the to correct type to use "item"
  person.getAdress();
}


```
**Compliant Solution**
```java
for (Person person : getPersons()) { // Compliant
  person.getAddress() ;
}
```
#### Rule 307: "StandardCharsets" constants should be preferred
##### Quality Category: Code Smell
JDK7 introduced the class java.nio.charset.StandardCharsets. It provides constants for all charsets that are guaranteed to be available on every implementation of the Java platform.

 ISO_8859_1
 US_ASCII
 UTF_16
 UTF_16BE
 UTF_16LE
 UTF_8

These constants should be preferred to:

- the use of a String such as "UTF-8" which has the drawback of requiring the catch/throw of an UnsupportedEncodingException that will never actually happen

- the use of Guava’s Charsets class, which has been obsolete since JDK7

**Noncompliant Code Example**
```java
try {
  byte[] bytes = string.getBytes("UTF-8"); // Noncompliant; use a String instead of StandardCharsets.UTF_8
} catch (UnsupportedEncodingException e) {
  throw new AssertionError(e);
}
// ...
byte[] bytes = string.getBytes(Charsets.UTF_8); // Noncompliant; Guava way obsolete since JDK7


```
**Compliant Solution**
```java
byte[] bytes = string.getBytes(StandardCharsets.UTF_8)
```
#### Rule 308: "@CheckForNull" or "@Nullable" should not be used on primitive types
##### Quality Category: Code Smell
By definition, primitive types are not Objects and so they can't be null. Adding @CheckForNull or @Nullable on primitive types adds confusion and is useless.

This rule raises an issue when @CheckForNull or @Nullable is set on a method returning a primitive type: byte, short, int, long, float, double, boolean, char.

**Noncompliant Code Example**
```java
@CheckForNull
boolean isFoo() {
 ...
}


```
**Compliant Solution**
```java
boolean isFoo() {
 ...
}
```
#### Rule 309: Composed "@RequestMapping" variants should be preferred
##### Quality Category: Code Smell
Spring framework 4.3 introduced variants of the @RequestMapping annotation to better represent the semantics of the annotated methods. The use of @GetMapping, @PostMapping, @PutMapping, @PatchMapping and @DeleteMapping should be preferred to the use of the raw @RequestMapping(method = RequestMethod.XYZ).

**Noncompliant Code Example**
```java
@RequestMapping(path = "/greeting", method = RequestMethod.GET) // Noncompliant
public Greeting greeting(@RequestParam(value = "name", defaultValue = "World") String name) {
...
}


```
**Compliant Solution**
```java
@GetMapping(path = "/greeting") // Compliant
public Greeting greeting(@RequestParam(value = "name", defaultValue = "World") String name) {
...
}
```
#### Rule 310: "write(byte[],int,int)" should be overridden
##### Quality Category: Code Smell
When directly subclassing java.io.OutputStream or java.io.FilterOutputStream, the only requirement is that you implement the method write(int). However most uses for such streams don't write a single byte at a time and the default implementation for write(byte[],int,int) will call write(int) for every single byte in the array which can create a lot of overhead and is utterly inefficient. It is therefore strongly recommended that subclasses provide an efficient implementation of write(byte[],int,int).

This rule raises an issue when a direct subclass of java.io.OutputStream or java.io.FilterOutputStream doesn't provide an override of write(byte[],int,int).

**Noncompliant Code Example**
```java
public class MyStream extends OutputStream { // Noncompliant
    private FileOutputStream fout;

    public MyStream(File file) throws IOException {
        fout = new FileOutputStream(file);
    }

    @Override
    public void write(int b) throws IOException {
        fout.write(b);
    }

    @Override
    public void close() throws IOException {
        fout.write("\n\n".getBytes());
        fout.close();
        super.close();
    }
}


```
**Compliant Solution**
```java
public class MyStream extends OutputStream {
    private FileOutputStream fout;

    public MyStream(File file) throws IOException {
        fout = new FileOutputStream(file);
    }

    @Override
    public void write(int b) throws IOException {
        fout.write(b);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        fout.write(b, off, len);
    }

    @Override
    public void close() throws IOException {
        fout.write("\n\n".getBytes());
        fout.close();
        super.close();
    }
}


```
**Exceptions**
```java

This rule doesn't raise an issue when the class is declared abstract.
```
#### Rule 311: Functional Interfaces should be as specialised as possible
##### Quality Category: Code Smell
The java.util.function package provides a large array of functional interface definitions for use in lambda expressions and method references. In general it is recommended to use the more specialised form to avoid auto-boxing. For instance IntFunction<Foo> should be preferred over Function<Integer, Foo>.

This rule raises an issue when any of the following substitution is possible:

Current Interface	Preferred Interface
Function<Integer, R>	IntFunction<R>
Function<Long, R>	LongFunction<R>
Function<Double, R>	DoubleFunction<R>
Function<Double,Integer>	DoubleToIntFunction
Function<Double,Long>	DoubleToLongFunction
Function<Long,Double>	LongToDoubleFunction
Function<Long,Integer>	LongToIntFunction
Function<R,Integer>	ToIntFunction<R>
Function<R,Long>	ToLongFunction<R>
Function<R,Double>	ToDoubleFunction<R>
Function<T,T>	UnaryOperator<T>
BiFunction<T,T,T>	BinaryOperator<T>
Consumer<Integer>	IntConsumer
Consumer<Double>	DoubleConsumer
Consumer<Long>	LongConsumer
BiConsumer<T,Integer>	ObjIntConsumer<T>
BiConsumer<T,Long>	ObjLongConsumer<T>
BiConsumer<T,Double>	ObjDoubleConsumer<T>
Predicate<Integer>	IntPredicate
Predicate<Double>	DoublePredicate
Predicate<Long>	LongPredicate
Supplier<Integer>	IntSupplier
Supplier<Double>	DoubleSupplier
Supplier<Long>	LongSupplier
Supplier<Boolean>	BooleanSupplier
UnaryOperator<Integer>	IntUnaryOperator
UnaryOperator<Double>	DoubleUnaryOperator
UnaryOperator<Long>	LongUnaryOperator
BinaryOperator<Integer>	IntBinaryOperator
BinaryOperator<Long>	LongBinaryOperator
BinaryOperator<Double>	DoubleBinaryOperator
Function<T, Boolean>	Predicate<T>
BiFunction<T,U,Boolean>	BiPredicate<T,U>
**Noncompliant Code Example**
```java
public class Foo implements Supplier<Integer> {  // Noncompliant
    @Override
    public Integer get() {
      // ...
    }
}


```
**Compliant Solution**
```java
public class Foo implements IntSupplier {

  @Override
  public int getAsInt() {
    // ...
  }
}
```
#### Rule 312: Null checks should not be used with "instanceof"
##### Quality Category: Code Smell
There's no need to null test in conjunction with an instanceof test. null is not an instanceof anything, so a null check is redundant.

**Noncompliant Code Example**
```java
if (x != null && x instanceof MyClass) { ... }  // Noncompliant

if (x == null || ! x instanceof MyClass) { ... } // Noncompliant


```
**Compliant Solution**
```java
if (x instanceof MyClass) { ... }

if (! x instanceof MyClass) { ... }
```
#### Rule 313: "close()" calls should not be redundant
##### Quality Category: Code Smell
Java 7's try-with-resources structure automatically handles closing the resources that the try itself opens. Thus, adding an explicit close() call is redundant and potentially confusing.

**Noncompliant Code Example**
```java
try (PrintWriter writer = new PrintWriter(process.getOutputStream())) {
  String contents = file.contents();
  writer.write(new Gson().toJson(new MyObject(contents)));
  writer.flush();
  writer.close();  // Noncompliant
}


```
**Compliant Solution**
```java
try (PrintWriter writer = new PrintWriter(process.getOutputStream())) {
  String contents = file.contents();
  writer.write(new Gson().toJson(new MyObject(contents)));
  writer.flush();
}
```
#### Rule 314: "ThreadLocal.withInitial" should be preferred
##### Quality Category: Code Smell
Java 8 introduced ThreadLocal.withInitial which is a simpler alternative to creating an anonymous inner class to initialise a ThreadLocal instance.

This rule raises an issue when a ThreadLocal anonymous inner class can be replaced by a call to ThreadLocal.withInitial.

**Noncompliant Code Example**
```java
ThreadLocal<List<String>> myThreadLocal =
    new ThreadLocal<List<String>>() { // Noncompliant
        @Override
        protected List<String> initialValue() {
            return new ArrayList<String>();
        }
    };


```
**Compliant Solution**
```java
ThreadLocal<List<String>> myThreadLocal = ThreadLocal.withInitial(ArrayList::new);
```
#### Rule 315: "Stream" call chains should be simplified when possible
##### Quality Category: Code Smell
When using the Stream API, call chains should be simplified as much as possible. Not only does it make the code easier to read, it also avoid creating unnecessary temporary objects.

This rule raises an issue when one of the following substitution is possible:

Original	Preferred
stream.filter(predicate).findFirst().isPresent()	stream.anyMatch(predicate)
stream.filter(predicate).findAny().isPresent()	stream.anyMatch(predicate)
!stream.anyMatch(predicate)	stream.noneMatch(predicate)
!stream.anyMatch(x -> !(...))	stream.allMatch(...)
stream.map(mapper).anyMatch(Boolean::booleanValue)	stream.anyMatch(predicate)
**Noncompliant Code Example**
```java
boolean hasRed = widgets.stream().filter(w -> w.getColor() == RED).findFirst().isPresent(); // Noncompliant


```
**Compliant Solution**
```java
boolean hasRed = widgets.stream().anyMatch(w -> w.getColor() == RED);
```
#### Rule 316: Packages containing only "package-info.java" should be removed
##### Quality Category: Code Smell
There is no reason to have a package that is empty except for "package-info.java". Such packages merely clutter a project, taking up space but adding no value.
#### Rule 317: Arrays should not be created for varargs parameters
##### Quality Category: Code Smell
There's no point in creating an array solely for the purpose of passing it as a varargs (...) argument; varargs is an array. Simply pass the elements directly. They will be consolidated into an array automatically. Incidentally passing an array where Object ... is expected makes the intent ambiguous: Is the array supposed to be one object or a collection of objects?

**Noncompliant Code Example**
```java
public void callTheThing() {
  //...
  doTheThing(new String[] { "s1", "s2"});  // Noncompliant: unnecessary
  doTheThing(new String[12]);  // Compliant
  doTheOtherThing(new String[8]);  // Noncompliant: ambiguous
  // ...
}

public void doTheThing (String ... args) {
  // ...
}

public void doTheOtherThing(Object ... args) {
  // ...
}


```
**Compliant Solution**
```java
public void callTheThing() {
  //...
  doTheThing("s1", "s2");
  doTheThing(new String[12]);
  doTheOtherThing((Object[]) new String[8]);
   // ...
}

public void doTheThing (String ... args) {
  // ...
}

public void doTheOtherThing(Object ... args) {
  // ...
}
```
#### Rule 318: Jump statements should not be redundant
##### Quality Category: Code Smell
Jump statements such as return and continue let you change the default flow of program execution, but jump statements that direct the control flow to the original direction are just a waste of keystrokes.

**Noncompliant Code Example**
```java
public void foo() {
  while (condition1) {
    if (condition2) {
      continue; // Noncompliant
    } else {
      doTheThing();
    }
  }
  return; // Noncompliant; this is a void method
}


```
**Compliant Solution**
```java
public void foo() {
  while (condition1) {
    if (!condition2) {
      doTheThing();
    }
  }
}
```
#### Rule 319: Deprecated "${pom}" properties should not be used
##### Quality Category: Code Smell
Deprecated features are those that have been retained temporarily for backward compatibility, but which will eventually be removed. In effect, deprecation announces a grace period to allow the smooth transition from the old features to the new ones. In that period, no use of the deprecated features should be added, and all existing uses should be gradually removed.

This rule raises an issue when ${pom.*} properties are used in a pom.

**Noncompliant Code Example**
```java
  <build>
    <finalName>${pom.artifactId}-${pom.version}</finalName>  <!-- Noncompliant -->


```
**Compliant Solution**
```java
  <build>
    <finalName>${project.artifactId}-${project.version}</finalName>


or

  <build>
    <finalName>${artifactId}-${version}</finalName>
```
#### Rule 320: Methods should not return constants
##### Quality Category: Code Smell
There's no point in forcing the overhead of a method call for a method that always returns the same constant value. Even worse, the fact that a method call must be made will likely mislead developers who call the method thinking that something more is done. Declare a constant instead.

This rule raises an issue if on methods that contain only one statement: the return of a constant value.

**Noncompliant Code Example**
```java
int getBestNumber() {
  return 12;  // Noncompliant
}


```
**Compliant Solution**
```java
static int bestNumber = 12;


```
**Exceptions**
```java

Methods with annotations, such as @Override and Spring's @RequestMapping, are ignored.
```
#### Rule 321: "private" methods called only by inner classes should be moved to those classes
##### Quality Category: Code Smell
When a private method is only invoked by an inner class, there's no reason not to move it into that class. It will still have the same access to the outer class' members, but the outer class will be clearer and less cluttered.

**Noncompliant Code Example**
```java
public class Outie {
  private int i=0;

  private void increment() {  // Noncompliant
    i++;
  }

  public class Innie {
    public void doTheThing() {
      Outie.this.increment();
    }
  }
}


```
**Compliant Solution**
```java
public class Outie {
  private int i=0;

  public class Innie {
    public void doTheThing() {
      Outie.this.increment();
    }

    private void increment() {
      Outie.this.i++;
    }
  }
}
```
#### Rule 322: Abstract methods should not be redundant
##### Quality Category: Code Smell
There's no point in redundantly defining an abstract method with the same signature as a method in an interface that the class implements. Any concrete child classes will have to implement the method either way.

**Noncompliant Code Example**
```java
public interface Reportable {
  String getReport();
}

public abstract class AbstractRuleReport implements Reportable{
  public abstract String getReport();  // Noncompliant

  // ...
}
```
#### Rule 323: Static non-final field names should comply with a naming convention
##### Quality Category: Code Smell
Shared naming conventions allow teams to collaborate efficiently. This rule checks that static non-final field names match a provided regular expression.

**Noncompliant Code Example**
```java

With the default regular expression ^[a-z][a-zA-Z0-9]*$:

public final class MyClass {
   private static String foo_bar;
}


```
**Compliant Solution**
```java
class MyClass {
   private static String fooBar;
}
```
#### Rule 324: JUnit rules should be used
##### Quality Category: Code Smell
While some TestRule classes have the desired effect without ever being directly referenced by a test, several others do not, and there's no reason to leave them cluttering up the file if they're not in use.

This rule raises an issue when Test class fields of the following types aren't used by any of the test methods: TemporaryFolder, and TestName.

This rule also applies to the JUnit 5 equivalent classes: TempDir, and TestInfo.

**Noncompliant Code Example**
```java
public class ProjectDefinitionTest {

  @Rule
  public TemporaryFolder temp = new TemporaryFolder();  // Noncompliant

  @Test
  public void shouldSetKey() {
    ProjectDefinition def = ProjectDefinition.create();
    def.setKey("mykey");
    assertThat(def.getKey(), is("mykey"));
  }
}


```
**Compliant Solution**
```java
public class ProjectDefinitionTest {

  @Test
  public void shouldSetKey() {
    ProjectDefinition def = ProjectDefinition.create();
    def.setKey("mykey");
    assertThat(def.getKey(), is("mykey"));
  }
}
```
#### Rule 325: "indexOf" checks should use a start position
##### Quality Category: Code Smell
One thing that makes good code good is the clarity with which it conveys the intent of the original programmer to maintainers, and the proper choice of indexOf methods can help move code from confusing to clear.

If you need to see whether a substring is located beyond a certain point in a string, you can test the indexOf the substring versus the target point, or you can use the version of indexOf which takes a starting point argument. The latter is arguably clearer because the result is tested against -1, which is an easily recognizable "not found" indicator.

**Noncompliant Code Example**
```java
String name = "ismael";

if (name.indexOf("ae") > 2) { // Noncompliant
  // ...
}


```
**Compliant Solution**
```java
String name = "ismael";

if (name.indexOf("ae", 2) > -1) {
  // ...
}
```
#### Rule 326: Nested "enum"s should not be declared static
##### Quality Category: Code Smell
According to the docs:

Nested enum types are implicitly static.

So there's no need to declare them static explicitly.

**Noncompliant Code Example**
```java
public class Flower {
  static enum Color { // Noncompliant; static is redundant here
    RED, YELLOW, BLUE, ORANGE
  }

  // ...
}


```
**Compliant Solution**
```java
public class Flower {
  enum Color { // Compliant
    RED, YELLOW, BLUE, ORANGE
  }

  // ...
}
```
#### Rule 327: "catch" clauses should do more than rethrow
##### Quality Category: Code Smell
A catch clause that only rethrows the caught exception has the same effect as omitting the catch altogether and letting it bubble up automatically, but with more code and the additional detriment of leaving maintainers scratching their heads.

Such clauses should either be eliminated or populated with the appropriate logic.

**Noncompliant Code Example**
```java
public String readFile(File f) {
  StringBuilder sb = new StringBuilder();
  try {
    FileReader fileReader = new FileReader(fileName);
    BufferedReader bufferedReader = new BufferedReader(fileReader);

    while((line = bufferedReader.readLine()) != null) {
      //...
  }
  catch (IOException e) {  // Noncompliant
    throw e;
  }
  return sb.toString();
}


```
**Compliant Solution**
```java
public String readFile(File f) {
  StringBuilder sb = new StringBuilder();
  try {
    FileReader fileReader = new FileReader(fileName);
    BufferedReader bufferedReader = new BufferedReader(fileReader);

    while((line = bufferedReader.readLine()) != null) {
      //...
  }
  catch (IOException e) {
    logger.LogError(e);
    throw e;
  }
  return sb.toString();
}


or

public String readFile(File f) throws IOException {
  StringBuilder sb = new StringBuilder();
  FileReader fileReader = new FileReader(fileName);
  BufferedReader bufferedReader = new BufferedReader(fileReader);

  while((line = bufferedReader.readLine()) != null) {
    //...

  return sb.toString();
}
```
#### Rule 328: The diamond operator ("<>") should be used
##### Quality Category: Code Smell
Java 7 introduced the diamond operator (<>) to reduce the verbosity of generics code. For instance, instead of having to declare a List's type in both its declaration and its constructor, you can now simplify the constructor declaration with <>, and the compiler will infer the type.

Note that this rule is automatically disabled when the project's sonar.java.source is lower than 7.

**Noncompliant Code Example**
```java
List<String> strings = new ArrayList<String>();  // Noncompliant
Map<String,List<Integer>> map = new HashMap<String,List<Integer>>();  // Noncompliant


```
**Compliant Solution**
```java
List<String> strings = new ArrayList<>();
Map<String,List<Integer>> map = new HashMap<>();
```
#### Rule 329: "finalize" should not set fields to "null"
##### Quality Category: Code Smell
There is no point in setting class fields to null in a finalizer. If this this is a hint to the garbage collector, it is unnecessary - the object will be garbage collected anyway - and doing so may actually cause extra work for the garbage collector.

**Noncompliant Code Example**
```java
public class Foo {
  private String name;

  @Override
  void finalize() {
    name = null;  // Noncompliant; completely unnecessary
```
#### Rule 330: Subclasses that add fields should override "equals"
##### Quality Category: Code Smell
Extend a class that overrides equals and add fields without overriding equals in the subclass, and you run the risk of non-equivalent instances of your subclass being seen as equal, because only the superclass fields will be considered in the equality test.

This rule looks for classes that do all of the following:

 extend classes that override equals.
 do not themselves override equals.
 add fields.
**Noncompliant Code Example**
```java
public class Fruit {
  private Season ripe;

  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (this.class != obj.class) {
      return false;
    }
    Fruit fobj = (Fruit) obj;
    if (ripe.equals(fobj.getRipe()) {
      return true;
    }
    return false;
  }
}

public class Raspberry extends Fruit {  // Noncompliant; instances will use Fruit's equals method
  private Color ripeColor;
}


```
**Compliant Solution**
```java
public class Fruit {
  private Season ripe;

  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (this.class != obj.class) {
      return false;
    }
    Fruit fobj = (Fruit) obj;
    if (ripe.equals(fobj.getRipe()) {
      return true;
    }
    return false;
  }
}

public class Raspberry extends Fruit {
  private Color ripeColor;

  public boolean equals(Object obj) {
    if (! super.equals(obj)) {
      return false;
    }
    Raspberry fobj = (Raspberry) obj;
    if (ripeColor.equals(fobj.getRipeColor()) {  // added fields are tested
      return true;
    }
    return false;
  }
}
```
#### Rule 331: Catches should be combined
##### Quality Category: Code Smell
Since Java 7 it has been possible to catch multiple exceptions at once. Therefore, when multiple catch blocks have the same code, they should be combined for better readability.

Note that this rule is automatically disabled when the project's sonar.java.source is lower than 7.

**Noncompliant Code Example**
```java
catch (IOException e) {
  doCleanup();
  logger.log(e);
}
catch (SQLException e) {  // Noncompliant
  doCleanup();
  logger.log(e);
}
catch (TimeoutException e) {  // Compliant; block contents are different
  doCleanup();
  throw e;
}


```
**Compliant Solution**
```java
catch (IOException|SQLException e) {
  doCleanup();
  logger.log(e);
}
catch (TimeoutException e) {
  doCleanup();
  throw e;
}
```
#### Rule 332: Methods of "Random" that return floating point values should not be used in random integer generation
##### Quality Category: Code Smell
There is no need to multiply the output of Random's nextDouble method to get a random integer. Use the nextInt method instead.

This rule raises an issue when the return value of any of Random's methods that return a floating point value is converted to an integer.

**Noncompliant Code Example**
```java
Random r = new Random();
int rand = (int)r.nextDouble() * 50;  // Noncompliant way to get a pseudo-random value between 0 and 50
int rand2 = (int)r.nextFloat(); // Noncompliant; will always be 0;


```
**Compliant Solution**
```java
Random r = new Random();
int rand = r.nextInt(50);  // returns pseudo-random value between 0 and 50
```
#### Rule 333: Parsing should be used to convert "Strings" to primitives
##### Quality Category: Code Smell
Rather than creating a boxed primitive from a String to extract the primitive value, use the relevant parse method instead. It will be clearer and more efficient.

**Noncompliant Code Example**
```java
String myNum = "12.2";

float f = (new Float(myNum)).floatValue();  // Noncompliant; creates & discards a Float


```
**Compliant Solution**
```java
String myNum = "12.2";

float f = Float.parseFloat(myNum);
```
#### Rule 334: Classes should not be empty
##### Quality Category: Code Smell
There is no good excuse for an empty class. If it's being used simply as a common extension point, it should be replaced with an interface. If it was stubbed in as a placeholder for future development it should be fleshed-out. In any other case, it should be eliminated.

**Noncompliant Code Example**
```java
public class Nothing {  // Noncompliant
}


```
**Compliant Solution**
```java
public interface Nothing {
}


```
**Exceptions**
```java

Empty classes can be used as marker types (for Spring for instance), therefore empty classes that are annotated will be ignored.

@Configuration
@EnableWebMvc
public final class ApplicationConfiguration {

}

```
#### Rule 335: Fields in non-serializable classes should not be "transient"
##### Quality Category: Code Smell
transient is used to mark fields in a Serializable class which will not be written out to file (or stream). In a class that does not implement Serializable, this modifier is simply wasted keystrokes, and should be removed.

**Noncompliant Code Example**
```java
class Vegetable {  // does not implement Serializable
  private transient Season ripe;  // Noncompliant
  // ...
}


```
**Compliant Solution**
```java
class Vegetable {
  private Season ripe;
  // ...
}
```
#### Rule 336: Boolean checks should not be inverted
##### Quality Category: Code Smell
It is needlessly complex to invert the result of a boolean comparison. The opposite comparison should be made instead.

**Noncompliant Code Example**
```java
if ( !(a == 2)) { ...}  // Noncompliant
boolean b = !(i < 10);  // Noncompliant


```
**Compliant Solution**
```java
if (a != 2) { ...}
boolean b = (i >= 10);
```
#### Rule 337: Redundant casts should not be used
##### Quality Category: Code Smell
Unnecessary casting expressions make the code harder to read and understand.

**Noncompliant Code Example**
```java
public void example() {
  for (Foo obj : (List<Foo>) getFoos()) {  // Noncompliant; cast unnecessary because List<Foo> is what's returned
    //...
  }
}

public List<Foo> getFoos() {
  return this.foos;
}


```
**Compliant Solution**
```java
public void example() {
  for (Foo obj : getFoos()) {
    //...
  }
}

public List<Foo> getFoos() {
  return this.foos;
}


```
**Exceptions**
```java

Casting may be required to distinguish the method to call in the case of overloading:

class A {}
class B extends A{}
class C {
  void fun(A a){}
  void fun(B b){}

  void foo() {
    B b = new B();
    fun(b);
    fun((A) b); //call the first method so cast is not redundant.
  }

}

```
#### Rule 338: "@Deprecated" code should not be used
##### Quality Category: Code Smell
Once deprecated, classes, and interfaces, and their members should be avoided, rather than used, inherited or extended. Deprecation is a warning that the class or interface has been superseded, and will eventually be removed. The deprecation period allows you to make a smooth transition away from the aging, soon-to-be-retired technology.

**Noncompliant Code Example**
```java
/**
 * @deprecated  As of release 1.3, replaced by {@link #Fee}
 */
@Deprecated
public class Fum { ... }

public class Foo {
  /**
   * @deprecated  As of release 1.7, replaced by {@link #doTheThingBetter()}
   */
  @Deprecated
  public void doTheThing() { ... }

  public void doTheThingBetter() { ... }
}

public class Bar extends Foo {
  public void doTheThing() { ... } // Noncompliant; don't override a deprecated method or explicitly mark it as @Deprecated
}

public class Bar extends Fum {  // Noncompliant; Fum is deprecated

  public void myMethod() {
    Foo foo = new Foo();  // okay; the class isn't deprecated
    foo.doTheThing();  // Noncompliant; doTheThing method is deprecated
  }
}


*See*

MITRE, CWE-477 - Use of Obsolete Functions
CERT, MET02-J. - Do not use deprecated or obsolete classes or methods
#### Rule 339: "toString()" should never be called on a String object
##### Quality Category: Code Smell
Invoking a method designed to return a string representation of an object which is already a string is a waste of keystrokes. This redundant construction may be optimized by the compiler, but will be confusing in the meantime.

**Noncompliant Code Example**
```java
String message = "hello world";
System.out.println(message.toString()); // Noncompliant;


```
**Compliant Solution**
```java
String message = "hello world";
System.out.println(message);
```
#### Rule 340: Annotation repetitions should not be wrapped
##### Quality Category: Code Smell
Before Java 8 if you needed to use multiple instances of the same annotation, they had to be wrapped in a container annotation. With Java 8, that's no longer necessary, allowing for cleaner, more readable code.

Note that this rule is automatically disabled when the project's sonar.java.source is lower than 8.

**Noncompliant Code Example**
```java
@SomeAnnotations({  // Noncompliant
  @SomeAnnotation(..a..),
  @SomeAnnotation(..b..),
  @SomeAnnotation(..c..),
})
public class SomeClass {
  ...
}


```
**Compliant Solution**
```java
@SomeAnnotation(..a..)
@SomeAnnotation(..b..)
@SomeAnnotation(..c..)
public class SomeClass {
  ...
}
```
#### Rule 341: Multiple variables should not be declared on the same line
##### Quality Category: Code Smell
Declaring multiple variables on one line is difficult to read.

**Noncompliant Code Example**
```java
class MyClass {

  private int a, b;

  public void method(){
    int c; int d;
  }
}


```
**Compliant Solution**
```java
class MyClass {

  private int a;
  private int b;

  public void method(){
    int c;
    int d;
  }
}


*See*

 MISRA C++:2008, 8-0-1 - An init-declarator-list or a member-declarator-list shall consist of a single init-declarator or member-declarator respectively
CERT, DCL52-J. - Do not declare more than one variable per declaration
CERT, DCL04-C. - Do not declare more than one variable per declaration
#### Rule 342: Strings should not be concatenated using '+' in a loop
##### Quality Category: Code Smell
Strings are immutable objects, so concatenation doesn't simply add the new String to the end of the existing string. Instead, in each loop iteration, the first String is converted to an intermediate object type, the second string is appended, and then the intermediate object is converted back to a String. Further, performance of these intermediate operations degrades as the String gets longer. Therefore, the use of StringBuilder is preferred.

**Noncompliant Code Example**
```java
String str = "";
for (int i = 0; i < arrayOfStrings.length ; ++i) {
  str = str + arrayOfStrings[i];
}


```
**Compliant Solution**
```java
StringBuilder bld = new StringBuilder();
  for (int i = 0; i < arrayOfStrings.length; ++i) {
    bld.append(arrayOfStrings[i]);
  }
  String str = bld.toString();
```
#### Rule 343: Maps with keys that are enum values should be replaced with EnumMap
##### Quality Category: Code Smell
When all the keys of a Map are values from the same enum, the Map can be replaced with an EnumMap, which can be much more efficient than other sets because the underlying data structure is a simple array.

**Noncompliant Code Example**
```java
public class MyClass {

  public enum COLOR {
    RED, GREEN, BLUE, ORANGE;
  }

  public void mapMood() {
    Map<COLOR, String> moodMap = new HashMap<COLOR, String> ();
  }
}


```
**Compliant Solution**
```java
public class MyClass {

  public enum COLOR {
    RED, GREEN, BLUE, ORANGE;
  }

  public void mapMood() {
    EnumMap<COLOR, String> moodMap = new EnumMap<> (COLOR.class);
  }
}
```
#### Rule 344: Lambdas should be replaced with method references
##### Quality Category: Code Smell
Method/constructor references are more compact and readable than using lambdas, and are therefore preferred. Similarly, null checks can be replaced with references to the Objects::isNull and Objects::nonNull methods.

Note that this rule is automatically disabled when the project's sonar.java.source is lower than 8.

**Noncompliant Code Example**
```java
class A {
  void process(List<A> list) {
    list.stream()
      .map(a -> a.<String>getObject())
      .forEach(a -> { System.out.println(a); });
  }

  <T> T getObject() {
    return null;
  }
}


```
**Compliant Solution**
```java
class A {
  void process(List<A> list) {
    list.stream()
      .map(A::<String>getObject)
      .forEach(System.out::println);
  }

  <T> T getObject() {
    return null;
  }
}
```
#### Rule 345: Parentheses should be removed from a single lambda input parameter when its type is inferred
##### Quality Category: Code Smell
There are two possible syntaxes for a lambda having only one input parameter with an inferred type: with and without parentheses around that single parameter. The simpler syntax, without parentheses, is more compact and readable than the one with parentheses, and is therefore preferred.

Note that this rule is automatically disabled when the project's sonar.java.source is lower than 8.

**Noncompliant Code Example**
```java
(x) -> x * 2


```
**Compliant Solution**
```java
x -> x * 2
```
#### Rule 346: Abstract classes without fields should be converted to interfaces
##### Quality Category: Code Smell
With Java 8's "default method" feature, any abstract class without direct or inherited field should be converted into an interface. However, this change may not be appropriate in libraries or other applications where the class is intended to be used as an API.

Note that this rule is automatically disabled when the project's sonar.java.source is lower than 8.

**Noncompliant Code Example**
```java
public abstract class Car {
  public abstract void start(Environment c);

  public void stop(Environment c) {
    c.freeze(this);
  }
}


```
**Compliant Solution**
```java
public interface Car {
  public void start(Environment c);

  public default void stop(Environment c) {
    c.freeze(this);
  }
}
```
#### Rule 347: Lamdbas containing only one statement should not nest this statement in a block
##### Quality Category: Code Smell
There are two ways to write lambdas that contain single statement, but one is definitely more compact and readable than the other.

Note that this rule is automatically disabled when the project's sonar.java.source is lower than 8.

**Noncompliant Code Example**
```java
x -> {System.out.println(x+1);}
(a, b) -> { return a+b; }


```
**Compliant Solution**
```java
x -> System.out.println(x+1)
(a, b) -> a+b    //For return statement, the return keyword should also be dropped
```
#### Rule 348: "Collections.EMPTY_LIST", "EMPTY_MAP", and "EMPTY_SET" should not be used
##### Quality Category: Code Smell
Since the introduction of generics in Java 5, the use of generic types such as List<String> is recommended over the use of raw ones such as List. Assigning a raw type to a generic one is not type safe, and will generate a warning. The old EMPTY_... fields of the Collections class return raw types, whereas the newer empty...() methods return generic ones.

**Noncompliant Code Example**
```java
List<String> collection1 = Collections.EMPTY_LIST;  // Noncompliant
Map<String, String> collection2 = Collections.EMPTY_MAP;  // Noncompliant
Set<String> collection3 = Collections.EMPTY_SET;  // Noncompliant


```
**Compliant Solution**
```java
List<String> collection1 = Collections.emptyList();
Map<String, String> collection2 = Collections.emptyMap();
Set<String> collection3 = Collections.emptySet();
```
#### Rule 349: Local variables should not be declared and then immediately returned or thrown
##### Quality Category: Code Smell
Declaring a variable only to immediately return or throw it is a bad practice.

Some developers argue that the practice improves code readability, because it enables them to explicitly name what is being returned. However, this variable is an internal implementation detail that is not exposed to the callers of the method. The method name should be sufficient for callers to know exactly what will be returned.

**Noncompliant Code Example**
```java
public long computeDurationInMilliseconds() {
  long duration = (((hours * 60) + minutes) * 60 + seconds ) * 1000 ;
  return duration;
}

public void doSomething() {
  RuntimeException myException = new RuntimeException();
  throw myException;
}


```
**Compliant Solution**
```java
public long computeDurationInMilliseconds() {
  return (((hours * 60) + minutes) * 60 + seconds ) * 1000 ;
}

public void doSomething() {
  throw new RuntimeException();
}
```
#### Rule 350: Unused local variables should be removed
##### Quality Category: Code Smell
If a local variable is declared but not used, it is dead code and should be removed. Doing so will improve maintainability because developers will not wonder what the variable is used for.

**Noncompliant Code Example**
```java
public int numberOfMinutes(int hours) {
  int seconds = 0;   // seconds is never used
  return hours * 60;
}


```
**Compliant Solution**
```java
public int numberOfMinutes(int hours) {
  return hours * 60;
}
```
#### Rule 351: Private fields only used as local variables in methods should become local variables
##### Quality Category: Code Smell
When the value of a private field is always assigned to in a class' methods before being read, then it is not being used to store class information. Therefore, it should become a local variable in the relevant methods to prevent any misunderstanding.

**Noncompliant Code Example**
```java
public class Foo {
  private int a;
  private int b;

  public void doSomething(int y) {
    a = y + 5;
    ...
    if(a == 0) {
      ...
    }
    ...
  }

  public void doSomethingElse(int y) {
    b = y + 3;
    ...
  }
}


```
**Compliant Solution**
```java
public class Foo {

  public void doSomething(int y) {
    int a = y + 5;
    ...
    if(a == 0) {
      ...
    }
  }

  public void doSomethingElse(int y) {
    int b = y + 3;
    ...
  }
}


```
**Exceptions**
```java

This rule doesn't raise any issue on annotated field.
```
#### Rule 352: Loops should not contain more than a single "break" or "continue" statement
##### Quality Category: Code Smell
Restricting the number of break and continue statements in a loop is done in the interest of good structured programming.

One break and continue statement is acceptable in a loop, since it facilitates optimal coding. If there is more than one, the code should be refactored to increase readability.

**Noncompliant Code Example**
```java
for (int i = 1; i <= 10; i++) {     // Noncompliant - 2 continue - one might be tempted to add some logic in between
  if (i % 2 == 0) {
    continue;
  }

  if (i % 3 == 0) {
    continue;
  }

  System.out.println("i = " + i);
}
```
#### Rule 353: Declarations should use Java collection interfaces such as "List" rather than specific implementation classes such as "LinkedList"
##### Quality Category: Code Smell
The purpose of the Java Collections API is to provide a well defined hierarchy of interfaces in order to hide implementation details.

Implementing classes must be used to instantiate new collections, but the result of an instantiation should ideally be stored in a variable whose type is a Java Collection interface.

This rule raises an issue when an implementation class:

 is returned from a public method.
 is accepted as an argument to a public method.
 is exposed as a public member.
**Noncompliant Code Example**
```java
public class Employees {
  private HashSet<Employee> employees = new HashSet<Employee>();  // Noncompliant - "employees" should have type "Set" rather than "HashSet"

  public HashSet<Employee> getEmployees() {                       // Noncompliant
    return employees;
  }
}


```
**Compliant Solution**
```java
public class Employees {
  private Set<Employee> employees = new HashSet<Employee>();      // Compliant

  public Set<Employee> getEmployees() {                           // Compliant
    return employees;
  }
}
```
#### Rule 354: "switch" statements should have at least 3 "case" clauses
##### Quality Category: Code Smell
switch statements are useful when there are many different cases depending on the value of the same expression.

For just one or two cases however, the code will be more readable with if statements.

**Noncompliant Code Example**
```java
switch (variable) {
  case 0:
    doSomething();
    break;
  default:
    doSomethingElse();
    break;
}


```
**Compliant Solution**
```java
if (variable == 0) {
  doSomething();
} else {
  doSomethingElse();
}


*See*

 MISRA C:2004, 15.5 - Every switch statement shall have at least one case clause.
 MISRA C++:2008, 6-4-8 - Every switch statement shall have at least one case-clause.
 MISRA C:2012, 16.6 - Every switch statement shall have at least two switch-clauses
#### Rule 355: A "while" loop should be used instead of a "for" loop
##### Quality Category: Code Smell
When only the condition expression is defined in a for loop, and the initialization and increment expressions are missing, a while loop should be used instead to increase readability.

**Noncompliant Code Example**
```java
for (;condition;) { /*...*/ }


```
**Compliant Solution**
```java
while (condition) { /*...*/ }
```
#### Rule 356: The default unnamed package should not be used
##### Quality Category: Code Smell
According to the Java Language Specification:

Unnamed packages are provided by the Java platform principally for convenience when developing small or temporary applications or when just beginning development.

To enforce this best practice, classes located in default package can no longer be accessed from named ones since Java 1.4.

**Noncompliant Code Example**
```java
public class MyClass { /* ... */ }


```
**Compliant Solution**
```java
package org.example;

public class MyClass{ /* ... */ }
```
#### Rule 357: "equals(Object obj)" should be overridden along with the "compareTo(T obj)" method
##### Quality Category: Code Smell
According to the Java Comparable.compareTo(T o) documentation:

It is strongly recommended, but not strictly required that (x.compareTo(y)==0) == (x.equals(y)).

Generally speaking, any class that implements the Comparable interface and violates this condition should clearly indicate this fact.

The recommended language is "Note: this class has a natural ordering that is inconsistent with equals."

If this rule is violated, weird and unpredictable failures can occur.

For example, in Java 5 the PriorityQueue.remove() method relied on compareTo(), but since Java 6 it has relied on equals().

**Noncompliant Code Example**
```java
public class Foo implements Comparable<Foo> {
  @Override
  public int compareTo(Foo foo) { /* ... */ }      // Noncompliant as the equals(Object obj) method is not overridden
}


```
**Compliant Solution**
```java
public class Foo implements Comparable<Foo> {
  @Override
  public int compareTo(Foo foo) { /* ... */ }      // Compliant

  @Override
  public boolean equals(Object obj) { /* ... */ }
}
```
#### Rule 358: Package names should comply with a naming convention
##### Quality Category: Code Smell
Shared coding conventions allow teams to collaborate efficiently. This rule checks that all package names match a provided regular expression.

**Noncompliant Code Example**
```java

With the default regular expression ^[a-z_]+(\.[a-z_][a-z0-9_]*)*$:

package org.exAmple; // Noncompliant


```
**Compliant Solution**
```java
package org.example;
```
#### Rule 359: Nested code blocks should not be used
##### Quality Category: Code Smell
Nested code blocks can be used to create a new scope and restrict the visibility of the variables defined inside it. Using this feature in a method typically indicates that the method has too many responsibilities, and should be refactored into smaller methods.

**Noncompliant Code Example**
```java
public void evaluate(int operator) {
  switch (operator) {
    /* ... */
    case ADD: {                                // Noncompliant - nested code block '{' ... '}'
        int a = stack.pop();
        int b = stack.pop();
        int result = a + b;
        stack.push(result);
        break;
      }
    /* ... */
  }
}


```
**Compliant Solution**
```java
public void evaluate(int operator) {
  switch (operator) {
    /* ... */
    case ADD:                                  // Compliant
      evaluateAdd();
      break;
    /* ... */
  }
}

private void evaluateAdd() {
  int a = stack.pop();
  int b = stack.pop();
  int result = a + b;
  stack.push(result);
}
```
#### Rule 360: Array designators "[]" should be on the type, not the variable
##### Quality Category: Code Smell
Array designators should always be located on the type for better code readability. Otherwise, developers must look both at the type and the variable name to know whether or not a variable is an array.

**Noncompliant Code Example**
```java
int matrix[][];   // Noncompliant
int[] matrix[];   // Noncompliant


```
**Compliant Solution**
```java
int[][] matrix;   // Compliant
```
#### Rule 361: Array designators "[]" should be located after the type in method signatures
##### Quality Category: Code Smell
According to the Java Language Specification:

For compatibility with older versions of the Java SE platform,

the declaration of a method that returns an array is allowed to place (some or all of) the empty bracket pairs that form the declaration of the array type after the formal parameter list.

This obsolescent syntax should not be used in new code.

**Noncompliant Code Example**
```java
public int getVector()[] { /* ... */ }    // Noncompliant

public int[] getMatrix()[] { /* ... */ }  // Noncompliant


```
**Compliant Solution**
```java
public int[] getVector() { /* ... */ }

public int[][] getMatrix() { /* ... */ }
```
#### Rule 362: Type parameter names should comply with a naming convention
##### Quality Category: Code Smell
Shared naming conventions make it possible for a team to collaborate efficiently. Following the established convention of single-letter type parameter names helps users and maintainers of your code quickly see the difference between a type parameter and a poorly named class.

This rule check that all type parameter names match a provided regular expression. The following code snippets use the default regular expression.

**Noncompliant Code Example**
```java
public class MyClass<TYPE> { // Noncompliant
  <TYPE> void method(TYPE t) { // Noncompliant
  }
}


```
**Compliant Solution**
```java
public class MyClass<T> {
  <T> void method(T t) {
  }
}
```
#### Rule 363: Overriding methods should do more than simply call the same method in the super class
##### Quality Category: Code Smell
Overriding a method just to call the same method from the super class without performing any other actions is useless and misleading. The only time this is justified is in final overriding methods, where the effect is to lock in the parent class behavior. This rule ignores such overrides of equals, hashCode and toString.

**Noncompliant Code Example**
```java
public void doSomething() {
  super.doSomething();
}

@Override
public boolean isLegal(Action action) {
  return super.isLegal(action);
}


```
**Compliant Solution**
```java
@Override
public boolean isLegal(Action action) {         // Compliant - not simply forwarding the call
  return super.isLegal(new Action(/* ... */));
}

@Id
@Override
public int getId() {                            // Compliant - there is annotation different from @Override
  return super.getId();
}
```
#### Rule 364: Classes that override "clone" should be "Cloneable" and call "super.clone()"
##### Quality Category: Code Smell
Cloneable is the marker Interface that indicates that clone() may be called on an object. Overriding clone() without implementing Cloneable can be useful if you want to control how subclasses clone themselves, but otherwise, it's probably a mistake.

The usual convention for Object.clone() according to Oracle's Javadoc is:

x.clone() != x
x.clone().getClass() == x.getClass()
x.clone().equals\(x\)

Obtaining the object that will be returned by calling super.clone() helps to satisfy those invariants:

super.clone() returns a new object instance
super.clone() returns an object of the same type as the one clone() was called on
Object.clone() performs a shallow copy of the object's state
**Noncompliant Code Example**
```java
class BaseClass {  // Noncompliant; should implement Cloneable
  @Override
  public Object clone() throws CloneNotSupportedException {    // Noncompliant; should return the super.clone() instance
    return new BaseClass();
  }
}

class DerivedClass extends BaseClass implements Cloneable {
  /* Does not override clone() */

  public void sayHello() {
    System.out.println("Hello, world!");
  }
}

class Application {
  public static void main(String[] args) throws Exception {
    DerivedClass instance = new DerivedClass();
    ((DerivedClass) instance.clone()).sayHello();              // Throws a ClassCastException because invariant #2 is violated
  }
}


```
**Compliant Solution**
```java
class BaseClass implements Cloneable {
  @Override
  public Object clone() throws CloneNotSupportedException {    // Compliant
    return super.clone();
  }
}

class DerivedClass extends BaseClass implements Cloneable {
  /* Does not override clone() */

  public void sayHello() {
    System.out.println("Hello, world!");
  }
}

class Application {
  public static void main(String[] args) throws Exception {
    DerivedClass instance = new DerivedClass();
    ((DerivedClass) instance.clone()).sayHello();              // Displays "Hello, world!" as expected. Invariant #2 is satisfied
  }
}


*See*

MITRE, CWE-580 - clone() Method Without super.clone()
CERT, MET53-J. - Ensure that the clone() method calls super.clone()
#### Rule 365: Public constants and fields initialized at declaration should be "static final" rather than merely "final"
##### Quality Category: Code Smell
Making a public constant just final as opposed to static final leads to duplicating its value for every instance of the class, uselessly increasing the amount of memory required to execute the application.

Further, when a non-public, final field isn't also static, it implies that different instances can have different values. However, initializing a non-static final field in its declaration forces every instance to have the same value. So such fields should either be made static or initialized in the constructor.

**Noncompliant Code Example**
```java
public class Myclass {
  public final int THRESHOLD = 3;
}


```
**Compliant Solution**
```java
public class Myclass {
  public static final int THRESHOLD = 3;    // Compliant
}


```
**Exceptions**
```java

No issues are reported on final fields of inner classes whose type is not a primitive or a String. Indeed according to the Java specification:

An inner class is a nested class that is not explicitly or implicitly declared static. Inner classes may not declare static initializers (§8.7) or member interfaces. Inner classes may not declare static members, unless they are compile-time constant fields (§15.28).
```
#### Rule 366: Local variable and method parameter names should comply with a naming convention
##### Quality Category: Code Smell
Shared naming conventions allow teams to collaborate effectively. This rule raises an issue when a local variable or function parameter name does not match the provided regular expression.

**Noncompliant Code Example**
```java

With the default regular expression ^[a-z][a-zA-Z0-9]*$:

public void doSomething(int my_param) {
  int LOCAL;
  ...
}


```
**Compliant Solution**
```java
public void doSomething(int myParam) {
  int local;
  ...
}


```
**Exceptions**
```java

Loop counters are ignored by this rule.

for (int i_1 = 0; i_1 < limit; i_1++) {  // Compliant
  // ...
}


as well as one-character catch variables:

try {
//...
} catch (Exception e) { // Compliant
}

```
#### Rule 367: Exception classes should be immutable
##### Quality Category: Code Smell

```
**Exceptions**
```java are meant to represent the application's state at the point at which an error occurred.

Making all fields in an Exception class final ensures that this state:

 Will be fully defined at the same time the Exception is instantiated.
 Won't be updated or corrupted by a questionable error handler.

This will enable developers to quickly understand what went wrong.

**Noncompliant Code Example**
```java
public class MyException extends Exception {

  private int status;                               // Noncompliant

  public MyException(String message) {
    super(message);
  }

  public int getStatus() {
    return status;
  }

  public void setStatus(int status) {
    this.status = status;
  }

}


```
**Compliant Solution**
```java
public class MyException extends Exception {

  private final int status;

  public MyException(String message, int status) {
    super(message);
    this.status = status;
  }

  public int getStatus() {
    return status;
  }

}

```
#### Rule 368: Field names should comply with a naming convention
##### Quality Category: Code Smell
Sharing some naming conventions is a key point to make it possible for a team to efficiently collaborate. This rule allows to check that field names match a provided regular expression.

**Noncompliant Code Example**
```java

With the default regular expression ^[a-z][a-zA-Z0-9]*$:

class MyClass {
   private int my_field;
}


```
**Compliant Solution**
```java
class MyClass {
   private int myField;
}
```
#### Rule 369: Primitive wrappers should not be instantiated only for "toString" or "compareTo" calls
##### Quality Category: Code Smell
Creating temporary primitive wrapper objects only for String conversion or the use of the compareTo method is inefficient.

Instead, the static toString() or compare method of the primitive wrapper class should be used.

**Noncompliant Code Example**
```java
new Integer(myInteger).toString();  // Noncompliant


```
**Compliant Solution**
```java
Integer.toString(myInteger);        // Compliant
```
#### Rule 370: Case insensitive string comparisons should be made without intermediate upper or lower casing
##### Quality Category: Code Smell
Using toLowerCase() or toUpperCase() to make case insensitive comparisons is inefficient because it requires the creation of temporary, intermediate String objects.

**Noncompliant Code Example**
```java
boolean result1 = foo.toUpperCase().equals(bar);             // Noncompliant
boolean result2 = foo.equals(bar.toUpperCase());             // Noncompliant
boolean result3 = foo.toLowerCase().equals(bar.LowerCase()); // Noncompliant


```
**Compliant Solution**
```java
boolean result = foo.equalsIgnoreCase(bar);                  // Compliant
```
#### Rule 371: Collection.isEmpty() should be used to test for emptiness
##### Quality Category: Code Smell
Using Collection.size() to test for emptiness works, but using Collection.isEmpty() makes the code more readable and can be more performant. The time complexity of any isEmpty() method implementation should be O(1) whereas some implementations of size() can be O(n).

**Noncompliant Code Example**
```java
if (myCollection.size() == 0) {  // Noncompliant
  /* ... */
}


```
**Compliant Solution**
```java
if (myCollection.isEmpty()) {
  /* ... */
}
```
#### Rule 372: String.valueOf() should not be appended to a String
##### Quality Category: Code Smell
Appending String.valueOf() to a String decreases the code readability.

The argument passed to String.valueOf() should be directly appended instead.

**Noncompliant Code Example**
```java
public void display(int i){
  System.out.println("Output is " + String.valueOf(i));    // Noncompliant
}


```
**Compliant Solution**
```java
public void display(int i){
  System.out.println("Output is " + i);                    // Compliant
}
```
#### Rule 373: Interface names should comply with a naming convention
##### Quality Category: Code Smell
Sharing some naming conventions is a key point to make it possible for a team to efficiently collaborate. This rule allows to check that all interface names match a provided regular expression.

**Noncompliant Code Example**
```java

With the default regular expression ^[A-Z][a-zA-Z0-9]*$:

public interface myInterface {...} // Noncompliant


```
**Compliant Solution**
```java
public interface MyInterface {...}
```
#### Rule 374: Return of boolean expressions should not be wrapped into an "if-then-else" statement
##### Quality Category: Code Smell
Return of boolean literal statements wrapped into if-then-else ones should be simplified.

Similarly, method invocations wrapped into if-then-else differing only from boolean literals should be simplified into a single invocation.

**Noncompliant Code Example**
```java
boolean foo(Object param) {
  if (expression) { // Noncompliant
    bar(param, true, "qix");
  } else {
    bar(param, false, "qix");
  }

  if (expression) {  // Noncompliant
    return true;
  } else {
    return false;
  }
}


```
**Compliant Solution**
```java
boolean foo(Object param) {
  bar(param, expression, "qix");

  return expression;
}
```
#### Rule 375: Boolean literals should not be redundant
##### Quality Category: Code Smell
Redundant Boolean literals should be removed from expressions to improve readability.

**Noncompliant Code Example**
```java
if (booleanMethod() == true) { /* ... */ }
if (booleanMethod() == false) { /* ... */ }
if (booleanMethod() || false) { /* ... */ }
doSomething(!false);
doSomething(booleanMethod() == true);

booleanVariable = booleanMethod() ? true : false;
booleanVariable = booleanMethod() ? true : exp;
booleanVariable = booleanMethod() ? false : exp;
booleanVariable = booleanMethod() ? exp : true;
booleanVariable = booleanMethod() ? exp : false;


```
**Compliant Solution**
```java
if (booleanMethod()) { /* ... */ }
if (!booleanMethod()) { /* ... */ }
if (booleanMethod()) { /* ... */ }
doSomething(true);
doSomething(booleanMethod());

booleanVariable = booleanMethod();
booleanVariable = booleanMethod() || exp;
booleanVariable = !booleanMethod() && exp;
booleanVariable = !booleanMethod() || exp;
booleanVariable = booleanMethod() && exp;
```
#### Rule 376: Empty statements should be removed
##### Quality Category: Code Smell
Empty statements, i.e. ;, are usually introduced by mistake, for example because:

 It was meant to be replaced by an actual statement, but this was forgotten.
 There was a typo which lead the semicolon to be doubled, i.e. ;;.
**Noncompliant Code Example**
```java
void doSomething() {
  ;                                                       // Noncompliant - was used as a kind of TODO marker
}

void doSomethingElse() {
  System.out.println("Hello, world!");;                     // Noncompliant - double ;
  ...
}


```
**Compliant Solution**
```java
void doSomething() {}

void doSomethingElse() {
  System.out.println("Hello, world!");
  ...
  for (int i = 0; i < 3; i++) ; // compliant if unique statement of a loop
  ...
}


*See*

 MISRA C:2004, 14.3 - Before preprocessing, a null statement shall only occur on a line by itself; it may be followed by a comment provided that the first character following the null statement is a white-space character.
 MISRA C++:2008, 6-2-3 - Before preprocessing, a null statement shall only occur on a line by itself; it may be followed by a comment, provided that the first character following the null statement is a white-space character.
CERT, MSC12-C. - Detect and remove code that has no effect or is never executed
CERT, MSC51-J. - Do not place a semicolon immediately following an if, for, or while condition
CERT, EXP15-C. - Do not place a semicolon on the same line as an if, for, or while statement
#### Rule 377: URIs should not be hardcoded
##### Quality Category: Code Smell
Hard coding a URI makes it difficult to test a program: path literals are not always portable across operating systems, a given absolute path may not exist on a specific test environment, a specified Internet URL may not be available when executing the tests, production environment filesystems usually differ from the development environment, ...etc. For all those reasons, a URI should never be hard coded. Instead, it should be replaced by customizable parameter.

Further even if the elements of a URI are obtained dynamically, portability can still be limited if the path-delimiters are hard-coded.

This rule raises an issue when URI's or path delimiters are hard coded.

**Noncompliant Code Example**
```java
public class Foo {
  public Collection<User> listUsers() {
    File userList = new File("/home/mylogin/Dev/users.txt"); // Non-Compliant
    Collection<User> users = parse(userList);
    return users;
  }
}


```
**Compliant Solution**
```java
public class Foo {
  // Configuration is a class that returns customizable properties: it can be mocked to be injected during tests.
  private Configuration config;
  public Foo(Configuration myConfig) {
    this.config = myConfig;
  }
  public Collection<User> listUsers() {
    // Find here the way to get the correct folder, in this case using the Configuration object
    String listingFolder = config.getProperty("myApplication.listingFolder");
    // and use this parameter instead of the hard coded path
    File userList = new File(listingFolder, "users.txt"); // Compliant
    Collection<User> users = parse(userList);
    return users;
  }
}


*See*

CERT, MSC03-J. - Never hard code sensitive information
#### Rule 378: Class names should comply with a naming convention
##### Quality Category: Code Smell
Shared coding conventions allow teams to collaborate effectively. This rule allows to check that all class names match a provided regular expression.

**Noncompliant Code Example**
```java

With default provided regular expression ^[A-Z][a-zA-Z0-9]*$:

class my_class {...}


```
**Compliant Solution**
```java
class MyClass {...}
```
#### Rule 379: Method names should comply with a naming convention
##### Quality Category: Code Smell
Shared naming conventions allow teams to collaborate efficiently. This rule checks that all method names match a provided regular expression.

**Noncompliant Code Example**
```java

With default provided regular expression ^[a-z][a-zA-Z0-9]*$:

public int DoSomething(){...}


```
**Compliant Solution**
```java
public int doSomething(){...}


```
**Exceptions**
```java

Overriding methods are excluded.

@Override
public int Do_Something(){...}

```
#### Rule 380: Track uses of "TODO" tags
##### Quality Category: Code Smell
TODO tags are commonly used to mark places where some more code is required, but which the developer wants to implement later.

Sometimes the developer will not have the time or will simply forget to get back to that tag.

This rule is meant to track those tags and to ensure that they do not go unnoticed.

**Noncompliant Code Example**
```java
void doSomething() {
  // TODO
}


*See*

MITRE, CWE-546 - Suspicious Comment
#### Rule 381: Deprecated code should be removed
##### Quality Category: Code Smell
This rule is meant to be used as a way to track code which is marked as being deprecated. Deprecated code should eventually be removed.

**Noncompliant Code Example**
```java
class Foo {
  /**
   * @deprecated
   */
  public void foo() {    // Noncompliant
  }

  @Deprecated            // Noncompliant
  public void bar() {
  }

  public void baz() {    // Compliant
  }
}
```
#### Rule 382: Security constraints should be defined
##### Quality Category: Vulnerability
Websphere, Tomcat, and JBoss web servers allow the definition of role-based access to servlets. It may not be granular enough for your purposes, but it's a start, and should be used at least as a base.

This rule raises an issue when a web.xml file has no <security-constraint> elements.


*See*

MITRE, CWE-284 - Improper Access Control
 OWASP Top 10 2017 Category A5 - Broken Access Control
#### Rule 383: Custom resources should be closed
##### Quality Category: Bug
Leaking resources in an application is never a good idea, as it can lead to memory issues, and even the crash of the application. This rule template allows you to specify which constructions open a resource and how it is closed in order to raise issue within a method scope when custom resources are leaked.


*See*
 also
 {rule:squid:S2095} - Resources should be closed
#### Rule 384: EJB interceptor exclusions should be declared as annotations
##### Quality Category: Code Smell
Exclusions for default interceptors can be declared either in xml or as class annotations. Since annotations are more visible to maintainers, they are preferred.

**Noncompliant Code Example**
```java
<assembly-descriptor>
      <interceptor-binding>
         <ejb-name>MyExcludedClass</ejb-name>
         <exclude-default-interceptors>true</exclude-default-interceptors> <!-- Noncompliant -->
         <exclude-class-interceptors>true</exclude-class-interceptors> <!-- Noncomopliant -->
         <method>
           <method-name>doTheThing</method-name>
         </method>
      </interceptor-binding>

</assembly-descriptor>


```
**Compliant Solution**
```java
@ExcludeDefaultInterceptors
public class MyExcludedClass implements MessageListener
{

  @ExcludeClassInterceptors
  @ExcludeDefaultInterceptors
  public void doTheThing() {
    // ...
  }
```
#### Rule 385: Threads should not be started in constructors
##### Quality Category: Code Smell
The problem with invoking Thread.start() in a constructor is that you'll have a confusing mess on your hands if the class is ever extended because the superclass' constructor will start the thread before the child class has truly been initialized.

This rule raises an issue any time start is invoked in the constructor of a non-final class.

**Noncompliant Code Example**
```java
public class MyClass {

  Thread thread = null;

  public MyClass(Runnable runnable) {
    thread = new Thread(runnable);
    thread.start(); // Noncompliant
  }
}


*See*

CERT, TSM02-J. - Do not use background threads during class initialization
#### Rule 386: "main" should not "throw" anything
##### Quality Category: Code Smell
There's no reason for a main method to throw anything. After all, what's going to catch it?

Instead, the method should itself gracefully handle any exceptions that may bubble up to it, attach as much contextual information as possible, and perform whatever logging or user communication is necessary, and exit with a non-zero (i.e. non-success) exit code if necessary.

**Noncompliant Code Example**
```java
public static void main(String args[]) throws Exception { // Noncompliant
  doSomething();


```
**Compliant Solution**
```java
public static void main(String args[]) {
 try {
    doSomething();
  } catch (Throwable t) {
    log.error(t);
    System.exit(1);  // Default exit code, 0, indicates success. Non-zero value means failure.
  }
}
```
#### Rule 387: Track lack of copyright and license headers
##### Quality Category: Code Smell
Each source file should start with a header stating file ownership and the license which must be used to distribute the application.

This rule must be fed with the header text that is expected at the beginning of every file.

Compliant Solution
/*
 * SonarQube, open source software quality management tool.
 * Copyright (C) 2008-2013 SonarSource
 * mailto:contact AT sonarsource DOT com
 *
 * SonarQube is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * SonarQube is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  
*See*
 the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#### Rule 388: Octal values should not be used
##### Quality Category: Code Smell
Integer literals starting with a zero are octal rather than decimal values. While using octal values is fully supported, most developers do not have experience with them. They may not recognize octal values as such, mistaking them instead for decimal values.

**Noncompliant Code Example**
```java
int myNumber = 010;   // Noncompliant. myNumber will hold 8, not 10 - was this really expected?


```
**Compliant Solution**
```java
int myNumber = 8;


*See*

 MISRA C:2004, 7.1 - Octal constants (other than zero) and octal escape sequences shall not be used.
 MISRA C++:2008, 2-13-2 - Octal constants (other than zero) and octal escape sequences (other than "\0") shall not be used
 MISRA C:2012, 7.1 - Octal constants shall not be used
CERT, DCL18-C. - Do not begin integer constants with 0 when specifying a decimal value
CERT, DCL50-J. - Use visually distinct identifiers
#### Rule 389: Exit methods should not be called
##### Quality Category: Code Smell
Calling System.exit(int status) or Rutime.getRuntime().exit(int status) calls the shutdown hooks and shuts downs the entire Java virtual machine. Calling Runtime.getRuntime().halt(int) does an immediate shutdown, without calling the shutdown hooks, and skipping finalization.

Each of these methods should be used with extreme care, and only when the intent is to stop the whole Java process. For instance, none of them should be called from applications running in a J2EE container.

**Noncompliant Code Example**
```java
System.exit(0);
Runtime.getRuntime().exit(0);
Runtime.getRuntime().halt(0);


```
**Exceptions**
```java

These methods are ignored inside main.


*See*

MITRE, CWE-382 - Use of System.exit()
CERT, ERR09-J. - Do not allow untrusted code to terminate the JVM

#### Rule 390: Members of Spring components should be injected
##### Quality Category: Vulnerability
Spring @Controller, @Service, and @Repository classes are singletons by default, meaning only one instance of the class is ever instantiated in the application. Typically such a class might have a few static members, such as a logger, but all non-static members should be managed by Spring. That is, they should have one of these annotations: @Resource, @Inject, @Autowired or @Value.

Having non-injected members in one of these classes could indicate an attempt to manage state. Because they are singletons, such an attempt is almost guaranteed to eventually expose data from User1's session to User2.

This rule raises an issue when a singleton @Controller, @Service, or @Repository has non-static members that are not annotated with one of:

org.springframework.beans.factory.annotation.Autowired
org.springframework.beans.factory.annotation.Value
javax.annotation.Inject
javax.annotation.Resource
**Noncompliant Code Example**
```java
@Controller
public class HelloWorld {

  private String name = null;

  @RequestMapping("/greet", method = GET)
  public String greet(String greetee) {

    if (greetee != null) {
      this.name = greetee;
    }

    return "Hello " + this.name;  // if greetee is null, you see the previous user's data
  }
}


*See*

 OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
#### Rule 391: Cypher Block Chaining IV's should be random and unique
##### Quality Category: Vulnerability
In encryption, when Cipher Block Chaining (CBC) is used, the Initialization Vector (IV) must be random and unpredictable. Otherwise, the encrypted value is vulnerable to crypto-analysis attacks such as the "Chosen-Plaintext Attack".

An IV value should be associated to one, and only one encryption cycle, because the IV's purpose is to ensure that the same plaintext encrypted twice will yield two different ciphertexts.

To that end, IV's should be:

 random
 unpredictable
 publishable (IV's frequently are published)
 authenticated, along with the ciphertext, with a Message Authentication Code (MAC)

This rule raises an issue when the IV is:

 hard-coded
 created using java.util.Random rather than java.security.SecureRandom.
**Noncompliant Code Example**
```java
public class MyCbcClass {

  public String applyCBC(String strKey, String plainText) {
    byte[] bytesIV = "7cVgr5cbdCZVw5WY".getBytes("UTF-8");

    /* KEY + IV setting */
    IvParameterSpec iv = new IvParameterSpec(bytesIV);
    SecretKeySpec skeySpec = new SecretKeySpec(strKey.getBytes("UTF-8"), "AES");

    /* Ciphering */
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
    cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);  // Noncompliant because IV hard coded and cannot vary with each ciphering round
    byte[] encryptedBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
    return DatatypeConverter.printBase64Binary(bytesIV) // IV is typically published
            + ";" + DatatypeConverter.printBase64Binary(encryptedBytes);
  }
}


```
**Compliant Solution**
```java
public class MyCbcClass {

  SecureRandom random = new SecureRandom();

  public String applyCBC(String strKey, String plainText) {
    byte[] bytesIV = new byte[16];
    random.nextBytes(bytesIV);

    /* KEY + IV setting */
    IvParameterSpec iv = new IvParameterSpec(bytesIV);
    SecretKeySpec skeySpec = new SecretKeySpec(strKey.getBytes("UTF-8"), "AES");

    /* Ciphering */
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
    cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
    byte[] encryptedBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
    return DatatypeConverter.printBase64Binary(bytesIV)
            + ";" + DatatypeConverter.printBase64Binary(encryptedBytes);
  }
}


*See*

MITRE, CWE-330 - Use of Insufficiently Random Values
 OWASP Top 10 2017 Category A6 - Security Misconfiguration
 Derived from FindSecBugs rule STATIC_IV
#### Rule 392: Classes should not be loaded dynamically
##### Quality Category: Vulnerability
Dynamically loaded classes could contain malicious code executed by a static class initializer. I.E. you wouldn't even have to instantiate or explicitly invoke methods on such classes to be vulnerable to an attack.

This rule raises an issue for each use of dynamic class loading.

**Noncompliant Code Example**
```java
String className = System.getProperty("messageClassName");
Class clazz = Class.forName(className);  // Noncompliant


*See*

 OWASP Top 10 2017 Category A1 - Injection
#### Rule 393: HTTP referers should not be relied on
##### Quality Category: Vulnerability
The fields in an HTTP request are putty in the hands of an attacker, and you cannot rely on them to tell you the truth about anything. While it may be safe to store such values after they have been neutralized, decisions should never be made based on their contents.

This rule flags uses of the referer header field.

**Noncompliant Code Example**
```java
public class MyServlet extends HttpServlet {
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
    String referer = request.getHeader("referer");  // Noncompliant
    if(isTrustedReferer(referer)){
      //..
    }
    //...
  }
}


*See*

MITRE, CWE-807 - Reliance on Untrusted Inputs in a Security Decision
MITRE, CWE-293 - Using Referer Field for Authentication
 OWASP Top 10 2017 Category A2 - Broken Authentication
SANS Top 25 - Porous Defenses
#### Rule 394: SHA-1 and Message-Digest hash algorithms should not be used in secure contexts
##### Quality Category: Vulnerability
The MD5 algorithm and its successor, SHA-1, are no longer considered secure, because it is too easy to create hash collisions with them. That is, it takes too little computational effort to come up with a different input that produces the same MD5 or SHA-1 hash, and using the new, same-hash value gives an attacker the same access as if he had the originally-hashed value. This applies as well to the other Message-Digest algorithms: MD2, MD4, MD6, HAVAL-128, HMAC-MD5, DSA (which uses SHA-1), RIPEMD, RIPEMD-128, RIPEMD-160, HMACRIPEMD160.

The following APIs are tracked for use of obsolete crypto algorithms:

* java.security.AlgorithmParameters (JDK)

* java.security.AlgorithmParameterGenerator (JDK)

* java.security.MessageDigest (JDK)

* java.security.KeyFactory (JDK)

* java.security.KeyPairGenerator (JDK)

* java.security.Signature (JDK)

* javax.crypto.Mac (JDK)

* javax.crypto.KeyGenerator (JDK)

* org.apache.commons.codec.digest.DigestUtils (Apache Commons Codec)

* com.google.common.hash.Hashing (Guava)

* org.springframework.security.authentication.encoding.ShaPasswordEncoder (Spring Security 4.2.x)

* org.springframework.security.authentication.encoding.Md5PasswordEncoder (Spring Security 4.2.x)

* org.springframework.security.crypto.password.LdapShaPasswordEncoder (Spring Security 5.0.x)

* org.springframework.security.crypto.password.Md4PasswordEncoder (Spring Security 5.0.x)

* org.springframework.security.crypto.password.MessageDigestPasswordEncoder (Spring Security 5.0.x)

* org.springframework.security.crypto.password.NoOpPasswordEncoder (Spring Security 5.0.x)

* org.springframework.security.crypto.password.StandardPasswordEncoder (Spring Security 5.0.x)

Consider using safer alternatives, such as SHA-256, SHA-3 or adaptive one way functions like bcrypt or PBKDF2.

**Noncompliant Code Example**
```java
MessageDigest md = MessageDigest.getInstance("SHA1");  // Noncompliant


```
**Compliant Solution**
```java
MessageDigest md = MessageDigest.getInstance("SHA-256");


*See*

MITRE, CWE-328 - Reversible One-Way Hash
MITRE, CWE-327 - Use of a Broken or Risky Cryptographic Algorithm
 OWASP Top 10 2017 Category A6 - Security Misconfiguration
SANS Top 25 - Porous Defenses
SHAttered - The first concrete collision attack against SHA-1.
#### Rule 395: "super.finalize()" should be called at the end of "Object.finalize()" implementations
##### Quality Category: Bug
Overriding the Object.finalize() method must be done with caution to dispose some system resources.

Calling the super.finalize() at the end of this method implementation is highly recommended in case parent implementations must also dispose some system resources.

**Noncompliant Code Example**
```java
protected void finalize() {   // Noncompliant; no call to super.finalize();
  releaseSomeResources();
}

protected void finalize() {
  super.finalize();  // Noncompliant; this call should come last
  releaseSomeResources();
}


```
**Compliant Solution**
```java
protected void finalize() {
  releaseSomeResources();
  super.finalize();
}


*See*

MITRE, CWE-568 - finalize() Method Without super.finalize()
CERT, MET12-J. - Do not use finalizers
#### Rule 396: Equality operators should not be used in "for" loop termination conditions
##### Quality Category: Code Smell
Testing for loop termination using an equality operator (== and !=) is dangerous, because it could set up an infinite loop. Using a broader relational operator instead casts a wider net, and makes it harder (but not impossible) to accidentally write an infinite loop.

**Noncompliant Code Example**
```java
for (int i = 1; i != 10; i += 2)  // Noncompliant. Infinite; i goes from 9 straight to 11.
{
  //...
}


```
**Compliant Solution**
```java
for (int i = 1; i <= 10; i += 2)  // Compliant
{
  //...
}


```
**Exceptions**
```java

Equality operators are ignored if the loop counter is not modified within the body of the loop and either:

 starts below the ending value and is incremented by 1 on each iteration.
 starts above the ending value and is decremented by 1 on each iteration.

Equality operators are also ignored when the test is against null.

for (int i = 0; arr[i] != null; i++) {
  // ...
}

for (int i = 0; (item = arr[i]) != null; i++) {
  // ...
}


*See*

 MISRA C++:2008, 6-5-2
MITRE, CWE-835 - Loop with Unreachable Exit Condition ('Infinite Loop')
CERT, MSC21-C. - Use robust loop termination conditions

#### Rule 397: Spring beans should be considered by "@ComponentScan"
##### Quality Category: Code Smell
Spring beans belonging to packages that are not included in a @ComponentScan configuration will not be accessible in the Spring Application Context. Therefore, it's likely to be a configuration mistake that will be detected by this rule. Note: the @ComponentScan is implicit in the @SpringBootApplication annotation, case in which Spring Boot will auto scan for components in the package containing the Spring Boot main class and its sub-packages.

**Noncompliant Code Example**
```java
@Configuration
@ComponentScan("com.mycompany.app.beans")
public class Application {
...
}

package com.mycompany.app.web;

@Controller
public class MyController { // Noncompliant; MyController belong to "com.mycompany.app.web" while the ComponentScan is looking for beans in "com.mycompany.app.beans" package
...
}


```
**Compliant Solution**
```java
@Configuration
@ComponentScan({"com.mycompany.app.beans","com.mycompany.app.web"})
public class Application {
...
}

package com.mycompany.app.web;

@Controller
public class MyController { // Compliant; "com.mycompany.app.web" is referenced by a @ComponentScan annotated class
...
}
```
#### Rule 398: Number patterns should be regular
##### Quality Category: Code Smell
The use of punctuation characters to separate subgroups in a number can make the number more readable. For instance consider 1,000,000,000 versus 1000000000. But when the grouping is irregular, such as 1,000,00,000; it indicates an error.

This rule raises an issue when underscores (_) are used to break a number into irregular subgroups.

**Noncompliant Code Example**
```java
int duos = 1_00_00;
int million = 1_000_00_000;  // Noncompliant
int thousand = 1000;
int tenThousand = 100_00;  // Noncompliant
```
#### Rule 399: Literal boolean values should not be used in assertions
##### Quality Category: Code Smell
There's no reason to use literal boolean values in assertions. Doing so is at best confusing for maintainers, and at worst a bug.

**Noncompliant Code Example**
```java
Assert.assertTrue(true);  // Noncompliant
assertThat(true).isTrue(); // Noncompliant
```
#### Rule 400: Lazy initialization of "static" fields should be "synchronized"
##### Quality Category: Code Smell
In a multi-threaded situation, un-synchronized lazy initialization of static fields could mean that a second thread has access to a half-initialized object while the first thread is still creating it. Allowing such access could cause serious bugs. Instead. the initialization block should be synchronized.

Similarly, updates of such fields should also be synchronized.

This rule raises an issue whenever a lazy static initialization is done on a class with at least one synchronized method, indicating intended usage in multi-threaded applications.

**Noncompliant Code Example**
```java
private static Properties fPreferences = null;

private static Properties getPreferences() {
        if (fPreferences == null) {
            fPreferences = new Properties(); // Noncompliant
            fPreferences.put("loading", "true");
            fPreferences.put("filterstack", "true");
            readPreferences();
        }
        return fPreferences;
    }
}


```
**Compliant Solution**
```java
private static Properties fPreferences = null;

private static synchronized Properties getPreferences() {
        if (fPreferences == null) {
            fPreferences = new Properties();
            fPreferences.put("loading", "true");
            fPreferences.put("filterstack", "true");
            readPreferences();
        }
        return fPreferences;
    }
}
```
#### Rule 401: Wildcard imports should not be used
##### Quality Category: Code Smell
Blindly importing all the classes in a package clutters the class namespace and could lead to conflicts between classes in different packages with the same name. On the other hand, specifically listing the necessary classes avoids that problem and makes clear which versions were wanted.

**Noncompliant Code Example**
```java
import java.sql.*; // Noncompliant
import java.util.*; // Noncompliant

private Date date; // Date class exists in java.sql and java.util. Which one is this?


```
**Compliant Solution**
```java
import java.sql.Date;
import java.util.List;
import java.util.ArrayList;

private Date date;


```
**Exceptions**
```java

Static imports are ignored by this rule. E.G.

import static java.lang.Math.*;

```
#### Rule 402: Modulus results should not be checked for direct equality
##### Quality Category: Code Smell
When the modulus of a negative number is calculated, the result will either be negative or zero. Thus, comparing the modulus of a variable for equality with a positive number (or a negative one) could result in unexpected results.

**Noncompliant Code Example**
```java
public boolean isOdd(int x) {
  return x % 2 == 1;  // Noncompliant; if x is an odd negative, x % 2 == -1
}


```
**Compliant Solution**
```java
public boolean isOdd(int x) {
  return x % 2 != 0;
}


*See*

CERT, NUM51-J. - Do not assume that the remainder operator always returns a nonnegative result for integral operands
CERT, INT10-C - Do not assume a positive remainder when using the % operator
#### Rule 403: Comparators should be "Serializable"
##### Quality Category: Code Smell
A non-serializable Comparator can prevent an otherwise-Serializable ordered collection from being serializable. Since the overhead to make a Comparator serializable is usually low, doing so can be considered good defensive programming.

**Noncompliant Code Example**
```java
public class FruitComparator implements Comparator<Fruit> {  // Noncompliant
  int compare(Fruit f1, Fruit f2) {...}
  boolean equals(Object obj) {...}
}


```
**Compliant Solution**
```java
public class FruitComparator implements Comparator<Fruit>, Serializable {
  private static final long serialVersionUID = 1;

  int compare(Fruit f1, Fruit f2) {...}
  boolean equals(Object obj) {...}
}
```
#### Rule 404: "Serializable" classes should have a "serialVersionUID"
##### Quality Category: Code Smell
A serialVersionUID field is strongly recommended in all Serializable classes. If you do not provide one, one will be calculated for you by the compiler. The danger in not explicitly choosing the value is that when the class changes, the compiler will generate an entirely new id, and you will be suddenly unable to deserialize (read from file) objects that were serialized with the previous version of the class.

serialVersionUID's should be declared with all of these modifiers: static final long.

**Noncompliant Code Example**
```java
public class Raspberry extends Fruit  // Noncompliant; no serialVersionUID.
        implements Serializable {
  private String variety;

  public Raspberry(Season ripe, String variety) { ...}
  public void setVariety(String variety) {...}
  public String getVarity() {...}
}

public class Raspberry extends Fruit
        implements Serializable {
  private final int serialVersionUID = 1; // Noncompliant; not static & int rather than long


```
**Compliant Solution**
```java
public class Raspberry extends Fruit
        implements Serializable {
  private static final long serialVersionUID = 1;
  private String variety;

  public Raspberry(Season ripe, String variety) { ...}
  public void setVariety(String variety) {...}
  public String getVarity() {...}
}


```
**Exceptions**
```java

Swing and AWT classes, abstract classes, Throwable and its subclasses (
```
**Exceptions**
```java and Errors), and classes marked with @SuppressWarnings("serial") are ignored.


*See*

CERT, SER00-J. - Enable serialization compatibility during class evolution

#### Rule 405: "switch" statements should not be nested
##### Quality Category: Code Smell
Nested switch structures are difficult to understand because you can easily confuse the cases of an inner switch as belonging to an outer statement. Therefore nested switch statements should be avoided.

Specifically, you should structure your code to avoid the need for nested switch statements, but if you cannot, then consider moving the inner switch to another function.

**Noncompliant Code Example**
```java
void foo(int n, int m) {
  switch (n) {
    case 0:
      switch (m) {  // Noncompliant; nested switch
        // ...
      }
    case 1:
      // ...
    default:
      // ...
  }
}


```
**Compliant Solution**
```java
void foo(int n, int m) {
  switch (n) {
    case 0:
      bar(m);
    case 1:
      // ...
    default:
      // ...
  }
}

void bar(int m){
  switch(m) {
    // ...
  }
}
```
#### Rule 406: Constructors should only call non-overridable methods
##### Quality Category: Code Smell
Calling an overridable method from a constructor could result in failures or strange behaviors when instantiating a subclass which overrides the method.

For example:

 The subclass class constructor starts by contract by calling the parent class constructor.
 The parent class constructor calls the method, which has been overridden in the child class.
 If the behavior of the child class method depends on fields that are initialized in the child class constructor, unexpected behavior (like a NullPointerException) can result, because the fields aren't initialized yet.
**Noncompliant Code Example**
```java
public class Parent {

  public Parent () {
    doSomething();  // Noncompliant
  }

  public void doSomething () {  // not final; can be overridden
    ...
  }
}

public class Child extends Parent {

  private String foo;

  public Child(String foo) {
    super(); // leads to call doSomething() in Parent constructor which triggers a NullPointerException as foo has not yet been initialized
    this.foo = foo;
  }

  public void doSomething () {
    System.out.println(this.foo.length());
  }

}


*See*

CERT, MET05-J. - Ensure that constructors do not call overridable methods
CERT, OOP50-CPP. - Do not invoke virtual functions from constructors or destructors
#### Rule 407: @FunctionalInterface annotation should be used to flag Single Abstract Method interfaces
##### Quality Category: Code Smell
A Single Abstract Method (SAM) interface is a Java interface containing only one method. The Java API is full of SAM interfaces, such as java.lang.Runnable, java.awt.event.ActionListener, java.util.Comparator and java.util.concurrent.Callable. SAM interfaces have a special place in Java 8 because they can be implemented using Lambda expressions or Method references.

Using @FunctionalInterface forces a compile break when an additional, non-overriding abstract method is added to a SAM, which would break the use of Lambda implementations.

Note that this rule is automatically disabled when the project's sonar.java.source is lower than 8.

**Noncompliant Code Example**
```java
public interface Changeable<T> {
  public void change(T o);
}


```
**Compliant Solution**
```java
@FunctionalInterface
public interface Changeable<T> {
  public void change(T o);
}

Deprecated

This rule is deprecated, and will eventually be removed.```
#### Rule 408: Methods should not be too complex
##### Quality Category: Code Smell
The cyclomatic complexity of methods should not exceed a defined threshold.

Complex code can perform poorly and will in any case be difficult to understand and therefore to maintain.


```
**Exceptions**
```java

While having a large number of fields in a class may indicate that it should be split, this rule nonetheless ignores high complexity in equals and hashCode methods.
```
#### Rule 409: Control flow statements "if", "for", "while", "switch" and "try" should not be nested too deeply
##### Quality Category: Code Smell
Nested if, for, while, switch, and try statements are key ingredients for making what's known as "Spaghetti code".

Such code is hard to read, refactor and therefore maintain.

**Noncompliant Code Example**
```java

With the default threshold of 3:

if (condition1) {                  // Compliant - depth = 1
  /* ... */
  if (condition2) {                // Compliant - depth = 2
    /* ... */
    for(int i = 0; i < 10; i++) {  // Compliant - depth = 3, not exceeding the limit
      /* ... */
      if (condition4) {            // Noncompliant - depth = 4
        if (condition5) {          // Depth = 5, exceeding the limit, but issues are only reported on depth = 4
          /* ... */
        }
        return;
      }
    }
  }
}
```
#### Rule 410: Classes should not be too complex
##### Quality Category: Code Smell
The Cyclomatic Complexity is measured by the number of && and || operators and if, while, do, for, ?:, catch, switch, case, return and throw statements in the body of a class plus one for each constructor, method, static initializer, or instance initializer in the class. The last return statement in method, if exists, is not taken into account.

Even when the Cyclomatic Complexity of a class is very high, this complexity might be well distributed among all methods. Nevertheless, most of the time, a very complex class is a class which breaks the Single Responsibility Principle and which should be re-factored to be split in several classes.

Deprecated

This rule is deprecated, and will eventually be removed.
#### Rule 411: "if ... else if" constructs should end with "else" clauses
##### Quality Category: Code Smell
This rule applies whenever an if statement is followed by one or more else if statements; the final else if should be followed by an else statement.

The requirement for a final else statement is defensive programming.

The else statement should either take appropriate action or contain a suitable comment as to why no action is taken. This is consistent with the requirement to have a final default clause in a switch statement.

**Noncompliant Code Example**
```java
if (x == 0) {
  doSomething();
} else if (x == 1) {
  doSomethingElse();
}


```
**Compliant Solution**
```java
if (x == 0) {
  doSomething();
} else if (x == 1) {
  doSomethingElse();
} else {
  throw new IllegalStateException();
}


*See*

 MISRA C:2004, 14.10 - All if...else if constructs shall be terminated with an else clause.
 MISRA C++:2008, 6-4-2 - All if...else if constructs shall be terminated with an else clause.
 MISRA C:2012, 15.7 - All if...else if constructs shall be terminated with an else statement
CERT, MSC01-C. - Strive for logical completeness
CERT, MSC57-J. - Strive for logical completeness
#### Rule 412: Control structures should use curly braces
##### Quality Category: Code Smell
While not technically incorrect, the omission of curly braces can be misleading, and may lead to the introduction of errors during maintenance.

**Noncompliant Code Example**
```java
if (condition)  // Noncompliant
  executeSomething();


```
**Compliant Solution**
```java
if (condition) {
  executeSomething();
}


*See*

 MISRA C:2004, 14.8 - The statement forming the body of a switch, while, do ... while or for statement shall be a compound statement
 MISRA C:2004, 14.9 - An if (expression) construct shall be followed by a compound statement. The else keyword shall be followed by either a compound statement, or another if statement
 MISRA C++:2008, 6-3-1 - The statement forming the body of a switch, while, do ... while or for statement shall be a compound statement
 MISRA C++:2008, 6-4-1 - An if (condition) construct shall be followed by a compound statement. The else keyword shall be followed by either a compound statement, or another if statement
 MISRA C:2012, 15.6 - The body of an iteration-statement or a selection-statement shall be a compound-statement
CERT, EXP19-C. - Use braces for the body of an if, for, or while statement
CERT, EXP52-J. - Use braces for the body of an if, for, or while statement
#### Rule 413: The Object.finalize() method should not be overriden
##### Quality Category: Code Smell
The Object.finalize() method is called on an object by the garbage collector when it determines that there are no more references to the object. But there is absolutely no warranty that this method will be called AS SOON AS the last references to the object are removed. It can be few microseconds to few minutes later. So when system resources need to be disposed by an object, it's better to not rely on this asynchronous mechanism to dispose them.

**Noncompliant Code Example**
```java
public class MyClass {
  ...
  protected void finalize() {
    releaseSomeResources();    // Noncompliant
  }
  ...
}


*See*

CERT, MET12-J. - Do not use finalizers
#### Rule 414: Expressions should not be too complex
##### Quality Category: Code Smell
The complexity of an expression is defined by the number of &&, || and condition ? ifTrue : ifFalse operators it contains.

A single expression's complexity should not become too high to keep the code readable.

**Noncompliant Code Example**
```java

With the default threshold value of 3:

if (((condition1 && condition2) || (condition3 && condition4)) && condition5) { ... }


```
**Compliant Solution**
```java
if ( (myFirstCondition() || mySecondCondition()) && myLastCondition()) { ... }
```
#### Rule 415: Spring "@Controller" classes should not use "@Scope"
##### Quality Category: Bug
Spring @Controllers, @Services, and @Repositorys have singleton scope by default, meaning only one instance of the class is ever instantiated in the application. Defining any other scope for one of these class types will result in needless churn as new instances are created and destroyed. In a busy web application, this could cause a significant amount of needless additional load on the server.

This rule raises an issue when the @Scope annotation is applied to a @Controller, @Service, or @Repository with any value but "singleton". @Scope("singleton") is redundant, but ignored.

**Noncompliant Code Example**
```java
@Scope("prototype")  // Noncompliant
@Controller
public class HelloWorld {


```
**Compliant Solution**
```java
@Controller
public class HelloWorld {
```
#### Rule 416: Constructor injection should be used instead of field injection
##### Quality Category: Bug
Field injection seems like a tidy way to get your classes what they need to do their jobs, but it's really a NullPointerException waiting to happen unless all your class constructors are private. That's because any class instances that are constructed by callers, rather than instantiated by a Dependency Injection framework compliant with the JSR-330 (Spring, Guice, ...), won't have the ability to perform the field injection.

Instead @Inject should be moved to the constructor and the fields required as constructor parameters.

This rule raises an issue when classes with non-private constructors (including the default constructor) use field injection.

**Noncompliant Code Example**
```java
class MyComponent {  // Anyone can call the default constructor

  @Inject MyCollaborator collaborator;  // Noncompliant

  public void myBusinessMethod() {
    collaborator.doSomething();  // this will fail in classes new-ed by a caller
  }
}


```
**Compliant Solution**
```java
class MyComponent {

  private final MyCollaborator collaborator;

  @Inject
  public MyComponent(MyCollaborator collaborator) {
    Assert.notNull(collaborator, "MyCollaborator must not be null!");
    this.collaborator = collaborator;
  }

  public void myBusinessMethod() {
    collaborator.doSomething();
  }
}
```
#### Rule 417: Classes that don't define "hashCode()" should not be used in hashes
##### Quality Category: Bug
Because Object implements hashCode, any Java class can be put into a hash structure. However, classes that define equals(Object) but not hashCode() aren't truly hash-able because instances that are equivalent according to the equals method can return different hashes.

**Noncompliant Code Example**
```java
public class Student {  // no hashCode() method; not hash-able
  // ...

  public boolean equals(Object o) {
    // ...
  }
}

public class School {
  private Map<Student, Integer> studentBody = // okay so far
          new HashTable<Student, Integer>(); // Noncompliant

  // ...


```
**Compliant Solution**
```java
public class Student {  // has hashCode() method; hash-able
  // ...

  public boolean equals(Object o) {
    // ...
  }
  public int hashCode() {
    // ...
  }
}

public class School {
  private Map<Student, Integer> studentBody = new HashTable<Student, Integer>();

  // ...
```
#### Rule 418: "instanceof" operators that always return "true" or "false" should be removed
##### Quality Category: Bug
instanceof operators that always return true or false are either useless or the result of a misunderstanding which could lead to unexpected behavior in production.

**Noncompliant Code Example**
```java
public boolean isSuitable(Integer param) {
...
  String name = null;

  if (name instanceof String) { // Noncompliant; always false since name is null
    //...
  }

  if(param instanceof Number) {  // Noncompliant; always true unless param is null, because param is an Integer
    doSomething();
  }
...
}


```
**Compliant Solution**
```java
public boolean isSuitable(Integer param) {
...
  doSomething();
...
}

Deprecated

This rule is deprecated; use {rule:squid:S2589} instead.```
#### Rule 419: Short-circuit logic should be used to prevent null pointer dereferences in conditionals
##### Quality Category: Bug
When either the equality operator in a null test or the logical operator that follows it is reversed, the code has the appearance of safely null-testing the object before dereferencing it. Unfortunately the effect is just the opposite - the object is null-tested and then dereferenced only if it is null, leading to a guaranteed null pointer dereference.

**Noncompliant Code Example**
```java
if (str == null && str.length() == 0) {
  System.out.println("String is empty");
}

if (str != null || str.length() > 0) {
  System.out.println("String is not empty");
}


```
**Compliant Solution**
```java
if (str == null || str.length() == 0) {
  System.out.println("String is empty");
}

if (str != null && str.length() > 0) {
  System.out.println("String is not empty");
}

Deprecated

This rule is deprecated; use {rule:squid:S2259} instead.```
#### Rule 420: Floating point numbers should not be tested for equality
##### Quality Category: Bug
Floating point math is imprecise because of the challenges of storing such values in a binary representation. Even worse, floating point math is not associative; push a float or a double through a series of simple mathematical operations and the answer will be different based on the order of those operation because of the rounding that takes place at each step.

Even simple floating point assignments are not simple:

float f = 0.1; // 0.100000001490116119384765625
double d = 0.1; // 0.1000000000000000055511151231257827021181583404541015625


(Results will vary based on compiler and compiler settings);

Therefore, the use of the equality (==) and inequality (!=) operators on float or double values is almost always an error. Instead the best course is to avoid floating point comparisons altogether. When that is not possible, you should consider using one of Java's float-handling Numbers such as BigDecimal which can properly handle floating point comparisons. A third option is to look not for equality but for whether the value is close enough. I.e. compare the absolute value of the difference between the stored value and the expected value against a margin of acceptable error. Note that this does not cover all cases (NaN and Infinity for instance).

This rule checks for the use of direct and indirect equality/inequailty tests on floats and doubles.

**Noncompliant Code Example**
```java
float myNumber = 3.146;
if ( myNumber == 3.146f ) { //Noncompliant. Because of floating point imprecision, this will be false
  // ...
}
if ( myNumber != 3.146f ) { //Noncompliant. Because of floating point imprecision, this will be true
  // ...
}

if (myNumber < 4 || myNumber > 4) { // Noncompliant; indirect inequality test
  // ...
}

float zeroFloat = 0.0f;
if (zeroFloat == 0) {  // Noncompliant. Computations may end up with a value close but not equal to zero.
}


```
**Exceptions**
```java

Since NaN is not equal to itself, the specific case of testing a floating point value against itself is a valid test for NaN and is therefore ignored. Though using Double.isNaN method should be preferred instead, as intent is more explicit.

float f;
double d;
if(f != f) { // Compliant; test for NaN value
  System.out.println("f is NaN");
} else if (f != d) { // Noncompliant
  // ...
}


*See*

 MISRA C:2004, 13.3 - Floating-point expressions shall not be tested for equality or inequality.
 MISRA C++:2008, 6-2-2 - Floating-point expressions shall not be directly or indirectly tested for equality or inequality

#### Rule 421: Useless "if(true) {...}" and "if(false){...}" blocks should be removed
##### Quality Category: Bug
if statements with conditions that are always false have the effect of making blocks of code non-functional. if statements with conditions that are always true are completely redundant, and make the code less readable.

There are three possible causes for the presence of such code:

 An if statement was changed during debugging and that debug code has been committed.
 Some value was left unset.
 Some logic is not doing what the programmer thought it did.

In any of these cases, unconditional if statements should be removed.

**Noncompliant Code Example**
```java
if (true) {
  doSomething();
}
...
if (false) {
  doSomethingElse();
}

if (2 < 3 ) { ... }  // Noncompliant; always false

int i = 0;
int j = 0;
// ...
j = foo();

if (j > 0 && i > 0) { ... }  // Noncompliant; always false - i never set after initialization

boolean b = true;
//...
if (b || !b) { ... }  // Noncompliant


```
**Compliant Solution**
```java
doSomething();
...


*See*

MITRE, CWE-489 - Leftover Debug Code
MITRE, CWE-570 - Expression is Always False
MITRE, CWE-571 - Expression is Always True
 MISRA C:2004, 13.7 - Boolean operations whose results are invariant shall not be permitted.
 MISRA C:2012, 14.3 - Controlling expressions shall not be invariant
Deprecated

This rule is deprecated; use {rule:squid:S2583} instead.
#### Rule 422: The Object.finalize() method should not be called
##### Quality Category: Bug
According to the official javadoc documentation, this Object.finalize() is called by the garbage collector on an object when garbage collection determines that there are no more references to the object. Calling this method explicitly breaks this contract and so is misleading.

**Noncompliant Code Example**
```java
public void dispose() throws Throwable {
  this.finalize();                       // Noncompliant
}


*See*

MITRE, CWE-586 - Explicit Call to Finalize()
CERT, MET12-J. - Do not use finalizers
#### Rule 423: Using setters in Struts 2 ActionSupport is security-sensitive
##### Quality Category: Security Hotspot
Using setters in Struts 2 ActionSupport is security-sensitive. For example, their use has led in the past to the following vulnerabilities:

CVE-2012-1006

All classes extending com.opensymphony.xwork2.ActionSupport are potentially remotely reachable. An action class extending ActionSupport will receive all HTTP parameters sent and these parameters will be automatically mapped to the setters of the Struts 2 action class. One should review the use of the fields set by the setters, to be sure they are used safely. By default, they should be considered as untrusted inputs.

This rule is there to allow a security auditor to quickly find some potential hotspots to review.

Ask Yourself Whether
 the setter is needed. There is no need for it if the attribute's goal is not to map queries' parameter.
 the value provided to the setter is properly sanitized before being used or stored. (*)

(*) You are at risk if you answered yes to this question.

Recommended Secure Coding Practices

As said in Strut's documentation: "Do not define setters when not needed"

Sanitize the user input. This can be for example done by implementing the validate() method of com.opensymphony.xwork2.ActionSupport.

**Noncompliant Code Example**
```java
public class AccountBalanceAction extends ActionSupport {
  private static final long serialVersionUID = 1L;
  private Integer accountId;

  // this setter might be called with user input
  public void setAccountId(Integer accountId) {
    this.accountId = accountId;
  }

  @Override
  public String execute() throws Exception {
    // call a service to get the account's details and its balance
    [...]
    return SUCCESS;
  }
}


*See*

 OWASP Top 10 2017 Category A1 - Injection
#### Rule 424: Using Struts 1 ActionForm is security-sensitive
##### Quality Category: Security Hotspot
Using Struts 1 ActionForm is security-sensitive. For example, their use has led in the past to the following vulnerability:

CVE-2014-0114

All classes extending org.apache.struts.action.Action are potentially remotely reachable. The ActionForm object provided as a parameter of the execute method is automatically instantiated and populated with the HTTP parameters. One should review the use of these parameters to be sure they are used safely.

This rule is there to allow a security auditor to quickly find some potential hotspots to review.

Ask Yourself Whether
 some parameters of the ActionForm might not have been validated properly.
 dangerous parameter names are accepted. Example: accept a "class" parameter and use the form to populate JavaBean properties (see the CVE-2014-0114 above).
 there are unused fields which are not empty or undefined.

You are at risk if you answered to any of these questions.

Recommended Secure Coding Practices

All ActionForm's properties should be validated, including their size. Whenever possible, filter the parameters with a whitelist of valid values. Otherwise, escape any sensitive character and constrain the values as much as possible.

Allow only non security-sensitive property names. All the ActionForm's property names should be whitelisted.

Unused fields should be constrained so that they are either empty or undefined.

**Noncompliant Code Example**
```java
// Struts 1.1+
public final class CashTransferAction extends Action {

  public String fromAccount = "";
  public String toAccount = "";

  public ActionForward execute(ActionMapping mapping, ActionForm form, HttpServletRequest req, HttpServletResponse res) throws Exception {
    // usage of the "form" object to call some services doing JDBC actions
    [...]
    return mapping.findForward(resultat);
  }
}


*See*

 OWASP Top 10 2017 Category A1 - Injection
MITRE, CWE-105: Struts Form Field Without Validator
#### Rule 425: Increment (++) and decrement (--) operators should not be used in a method call or mixed with other operators in an expression
##### Quality Category: Code Smell
The use of increment and decrement operators in method calls or in combination with other arithmetic operators is not recommended, because:

 It can significantly impair the readability of the code.
 It introduces additional side effects into a statement, with the potential for undefined behavior.
 It is safer to use these operators in isolation from any other arithmetic operators.
**Noncompliant Code Example**
```java
u8a = ++u8b + u8c--;
foo = bar++ / 4;


```
**Compliant Solution**
```java

The following sequence is clearer and therefore safer:

++u8b;
u8a = u8b + u8c;
u8c--;
foo = bar / 4;
bar++;


*See*

 MISRA C:2004, 12.1 - Limited dependence should be placed on the C operator precedence rules in expressions.
 MISRA C:2004, 12.13 - The increment (++) and decrement (--) operators should not be mixed with other operators in an expression.
 MISRA C++:2008, 5-2-10 - The increment (++) and decrement (--) operator should not be mixed with other operators in an expression.
 MISRA C:2012, 12.1 - The precedence of operators within expressions should be made explicit
 MISRA C:2012, 13.3 - A full expression containing an increment (++) or decrement (--) operator should have no other potential side effects other than that cause by the increment or decrement operator
CERT, EXP30-C. - Do not depend on the order of evaluation for side effects
CERT, EXP50-CPP. - Do not depend on the order of evaluation for side effects
CERT, EXP05-J. - Do not follow a write by a subsequent write or read of the same object within an expression
#### Rule 426: Limited dependence should be placed on operator precedence
##### Quality Category: Code Smell
The rules of operator precedence are complicated and can lead to errors. For this reason, parentheses should be used for clarification in complex statements. However, this does not mean that parentheses should be gratuitously added around every operation.

This rule raises issues when && and || are used in combination, when assignment and equality or relational operators are used in together in a condition, and for other operator combinations according to the following table:

	+, -, *, /, %	<<, >>, >>>	&	^	|
+, -, *, /, %		x	x	x	x
<<, >>, >>>	x		x	x	x
&	x	x		x	x
^	x	x	x		x
|	x	x	x	x	
**Noncompliant Code Example**
```java
x = a + b - c;
x = a + 1 << b;  // Noncompliant

if ( a > b || c < d || a == d) {...}
if ( a > b && c < d || a == b) {...}  // Noncompliant
if (a = f(b,c) == 1) { ... } // Noncompliant; == evaluated first


```
**Compliant Solution**
```java
x = a + b - c;
x = (a + 1) << b;

if ( a > b || c < d || a == d) {...}
if ( (a > b && c < d) || a == b) {...}
if ( (a = f(b,c)) == 1) { ... }


*See*

 MISRA C:2004, 12.1 - Limited dependence should be placed on C's operator precedence rules in expressions
 MISRA C:2004, 12.2 - The value of an expression shall be the same under any order of evaluation that the standard permits.
 MISRA C:2004, 12.5 - The operands of a logical && or || shall be primary-expressions.
 MISRA C++:2008, 5-0-1 - The value of an expression shall be the same under any order of evaluation that the standard permits.
 MISRA C++:2008, 5-0-2 - Limited dependence should be placed on C++ operator precedence rules in expressions
 MISRA C++:2008, 5-2-1 - Each operand of a logical && or || shall be a postfix-expression.
 MISRA C:2012, 12.1 - The precedence of operators within expressions should be made explicit
CERT, EXP00-C. - Use parentheses for precedence of operation
CERT, EXP53-J. - Use parentheses for precedence of operation
MITRE, CWE-783 - Operator Precedence Logic Error
#### Rule 427: "@EnableAutoConfiguration" should be fine-tuned
##### Quality Category: Code Smell
"@EnableAutoConfiguration" is a convenient feature to configure the Spring Application Context by attempting to guess the beans that you are likely to need. The drawback is that it may load and configure beans the application will never use and therefore consume more CPU and RAM than really required. @EnableAutoConfiguration should be configured to exclude all the beans not required by the application. Alternatively, use the @Import annotation instead of @EnableAutoConfiguration, to explicitly import the useful AutoConfiguration classes.

This rule applies for @SpringBootApplication as well.

**Noncompliant Code Example**
```java
@SpringBootApplication
public class MyApplication {
...
}

@Configuration
@EnableAutoConfiguration
public class MyApplication {
...
}


```
**Compliant Solution**
```java
@SpringBootApplication(exclude = {
  MultipartAutoConfiguration.class,
  JmxAutoConfiguration.class,
})
public class MyApplication {
...
}

@Configuration
@EnableAutoConfiguration(exclude = {
  MultipartAutoConfiguration.class,
  JmxAutoConfiguration.class,
})
public class MyApplication {
...
}

@Configuration
@Import({
        DispatcherServletAutoConfiguration.class,
        EmbeddedServletContainerAutoConfiguration.class,
        ErrorMvcAutoConfiguration.class,
        HttpEncodingAutoConfiguration.class,
        HttpMessageConvertersAutoConfiguration.class,
        JacksonAutoConfiguration.class,
        ServerPropertiesAutoConfiguration.class,
        PropertyPlaceholderAutoConfiguration.class,
        ThymeleafAutoConfiguration.class,
        WebMvcAutoConfiguration.class
})
public class MyApplication {
...
}
```
#### Rule 428: "@Import"s should be preferred to "@ComponentScan"s
##### Quality Category: Code Smell
@ComponentScan is used to find which Spring @Component beans (@Service or @Repository or Controller) are available in the classpath so they can be used in the application context. This is a convenient feature especially when you begin a new project but it comes with the drawback of slowing down the application start-up time especially when the application becomes bigger (ie: it references a large JAR file, or it references a significant number of JAR files, or the base-package refers to a large amount of .class files).

@ComponentScan should be replaced by an explicit list of Spring beans loaded by @Import.

The interface @SpringBootApplication is also considered by this rule because it is annotated with @ComponentScan.

**Noncompliant Code Example**
```java
@ComponentScan
public class MyApplication {
...
}

@SpringBootApplication
public class MyApplication {
...
}


```
**Compliant Solution**
```java
@Configuration
@Import({
        DispatcherServletAutoConfiguration.class,
        ErrorMvcAutoConfiguration.class,
        HttpEncodingAutoConfiguration.class,
        HttpMessageConvertersAutoConfiguration.class,
        MultipartAutoConfiguration.class,
        ServerPropertiesAutoConfiguration.class,
        PropertyPlaceholderAutoConfiguration.class,
        WebMvcAutoConfiguration.class
})
public class MyApplication {
...
}


*See*

Optimizing Spring Framework for App Engine Applications
#### Rule 429: Enum values should be compared with "=="
##### Quality Category: Code Smell
Testing equality of an enum value with equals is perfectly valid because an enum is an Object and every Java developer knows "==" should not be used to compare the content of an Object. At the same time, using "==" on enums:

- provides the same expected comparison (content) as equals

- is more null-safe than equals()

- provides compile-time (static) checking rather than runtime checking

For these reasons, use of "==" should be preferred to equals.

**Noncompliant Code Example**
```java
public enum Fruit {
   APPLE, BANANA, GRAPE
}

public enum Cake {
  LEMON_TART, CHEESE_CAKE
}

public boolean isFruitGrape(Fruit candidateFruit) {
  return candidateFruit.equals(Fruit.GRAPE); // Noncompliant; this will raise an NPE if candidateFruit is NULL
}

public boolean isFruitGrape(Cake candidateFruit) {
  return candidateFruit.equals(Fruit.GRAPE); // Noncompliant; always returns false
}



```
**Compliant Solution**
```java
public boolean isFruitGrape(Fruit candidateFruit) {
  return candidateFruit == Fruit.GRAPE; // Compliant; there is only one instance of Fruit.GRAPE - if candidateFruit is a GRAPE it will have the same reference as Fruit.GRAPE
}

public boolean isFruitGrape(Cake candidateFruit) {
  return candidateFruit == Fruit.GRAPE; // Compliant; compilation time failure
}


*See*

Use == (or !=) to Compare Java Enums
#### Rule 430: Spring components should use constructor injection
##### Quality Category: Code Smell
Spring @Controller, @Service, and @Repository classes are singletons by default, meaning only one instance of the class is ever instantiated in the application. Typically such a class might have a few static members, such as a logger, but all non-static members should be managed by Spring and supplied via constructor injection rather than by field injection.

This rule raise an issue when any non-static member of a Spring component has an injection annotation, or if the constructor of Spring component does not have injection annotation.

**Noncompliant Code Example**
```java
@Controller
public class HelloWorld {

  @Autowired
  private String name = null; // Noncompliant

  HelloWorld() {
   // ...
  }

  // ...
}


```
**Compliant Solution**
```java
@Controller
public class HelloWorld {

  private String name = null;

  @Autowired
  HelloWorld(String name) {
    this.name = name;
   // ...
  }

  // ...
}
```
#### Rule 431: Regex patterns should not be created needlessly
##### Quality Category: Code Smell
The java.util.regex.Pattern.compile() methods have a significant performance cost, and therefore should be used sensibly.

Moreover they are the only mechanism available to create instances of the Pattern class, which are necessary to do any pattern matching using regular expressions. Unfortunately that can be hidden behind convenience methods like String.matches() or String.split().

It is therefore somewhat easy to inadvertently repeatedly compile the same regular expression at great performance cost with no valid reason.

This rule raises an issue when:

 A Pattern is compiled from a String literal or constant and is not stored in a static final reference.
String.matches, String.split, String.replaceAll or String.replaceFirst are invoked with a String literal or constant. In which case the code should be refactored to use a java.util.regex.Pattern while respecting the previous rule.
**Noncompliant Code Example**
```java
public void doingSomething(String stringToMatch) {
  Pattern regex = Pattern.compile("myRegex");  // Noncompliant
  Matcher matcher = regex.matcher("s");
  // ...
  if (stringToMatch.matches("myRegex2")) {  // Noncompliant
    // ...
  }
}


```
**Compliant Solution**
```java
private static final Pattern myRegex = Pattern.compile("myRegex");
private static final Pattern myRegex2 = Pattern.compile("myRegex2");

public void doingSomething(String stringToMatch) {
  Matcher matcher = myRegex.matcher("s");
  // ...
  if (myRegex2.matcher(stringToMatch).matches()) {
    // ...
  }
}


```
**Exceptions**
```java

String.split doesn't create a regex when the string passed as argument meets either of these 2 conditions:

 It is a one-char String and this character is not one of the RegEx's meta characters ".$|()[{^?*+\"
 It is a two-char String and the first char is the backslash and the second is not the ascii digit or ascii letter.

In which case no issue will be raised.
```
#### Rule 432: Duplicate values should not be passed as arguments
##### Quality Category: Code Smell
There are valid cases for passing a variable multiple times into the same method call, but usually doing so is a mistake, and something else was intended for one of the arguments.

**Noncompliant Code Example**
```java
if (compare(myPoint.x, myPoint.x) != 0) { // Noncompliant
  //...
}

if (compare(getNextValue(), getNextValue()) != 0) { // Noncompliant
  // ...
}


```
**Compliant Solution**
```java
if (compare(myPoint.x, myPoint.y) != 0) {
  //...
}

Object v1 = getNextValue();
Object v2 = getNextValue();
if (compare(v1, v2) != 0) {
  // ...
}

Deprecated

This rule is deprecated, and will eventually be removed.```
#### Rule 433: Track uses of disallowed constructors
##### Quality Category: Code Smell
This rule allows banning usage of certain constructors.

**Noncompliant Code Example**
```java

Given parameters:

 className: java.util.Date
 argumentTypes: java.lang.String
Date birthday;
birthday = new Date("Sat Sep 27 05:42:21 EDT 1986");  // Noncompliant
birthday = new Date(528176541000L); // Compliant
```
#### Rule 434: "Optional" should not be used for parameters
##### Quality Category: Code Smell
The Java language authors have been quite frank that Optional was intended for use only as a return type, as a way to convey that a method may or may not return a value.

And for that, it's valuable but using Optional on the input side increases the work you have to do in the method without really increasing the value. With an Optional parameter, you go from having 2 possible inputs: null and not-null, to three: null, non-null-without-value, and non-null-with-value. Add to that the fact that overloading has long been available to convey that some parameters are optional, and there's really no reason to have Optional parameters.

**Noncompliant Code Example**
```java
public String sayHello(Optional<String> name) {  // Noncompliant
  if (name == null || !name.isPresent()) {
    return "Hello World";
  } else {
    return "Hello " + name;
  }
}


```
**Compliant Solution**
```java
public String sayHello(String name) {
  if (name == null) {
    return "Hello World";
  } else {
    return "Hello " + name;
  }
}
```
#### Rule 435: Track uses of disallowed dependencies
##### Quality Category: Code Smell
Whether they are disallowed locally for security, license, or dependability reasons, forbidden dependencies should not be used.

This rule raises an issue when the group or artifact id of a direct dependency matches the configured forbidden dependency pattern.

**Noncompliant Code Example**
```java

With a parameter of: *:.*log4j.*

<dependency> <!-- Noncompliant -->
    <groupId>log4j</groupId>
    <artifactId>log4j</artifactId>
    <version>1.2.17</version>
</dependency>
```
#### Rule 436: "this" should not be exposed from constructors
##### Quality Category: Code Smell
In single-threaded environments, the use of this in constructors is normal, and expected. But in multi-threaded environments, it could expose partially-constructed objects to other threads, and should be used with caution.

The classic example is a class with a static list of its instances. If the constructor stores this in the list, another thread could access the object before it's fully-formed. Even when the storage of this is the last instruction in the constructor, there's still a danger if the class is not final. In that case, the initialization of subclasses won't be complete before this is exposed.

This rule raises an issue when this is assigned to any globally-visible object in a constructor, and when it is passed to the method of another object in a constructor

**Noncompliant Code Example**
```java
public class Monument {

  public static final List<Monument> ALL_MONUMENTS = new ArrayList()<>;
  // ...

  public Monument(String location, ...) {
    ALL_MONUMENTS.add(this);  // Noncompliant; passed to a method of another object

    this.location = location;
    // ...
  }
}


```
**Exceptions**
```java

This rule ignores instances of assigning this directly to a static field of the same class because that case is covered by S3010.


*See*

CERT, TSM01-J. - Do not let the this reference escape during object construction
CERT, TSM03-J. - Do not publish partially initialized objects

#### Rule 437: Classes should not have too many "static" imports
##### Quality Category: Code Smell
Importing a class statically allows you to use its public static members without qualifying them with the class name. That can be handy, but if you import too many classes statically, your code can become confusing and difficult to maintain.

**Noncompliant Code Example**
```java

With the default threshold value: 4

import static java.lang.Math.*;
import static java.util.Collections.*;
import static com.myco.corporate.Constants.*;
import static com.myco.division.Constants.*;
import static com.myco.department.Constants.*;  // Noncompliant
```
#### Rule 438: Escaped Unicode characters should not be used
##### Quality Category: Code Smell
The use of Unicode escape sequences should be reserved for characters that would otherwise be ambiguous, such as unprintable characters.

This rule ignores sequences composed entirely of Unicode characters, but otherwise raises an issue for each Unicode character that represents a printable character.

**Noncompliant Code Example**
```java
String prefix = "n\u00E9e"; // Noncompliant


```
**Compliant Solution**
```java
String prefix = "née";
```
#### Rule 439: Inner classes should not have too many lines of code
##### Quality Category: Code Smell
Inner classes should be short and sweet, to manage complexity in the overall file. An inner class that has grown longer than a certain threshold should probably be externalized to its own file.
#### Rule 440: Inner classes which do not reference their owning classes should be "static"
##### Quality Category: Code Smell
A non-static inner class has a reference to its outer class, and access to the outer class' fields and methods. That class reference makes the inner class larger and could cause the outer class instance to live in memory longer than necessary.

If the reference to the outer class isn't used, it is more efficient to make the inner class static (also called nested). If the reference is used only in the class constructor, then explicitly pass a class reference to the constructor. If the inner class is anonymous, it will also be necessary to name it.

However, while a nested/static class would be more efficient, it's worth noting that there are semantic differences between an inner class and a nested one:

 an inner class can only be instantiated within the context of an instance of the outer class.
 a nested (static) class can be instantiated independently of the outer class.
**Noncompliant Code Example**
```java
public class Fruit {
  // ...

  public class 
*See*
d {  // Noncompliant; there's no use of the outer class reference so make it static
    int germinationDays = 0;
    public 
*See*
d(int germinationDays) {
      this.germinationDays = germinationDays;
    }
    public int getGerminationDays() {
      return germinationDays;
    }
  }
}


```
**Compliant Solution**
```java
public class Fruit {
  // ...

  public static class 
*See*
d {
    int germinationDays = 0;
    public 
*See*
d(int germinationDays) {
      this.germinationDays = germinationDays;
    }
    public int getGerminationDays() {
      return germinationDays;
    }
  }
}

#### Rule 441: "deleteOnExit" should not be used
##### Quality Category: Code Smell
Use of File.deleteOnExit() is not recommended for the following reasons:

 The deletion occurs only in the case of a normal JVM shutdown but not when the JVM crashes or is killed.
 For each file handler, the memory associated with the handler is released only at the end of the process.
**Noncompliant Code Example**
```java
File file = new File("file.txt");
file.deleteOnExit();  // Noncompliant
```
#### Rule 442: Public methods should not contain selector arguments
##### Quality Category: Code Smell
A selector argument is a boolean argument that's used to determine which of two paths to take through a method. Specifying such a parameter may seem innocuous, particularly if it's well named.

Unfortunately, the maintainers of the code calling the method won't see the parameter name, only its value. They'll be forced either to guess at the meaning or to take extra time to look the method up.

Instead, separate methods should be written.

This rule finds methods with a boolean that's used to determine which path to take through the method.

**Noncompliant Code Example**
```java
public String tempt(String name, boolean ofAge) {
  if (ofAge) {
    offerLiquor(name);
  } else {
    offerCandy(name);
  }
}

// ...
public void corrupt() {
  tempt("Joe", false); // does this mean not to temp Joe?
}


```
**Compliant Solution**
```java
public void temptAdult(String name) {
  offerLiquor(name);
}

public void temptChild(String name) {
    offerCandy(name);
}

// ...
public void corrupt() {
  age < legalAge ? temptChild("Joe") : temptAdult("Joe");
}
```
#### Rule 443: Java parser failure
##### Quality Category: Code Smell
When the Java parser fails, it is possible to record the failure as a violation on the file. This way, not only it is possible to track the number of files that do not parse but also to easily find out why they do not parse.
#### Rule 444: Track uses of disallowed methods
##### Quality Category: Code Smell
This rule allows banning certain methods.

**Noncompliant Code Example**
```java

Given parameters:

 className:java.lang.String
 methodName: replace
 argumentTypes: java.lang.CharSequence, java.lang.CharSequence
String name;
name.replace("A","a");  // Noncompliant
```
#### Rule 445: Types should be used in lambdas
##### Quality Category: Code Smell
Shared coding conventions allow teams to collaborate effectively. While types for lambda arguments are optional, specifying them anyway makes the code clearer and easier to read.

**Noncompliant Code Example**
```java
Arrays.sort(rosterAsArray,
    (a, b) -> {  // Noncompliant
        return a.getBirthday().compareTo(b.getBirthday());
    }
);


```
**Compliant Solution**
```java
Arrays.sort(rosterAsArray,
    (Person a, Person b) -> {
        return a.getBirthday().compareTo(b.getBirthday());
    }
);


```
**Exceptions**
```java

When the lambda has one or two parameters and does not have a block this rule will not fire up an issue as things are considered more readable in those cases.

stream.map((a, b) -> a.length); // compliant

```
#### Rule 446: "java.time" classes should be used for dates and times
##### Quality Category: Code Smell
The old, much-derided Date and Calendar classes have always been confusing and difficult to use properly, particularly in a multi-threaded context. JodaTime has long been a popular alternative, but now an even better option is built-in. Java 8's JSR 310 implementation offers specific classes for:

Class	Use for
LocalDate	a date, without time of day, offset, or zone
LocalTime	the time of day, without date, offset, or zone
LocalDateTime	the date and time, without offset, or zone
OffsetDate	a date with an offset such as +02:00, without time of day, or zone
OffsetTime	the time of day with an offset such as +02:00, without date, or zone
OffsetDateTime	the date and time with an offset such as +02:00, without a zone
ZonedDateTime	the date and time with a time zone and offset
YearMonth	a year and month
MonthDay	month and day
Year/MonthOfDay/DayOfWeek/...	classes for the important fields
DateTimeFields	stores a map of field-value pairs which may be invalid
Calendrical	access to the low-level API
Period	a descriptive amount of time, such as "2 months and 3 days"
**Noncompliant Code Example**
```java
Date now = new Date();  // Noncompliant
DateFormat df = new SimpleDateFormat("dd.MM.yyyy");
Calendar christmas  = Calendar.getInstance();  // Noncompliant
christmas.setTime(df.parse("25.12.2020"));


```
**Compliant Solution**
```java
LocalDate now = LocalDate.now();  // gets calendar date. no time component
LocalTime now2 = LocalTime.now(); // gets current time. no date component
LocalDate christmas = LocalDate.of(2020,12,25);
```
#### Rule 447: The names of methods with boolean return values should start with "is" or "has"
##### Quality Category: Code Smell
Well-named functions can allow the users of your code to understand at a glance what to expect from the function - even before reading the documentation. Toward that end, methods returning a boolean should have names that start with "is" or "has" rather than with "get".

**Noncompliant Code Example**
```java
public boolean getFoo() { // Noncompliant
  // ...
}

public boolean getBar(Bar c) { // Noncompliant
  // ...
}

public boolean testForBar(Bar c) { // Compliant - The method does not start by 'get'.
  // ...
}


```
**Compliant Solution**
```java
public boolean isFoo() {
  // ...
}

public boolean hasBar(Bar c) {
  // ...
}

public boolean testForBar(Bar c) {
  // ...
}


```
**Exceptions**
```java

Overriding methods are excluded.

@Override
public boolean getFoo(){
  // ...
}

```
#### Rule 448: Files should contain only one top-level class or interface each
##### Quality Category: Code Smell
A file that grows too much tends to aggregate too many responsibilities and inevitably becomes harder to understand and therefore to maintain. This is doubly true for a file with multiple top-level classes and interfaces. It is strongly advised to divide the file into one top-level class or interface per file.
#### Rule 449: Classes should not have too many fields
##### Quality Category: Code Smell
A class that grows too much tends to aggregate too many responsibilities and inevitably becomes harder to understand and therefore to maintain, and having a lot of fields is an indication that a class has grown too large.

Above a specific threshold, it is strongly advised to refactor the class into smaller ones which focus on well defined topics.
#### Rule 450: The ternary operator should not be used
##### Quality Category: Code Smell
While the ternary operator is pleasingly compact, its use can make code more difficult to read. It should therefore be avoided in favor of the more verbose if/else structure.

**Noncompliant Code Example**
```java
System.out.println(i>10?"yes":"no");


```
**Compliant Solution**
```java
if (i > 10) {
  System.out.println(("yes");
} else {
  System.out.println("no");
}
```
#### Rule 451: Standard functional interfaces should not be redefined
##### Quality Category: Code Smell
Just as there is little justification for writing your own String class, there is no good reason to re-define one of the existing, standard functional interfaces.

Doing so may seem tempting, since it would allow you to specify a little extra context with the name. But in the long run, it will be a source of confusion, because maintenance programmers will wonder what is different between the custom functional interface and the standard one.

**Noncompliant Code Example**
```java
@FunctionalInterface
public interface MyInterface { // Noncompliant
	double toDouble(int a);
}

@FunctionalInterface
public interface ExtendedBooleanSupplier { // Noncompliant
  boolean get();
  default boolean isFalse() {
    return !get();
  }
}

public class MyClass {
    private int a;
    public double myMethod(MyInterface instance){
	return instance.toDouble(a);
    }
}


```
**Compliant Solution**
```java
@FunctionalInterface
public interface ExtendedBooleanSupplier extends BooleanSupplier { // Compliant, extends java.util.function.BooleanSupplier
  default boolean isFalse() {
    return !getAsBoolean();
  }
}

public class MyClass {
    private int a;
    public double myMethod(IntToDoubleFunction instance){
	return instance.applyAsDouble(a);
    }
}
```
#### Rule 452: "NullPointerException" should not be caught
##### Quality Category: Code Smell
NullPointerException should be avoided, not caught. Any situation in which NullPointerException is explicitly caught can easily be converted to a null test, and any behavior being carried out in the catch block can easily be moved to the "is null" branch of the conditional.

**Noncompliant Code Example**
```java
public int lengthPlus(String str) {
  int len = 2;
  try {
    len += str.length();
  }
  catch (NullPointerException e) {
    log.info("argument was null");
  }
  return len;
}


```
**Compliant Solution**
```java
public int lengthPlus(String str) {
  int len = 2;

  if (str != null) {
    len += str.length();
  }
  else {
    log.info("argument was null");
  }
  return len;
}


*See*

MITRE, CWE-395 - Use of NullPointerException Catch to Detect NULL Pointer Dereference
CERT, ERR08-J. - Do not catch NullPointerException or any of its ancestors
#### Rule 453: "NullPointerException" should not be explicitly thrown
##### Quality Category: Code Smell
A NullPointerException should indicate that a null value was unexpectedly encountered. Good programming practice dictates that code is structured to avoid NPE's.

Explicitly throwing NullPointerException forces a method's callers to explicitly catch it, rather than coding to avoid it. Further, it makes it difficult to distinguish between the unexpectedly-encountered null value and the condition which causes the method to purposely throw an NPE.

If an NPE is being thrown to indicate that a parameter to the method should not have been null, use the @NotNull annotation instead.

**Noncompliant Code Example**
```java
public void doSomething (String aString) throws NullPointerException {
     throw new NullPointerException();
}


```
**Compliant Solution**
```java
public void doSomething (@NotNull String aString) {
}
```
#### Rule 454: Classes should not have too many methods
##### Quality Category: Code Smell
A class that grows too much tends to aggregate too many responsibilities and inevitably becomes harder to understand and therefore to maintain. Above a specific threshold, it is strongly advised to refactor the class into smaller ones which focus on well defined topics.
#### Rule 455: Methods should not have too many lines
##### Quality Category: Code Smell
A method that grows too large tends to aggregate too many responsibilities. Such method inevitably become harder to understand and therefore harder to maintain.

Above a specific threshold, it is strongly advised to refactor into smaller methods which focus on well-defined tasks. Those smaller methods will not only be easier to understand, but also probably easier to test.
#### Rule 456: Track uses of "NOSONAR" comments
##### Quality Category: Code Smell
Any issue to quality rule can be deactivated with the NOSONAR marker. This marker is pretty useful to exclude false-positive results but it can also be used abusively to hide real quality flaws.

This rule raises an issue when NOSONAR is used.
#### Rule 457: Classes and enums with private members should have a constructor
##### Quality Category: Code Smell
Non-abstract classes and enums with non-static, private members should explicitly initialize those members, either in a constructor or with a default value.

**Noncompliant Code Example**
```java
class A { // Noncompliant
  private int field;
}


```
**Compliant Solution**
```java
class A {
  private int field;

  A(int field) {
    this.field = field;
  }
}
```
#### Rule 458: Track comments matching a regular expression
##### Quality Category: Code Smell
This rule template can be used to create rules which will be triggered when the full content of a comment matches a given regular expression. Note that the regular expression should be expressed using the dotall format (where the . character matches any character).

For example, one can create a rule with the regular expression .*REVIEW.* to match all comment containing "REVIEW".

Note that, in order to match REVIEW regardless of the case, the (?i) modifier should be prepended to the expression, as in (?i).*REVIEW.*.
#### Rule 459: Statements should be on separate lines
##### Quality Category: Code Smell
For better readability, do not put more than one statement on a single line.

**Noncompliant Code Example**
```java
if(someCondition) doSomething();


```
**Compliant Solution**
```java
if(someCondition) {
  doSomething();
}
```
#### Rule 460: Classes should not be coupled to too many other classes (Single Responsibility Principle)
##### Quality Category: Code Smell
According to the Single Responsibility Principle, introduced by Robert C. Martin in his book "Principles of Object Oriented Design", a class should have only one responsibility:

If a class has more than one responsibility, then the responsibilities become coupled.

Changes to one responsibility may impair or inhibit the class' ability to meet the others.

This kind of coupling leads to fragile designs that break in unexpected ways when changed.

Classes which rely on many other classes tend to aggregate too many responsibilities and should be split into several smaller ones.

Nested classes dependencies are not counted as dependencies of the outer class.

**Noncompliant Code Example**
```java

With a threshold of 5:

class Foo {                        // Noncompliant - Foo depends on too many classes: T1, T2, T3, T4, T5, T6 and T7
  T1 a1;                           // Foo is coupled to T1
  T2 a2;                           // Foo is coupled to T2
  T3 a3;                           // Foo is coupled to T3

  public T4 compute(T5 a, T6 b) {  // Foo is coupled to T4, T5 and T6
    T7 result = a.getResult(b);    // Foo is coupled to T7
    return result;
  }

  public static class Bar {        // Compliant - Bar depends on 2 classes: T8 and T9
    T8 a8;
    T9 a9;
  }
}
```
#### Rule 461: "java.lang.Error" should not be extended
##### Quality Category: Code Smell
java.lang.Error and its subclasses represent abnormal conditions, such as OutOfMemoryError, which should only be encountered by the Java Virtual Machine.

**Noncompliant Code Example**
```java
public class MyException extends Error { /* ... */ }       // Noncompliant


```
**Compliant Solution**
```java
public class MyException extends Exception { /* ... */ }   // Compliant
```
#### Rule 462: Lambdas and anonymous classes should not have too many lines of code
##### Quality Category: Code Smell
Anonymous classes and lambdas (with Java 8) are a very convenient and compact way to inject a behavior without having to create a dedicated class. But those anonymous inner classes and lambdas should be used only if the behavior to be injected can be defined in a few lines of code, otherwise the source code can quickly become unreadable.
#### Rule 463: Public types, methods and fields (API) should be documented with Javadoc
##### Quality Category: Code Smell
Try to imagine using the standard Java API (Collections, JDBC, IO, ...) without Javadoc. It would be a nightmare, because Javadoc is the only way to understand of the contract of the API. Documenting an API with Javadoc increases the productivity of the developers consuming it.

On top of a main description for each member of a public API, the following Javadoc elements are required to be described:

 Parameters, using @param parameterName.
 Thrown exceptions, using @throws exceptionName.
 Method return values, using @return.
 Generic types, using @param <T>.

Furthermore the following guidelines should be followed:

 At least 1 line of description.
 All parameters documented with @param, and names should match.
 All checked exceptions documented with @throws
@return present and documented when not void.
 Placeholders like "TODO", "FIXME", "..." should be avoided.

The following public methods and constructors are not taken into account by this rule:

 Getters and setters.
 Methods overriding another method (usually decorated with @Override).
 Empty constructors.
 Static constants.
**Noncompliant Code Example**
```java
/**
  * This is a Javadoc comment
  */
public class MyClass<T> implements Runnable {    // Noncompliant - missing '@param <T>'

  public static final DEFAULT_STATUS = 0;    // Compliant - static constant
  private int status;                           // Compliant - not public

  public String message;                  // Noncompliant

  public MyClass() {                         // Noncompliant - missing documentation
    this.status = DEFAULT_STATUS;
  }

  public void setStatus(int status) {  // Compliant - setter
    this.status = status;
  }

  @Override
  public void run() {                          // Compliant - has @Override annotation
  }

  protected void doSomething() {    // Compliant - not public
  }

  public void doSomething2(int value) {  // Noncompliant
  }

  public int doSomething3(int value) {  // Noncompliant
    return value;
  }
}


```
**Compliant Solution**
```java
/**
  * This is a Javadoc comment
  * @param <T> the parameter of the class
  */
public class MyClass<T> implements Runnable {

  public static final DEFAULT_STATUS = 0;
  private int status;

  /**
    * This is a Javadoc comment
    */
  public String message;

  /**
   * Class comment...
   */
  public MyClass() {
    this.status = DEFAULT_STATUS;
  }

  public void setStatus(int status) {
    this.status = status;
  }

  @Override
  public void run() {
  }

  protected void doSomething() {
  }

  /**
    * Will do something.
    * @param value the value to be used
    */
  public void doSomething(int value) {

  /**
    *  {@inheritDoc}
    */
  public int doSomething(int value) {
    return value;
  }
}
```
#### Rule 464: Exception handlers should preserve the original exceptions
##### Quality Category: Code Smell
When handling a caught exception, the original exception's message and stack trace should be logged or passed forward.

**Noncompliant Code Example**
```java
try {
  /* ... */
} catch (Exception e) {   // Noncompliant - exception is lost
  LOGGER.info("context");
}

try {
  /* ... */
} catch (Exception e) {  // Noncompliant - exception is lost (only message is preserved)
  LOGGER.info(e.getMessage());
}

try {
  /* ... */
} catch (Exception e) {  // Noncompliant - original exception is lost
  throw new RuntimeException("context");
}


```
**Compliant Solution**
```java
try {
  /* ... */
} catch (Exception e) {
  LOGGER.info(e);  // exception is logged
}

try {
  /* ... */
} catch (Exception e) {
  throw new RuntimeException(e);   // exception stack trace is propagated
}

try {
  /* ... */
} catch (RuntimeException e) {
  doSomething();
  throw e;  // original exception passed forward
} catch (Exception e) {
  throw new RuntimeException(e);  // Conversion into unchecked exception is also allowed
}


```
**Exceptions**
```java

InterruptedException, NumberFormatException, DateTimeParseException, ParseException and MalformedURLException exceptions are arguably used to indicate nonexceptional outcomes. Similarly, handling NoSuchMethodException is often required when dealing with the Java reflection API.

Because they are part of Java, developers have no choice but to deal with them. This rule does not verify that those particular exceptions are correctly handled.

int myInteger;
try {
  myInteger = Integer.parseInt(myString);
} catch (NumberFormatException e) {
  // It is perfectly acceptable to not handle "e" here
  myInteger = 0;
}


Furthermore, no issue will be raised if the exception message is logged with additional information, as it shows that the developer added some context to the error message.

try {
  /* ... */
} catch (Exception e) {
  String message = "Exception raised while authenticating user: " + e.getMessage();
  LOGGER.warn(message); // Compliant - exception message logged with some contextual information
}


*See*

CERT, ERR00-J. - Do not suppress or ignore checked exceptions
MITRE, CWE-778 - Insufficient Logging
 OWASP Top 10 2017 Category A10 - Insufficient Logging & Monitoring

#### Rule 465: Checked exceptions should not be thrown
##### Quality Category: Code Smell
The purpose of checked exceptions is to ensure that errors will be dealt with, either by propagating them or by handling them, but some believe that checked exceptions negatively impact the readability of source code, by spreading this error handling/propagation logic everywhere.

This rule verifies that no method throws a new checked exception.

**Noncompliant Code Example**
```java
public void myMethod1() throws CheckedException {
  ...
  throw new CheckedException(message);   // Noncompliant
  ...
  throw new IllegalArgumentException(message); // Compliant; IllegalArgumentException is unchecked
}

public void myMethod2() throws CheckedException {  // Compliant; propagation allowed
  myMethod1();
}
```
#### Rule 466: Public methods should throw at most one checked exception
##### Quality Category: Code Smell
Using checked exceptions forces method callers to deal with errors, either by propagating them or by handling them. Throwing exceptions makes them fully part of the API of the method.

But to keep the complexity for callers reasonable, methods should not throw more than one kind of checked exception.

**Noncompliant Code Example**
```java
public void delete() throws IOException, SQLException {      // Noncompliant
  /* ... */
}


```
**Compliant Solution**
```java
public void delete() throws SomeApplicationLevelException {
  /* ... */
}


```
**Exceptions**
```java

Overriding methods are not checked by this rule and are allowed to throw several checked exceptions.
```
#### Rule 467: "switch case" clauses should not have too many lines of code
##### Quality Category: Code Smell
The switch statement should be used only to clearly define some new branches in the control flow. As soon as a case clause contains too many statements this highly decreases the readability of the overall control flow statement. In such case, the content of the case clause should be extracted into a dedicated method.

**Noncompliant Code Example**
```java

With the default threshold of 5:

switch (myVariable) {
  case 0: // Noncompliant: 6 lines till next case
    methodCall1("");
    methodCall2("");
    methodCall3("");
    methodCall4("");
    break;
  case 1:
  ...
}


```
**Compliant Solution**
```java
switch (myVariable) {
  case 0:
    doSomething()
    break;
  case 1:
  ...
}
...
private void doSomething(){
    methodCall1("");
    methodCall2("");
    methodCall3("");
    methodCall4("");
}
```
#### Rule 468: Methods should not have too many return statements
##### Quality Category: Code Smell
Having too many return statements in a method increases the method's essential complexity because the flow of execution is broken each time a return statement is encountered. This makes it harder to read and understand the logic of the method.

**Noncompliant Code Example**
```java

With the default threshold of 3:

public boolean myMethod() { // Noncompliant; there are 4 return statements
  if (condition1) {
    return true;
  } else {
    if (condition2) {
      return false;
    } else {
      return true;
    }
  }
  return false;
}
```
#### Rule 469: Labels should not be used
##### Quality Category: Code Smell
Labels are not commonly used in Java, and many developers do not understand how they work. Moreover, their usage makes the control flow harder to follow, which reduces the code's readability.

**Noncompliant Code Example**
```java
int matrix[][] = {
  {1, 2, 3},
  {4, 5, 6},
  {7, 8, 9}
};

outer: for (int row = 0; row < matrix.length; row++) {   // Non-Compliant
  for (int col = 0; col < matrix[row].length; col++) {
    if (col == row) {
      continue outer;
    }
    System.out.println(matrix[row][col]);                // Prints the elements under the diagonal, i.e. 4, 7 and 8
  }
}


```
**Compliant Solution**
```java
for (int row = 1; row < matrix.length; row++) {          // Compliant
  for (int col = 0; col < row; col++) {
    System.out.println(matrix[row][col]);                // Also prints 4, 7 and 8
  }
}
```
#### Rule 470: Magic numbers should not be used
##### Quality Category: Code Smell
A magic number is a number that comes out of nowhere, and is directly used in a statement. Magic numbers are often used, for instance to limit the number of iterations of a loops, to test the value of a property, etc.

Using magic numbers may seem obvious and straightforward when you're writing a piece of code, but they are much less obvious and straightforward at debugging time.

That is why magic numbers must be demystified by first being assigned to clearly named variables before being used.

-1, 0 and 1 are not considered magic numbers.

**Noncompliant Code Example**
```java
public static void doSomething() {
	for(int i = 0; i < 4; i++){                 // Noncompliant, 4 is a magic number
		...
	}
}


```
**Compliant Solution**
```java
public static final int NUMBER_OF_CYCLES = 4;
public static void doSomething() {
  for(int i = 0; i < NUMBER_OF_CYCLES ; i++){
    ...
  }
}


```
**Exceptions**
```java

This rule ignores hashCode methods.
```
#### Rule 471: Files should not have too many lines of code
##### Quality Category: Code Smell
A source file that grows too much tends to aggregate too many responsibilities and inevitably becomes harder to understand and therefore to maintain. Above a specific threshold, it is strongly advised to refactor it into smaller pieces of code which focus on well defined tasks. Those smaller files will not only be easier to understand but also probably easier to test.
#### Rule 472: Lines should not be too long
##### Quality Category: Code Smell
Having to scroll horizontally makes it harder to get a quick overview and understanding of any piece of code.
#### Rule 473: Mutable members should not be stored or returned directly
##### Quality Category: Vulnerability
Mutable objects are those whose state can be changed. For instance, an array is mutable, but a String is not. Mutable class members should never be returned to a caller or accepted and stored directly. Doing so leaves you vulnerable to unexpected changes in your class state.

Instead use an unmodifiable Collection (via Collections.unmodifiableCollection, Collections.unmodifiableList, ...) or make a copy of the mutable object, and store or return the copy instead.

This rule checks that arrays, collections and Dates are not stored or returned directly.

**Noncompliant Code Example**
```java
class A {
  private String [] strings;

  public A () {
    strings = new String[]{"first", "second"};
  }

  public String [] getStrings() {
    return strings; // Noncompliant
  }

  public void setStrings(String [] strings) {
    this.strings = strings;  // Noncompliant
  }
}

public class B {

  private A a = new A();  // At this point a.strings = {"first", "second"};

  public void wreakHavoc() {
    a.getStrings()[0] = "yellow";  // a.strings = {"yellow", "second"};
  }
}


```
**Compliant Solution**
```java
class A {
  private String [] strings;

  public A () {
    strings = new String[]{"first", "second"};
  }

  public String [] getStrings() {
    return strings.clone();
  }

  public void setStrings(String [] strings) {
    this.strings = strings.clone();
  }
}

public class B {

  private A a = new A();  // At this point a.strings = {"first", "second"};

  public void wreakHavoc() {
    a.getStrings()[0] = "yellow";  // a.strings = {"first", "second"};
  }
}



*See*

MITRE, CWE-374 - Passing Mutable Objects to an Untrusted Method
MITRE, CWE-375 - Returning a Mutable Object to an Untrusted Caller
CERT, OBJ05-J. - Do not return references to private mutable class members
CERT, OBJ06-J. - Defensively copy mutable inputs and mutable internal components
CERT, OBJ13-J. - Ensure that references to mutable objects are not exposed
#### Rule 474: Member variable visibility should be specified
##### Quality Category: Vulnerability
Failing to explicitly declare the visibility of a member variable could result it in having a visibility you don't expect, and potentially leave it open to unexpected modification by other classes.

**Noncompliant Code Example**
```java
class Ball {
    String color="red";  // Noncompliant
}
enum A {
  B;
  int a;
}


```
**Compliant Solution**
```java
class Ball {
    private String color="red";  // Compliant
}
enum A {
  B;
  private int a;
}


```
**Exceptions**
```java

Members annotated with Guava's @VisibleForTesting annotation are ignored, as it indicates that visibility has been purposely relaxed to make the code testable.

class Cone {
  @VisibleForTesting
  Logger logger; // Compliant
}

```
#### Rule 475: Class variable fields should not have public accessibility
##### Quality Category: Vulnerability
Public class variable fields do not respect the encapsulation principle and has three main disadvantages:

 Additional behavior such as validation cannot be added.
 The internal representation is exposed, and cannot be changed afterwards.
 Member values are subject to change from anywhere in the code and may not meet the programmer's assumptions.

By using private attributes and accessor methods (set and get), unauthorized modifications are prevented.

**Noncompliant Code Example**
```java
public class MyClass {

  public static final int SOME_CONSTANT = 0;     // Compliant - constants are not checked

  public String firstName;                       // Noncompliant

}


```
**Compliant Solution**
```java
public class MyClass {

  public static final int SOME_CONSTANT = 0;     // Compliant - constants are not checked

  private String firstName;                      // Compliant

  public String getFirstName() {
    return firstName;
  }

  public void setFirstName(String firstName) {
    this.firstName = firstName;
  }

}


```
**Exceptions**
```java

Because they are not modifiable, this rule ignores public final fields.


*See*

MITRE, CWE-493 - Critical Public Variable Without Final Modifier

#### Rule 476: JEE applications should not "getClassLoader"
##### Quality Category: Bug
Using the standard getClassLoader() may not return the right class loader in a JEE context. Instead, go through the currentThread.

**Noncompliant Code Example**
```java
ClassLoader cl = this.getClass().getClassLoader();  // Noncompliant


```
**Compliant Solution**
```java
ClassLoader cl = Thread.currentThread().getContextClassLoader();
```
#### Rule 477: Math should not be performed on floats
##### Quality Category: Bug
For small numbers, float math has enough precision to yield the expected value, but for larger numbers, it does not. BigDecimal is the best alternative, but if a primitive is required, use a double.

**Noncompliant Code Example**
```java
float a = 16777216.0f;
float b = 1.0f;
float c = a + b; // Noncompliant; yields 1.6777216E7 not 1.6777217E7

double d = a + b; // Noncompliant; addition is still between 2 floats


```
**Compliant Solution**
```java
float a = 16777216.0f;
float b = 1.0f;
BigDecimal c = BigDecimal.valueOf(a).add(BigDecimal.valueOf(b));

double d = (double)a + (double)b;


```
**Exceptions**
```java

This rule doesn't raise an issue when the mathematical expression is only used to build a string.

System.out.println("["+getName()+"] " +
           "\n\tMax time to retrieve connection:"+(max/1000f/1000f)+" ms.");


*See*

CERT, FLP02-C. - Avoid using floating-point numbers when precise computation is needed

#### Rule 478: "equals" methods should be symmetric and work for subclasses
##### Quality Category: Bug
A key facet of the equals contract is that if a.equals(b) then b.equals(a), i.e. that the relationship is symmetric.

Using instanceof breaks the contract when there are subclasses, because while the child is an instanceof the parent, the parent is not an instanceof the child. For instance, assume that Raspberry extends Fruit and adds some fields (requiring a new implementation of equals):

Fruit fruit = new Fruit();
Raspberry raspberry = new Raspberry();

if (raspberry instanceof Fruit) { ... } // true
if (fruit instanceof Raspberry) { ... } // false


If similar instanceof checks were used in the classes' equals methods, the symmetry principle would be broken:

raspberry.equals(fruit); // false
fruit.equals(raspberry); //true


Additionally, non final classes shouldn't use a hardcoded class name in the equals method because doing so breaks the method for subclasses. Instead, make the comparison dynamic.

Further, comparing to an unrelated class type breaks the contract for that unrelated type, because while thisClass.equals(unrelatedClass) can return true, unrelatedClass.equals(thisClass) will not.

**Noncompliant Code Example**
```java
public class Fruit extends Food {
  private Season ripe;

  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (Fruit.class == obj.getClass()) { // Noncompliant; broken for child classes
      return ripe.equals(((Fruit)obj).getRipe());
    }
    if (obj instanceof Fruit ) {  // Noncompliant; broken for child classes
      return ripe.equals(((Fruit)obj).getRipe());
    }
    else if (obj instanceof Season) { // Noncompliant; symmetry broken for Season class
      // ...
    }
    //...


```
**Compliant Solution**
```java
public class Fruit extends Food {
  private Season ripe;

  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (this.getClass() == obj.getClass()) {
      return ripe.equals(((Fruit)obj).getRipe());
    }
    return false;
}


*See*

CERT, MET08-J. - Preserve the equality contract when overriding the equals() method
#### Rule 479: Literal suffixes should be upper case
##### Quality Category: Code Smell
Using upper case literal suffixes removes the potential ambiguity between "1" (digit 1) and "l" (letter el) for declaring literals.

**Noncompliant Code Example**
```java
long long1 = 1l; // Noncompliant
float float1 = 1.0f; // Noncompliant
double double1 = 1.0d; // Noncompliant


```
**Compliant Solution**
```java
long long1 = 1L;
float float1 = 1.0F;
double double1 = 1.0D;


*See*

 MISRA C++:2008, 2-13-4 - Literal suffixes shall be upper case
 MISRA C:2012, 7.3 - The lowercase character "l" shall not be used in a literal suffix
CERT DCL16-C. - Use "L," not "l," to indicate a long value
CERT, DCL50-J. - Use visually distinct identifiers
#### Rule 480: "serialVersionUID" should not be declared blindly
##### Quality Category: Code Smell
Providing a serialVersionUID field on Serializable classes is strongly recommended by the Serializable documentation but blindly following that recommendation can be harmful.

serialVersionUID value is stored with the serialized data and this field is verified when deserializing the data to ensure that the code reading the data is compatible with the serialized data. In case of failure, it means the serialized data and the code are not in sync and this fine because you know what's wrong.

When the serialVersionUID is generated by an IDE or blindly hard-coded, there is a high probability that one will forget to update the serialVersionUID value when the Serializable class is later enriched with additional fields. As a consequence, old serialized data will incorrectly be considered compatible with the newer version of the code creating situations which are hard to debug.

Therefore, defining serialVersionUID should be done with care. This rule raises an issue on each serialVersionUID field declared on classes implementing Serializable to be sure the presence and the value of the serialVersionUID field is challenged and validated by the team.

**Noncompliant Code Example**
```java
public class Foo implements Serializable {
  private static final long serialVersionUID = 1;
}

public class BarException extends RuntimeException {
  private static final long serialVersionUID = 8582433437601788991L;
}


*See*

 Vojtech Ruzicka's Programming Blog: Should I explicitly declare serialVersionUID?
#### Rule 481: "Stream.collect()" calls should not be redundant
##### Quality Category: Code Smell
When using the Stream API, call chains should be simplified as much as possible to improve readability and maintainability.

This rule raises an issue when one of the following substitution can be made:

Original	Preferred
stream.collect(counting())	stream.count()
stream.collect(maxBy(comparator))	stream.max(comparator)
stream.collect(minBy(comparator))	stream.min(comparator)
stream.collect(mapping(mapper))	stream.map(mapper).collect()
stream.collect(reducing(...))	stream.reduce(...)
stream.collect(summingInt(mapper))	stream.mapToInt(mapper).sum()
stream.collect(summingLong(mapper))	stream.mapToLong(mapper).sum()
stream.collect(summingDouble(mapper))	stream.mapToDouble(mapper).sum()
**Noncompliant Code Example**
```java
int count = stream.collect(counting());  // Noncompliant


```
**Compliant Solution**
```java
int count = stream.count();
```
#### Rule 482: Local constants should follow naming conventions for constants
##### Quality Category: Code Smell
Shared coding conventions allow teams to collaborate efficiently. This rule checks that all local, final, initialized, primitive variables, have names that match a provided regular expression.

**Noncompliant Code Example**
```java

With the default regular expression ^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$:

public void doSomething() {
  final int local = 42;
  ...
}


```
**Compliant Solution**
```java
public void doSomething() {
  final int LOCAL = 42;
  ...
}
```
#### Rule 483: Unit tests should throw exceptions
##### Quality Category: Code Smell
When the code under test in a unit test throws an exception, the test itself fails. Therefore, there is no need to surround the tested code with a try-catch structure to detect failure. Instead, you can simply move the exception type to the method signature.

This rule raises an issue when there is a fail assertion inside a catch block.

**Noncompliant Code Example**
```java
@Test
public void testMethod() {
  try {
            // Some code
  } catch (MyException e) {
    Assert.fail(e.getMessage());  // Noncompliant
  }
}


```
**Compliant Solution**
```java
@Test
public void testMethod() throws MyException {
    // Some code
}
```
#### Rule 484: Test methods should comply with a naming convention
##### Quality Category: Code Smell
Shared naming conventions allow teams to collaborate efficiently. This rule raises an issue when a test method name does not match the provided regular expression.

**Noncompliant Code Example**
```java

With the default value: ^test[A-Z][a-zA-Z0-9]*$

@Test
public void foo() {  // Noncompliant
  //...
}


```
**Compliant Solution**
```java
@Test
public void testFoo() {
  // ...
}
```
#### Rule 485: Test classes should comply with a naming convention
##### Quality Category: Code Smell
Shared naming conventions allow teams to collaborate efficiently. This rule raises an issue when a test class name does not match the provided regular expression.

**Noncompliant Code Example**
```java

With the default value: ^((Test|IT)[a-zA-Z0-9]+|[A-Z][a-zA-Z0-9]*(Test|IT|TestCase|ITCase))$

class Foo {  // Noncompliant
}


```
**Compliant Solution**
```java
class FooTest {
}
```
#### Rule 486: Value-based objects should not be serialized
##### Quality Category: Code Smell
According to the documentation,

A program may produce unpredictable results if it attempts to distinguish two references to equal values of a value-based class, whether directly via reference equality or indirectly via an appeal to synchronization, identity hashing, serialization...

For example (credit to Brian Goetz), imagine Foo is a value-based class:

Foo[] arr = new Foo[2];
arr[0] = new Foo(0);
arr[1] = new Foo(0);


Serialization promises that on deserialization of arr, elements 0 and 1 will not be aliased. Similarly, in:

Foo[] arr = new Foo[2];
arr[0] = new Foo(0);
arr[1] = arr[0];


Serialization promises that on deserialization of arr, elements 0 and 1 will be aliased.

While these promises are coincidentally fulfilled in current implementations of Java, that is not guaranteed in the future, particularly when true value types are introduced in the language.

This rule raises an issue when a Serializable class defines a non-transient, non-static field field whose type is a known serializable value-based class. Known serializable value-based classes are: all the classes in the java.time package except Clock; the date classes for alternate calendars: HijrahDate, JapaneseDate, MinguoDate, ThaiBuddhistDate.

**Noncompliant Code Example**
```java
class MyClass implements Serializable {
  private HijrahDate date;  // Noncompliant; mark this transient
  // ...
}


```
**Compliant Solution**
```java
class MyClass implements Serializable {
  private transient HijrahDate date;
  // ...
}


*See*

Value-based classes
#### Rule 487: pom elements should be in the recommended order
##### Quality Category: Code Smell
The POM Code Convention is the Maven project's internal recommendation for POM element ordering. It calls for listing modifiers in the following order:

 <modelVersion/>
 <parent/>
 <groupId/>
 <artifactId/>
 <version/>
 <packaging/>
 <name/>
 <description/>
 <url/>
 <inceptionYear/>
 <organization/>
 <licenses/>
 <developers/>
 <contributors/>
 <mailingLists/>
 <prerequisites/>
 <modules/>
 <scm/>
 <issueManagement/>
 <ciManagement/>
 <distributionManagement/>
 <properties/>
 <dependencyManagement/>
 <dependencies/>
 <repositories/>
 <pluginRepositories/>
 <build/>
 <reporting/>
 <profiles/>

Not following this convention has no technical impact, but will reduce the pom's readability because most developers are used to the standard order.


*See*

POM Code Convention
#### Rule 488: Artifact ids should follow a naming convention
##### Quality Category: Code Smell
Shared naming conventions allow teams to collaborate effectively. This rule raises an issue when a pom's artifactId does not match the provided regular expression.

**Noncompliant Code Example**
```java

With the default regular expression: [a-z][a-z-0-9]+

<project ...>
  <artifactId>My_Project</artifactId>  <!-- Noncompliant -->

  <!-- ... -->
</project>


```
**Compliant Solution**
```java
<project ...>
  <artifactId>my-project</artifactId>

  <!-- ... -->
</project>
```
#### Rule 489: Group ids should follow a naming convention
##### Quality Category: Code Smell
Shared naming conventions allow teams to collaborate effectively. This rule raises an issue when the a pom's groupId does not match the provided regular expression.

**Noncompliant Code Example**
```java

With the default regular expression: (com|org)(\.[a-z][a-z-0-9]*)+

<project ...>
  <groupId>myCo</groupId>  <!-- Noncompliant -->

  <!-- ... -->
</project>


```
**Compliant Solution**
```java
<project ...>
  <groupId>com.myco</groupId>

  <!-- ... -->
</project>
```
#### Rule 490: "action" mappings should not have too many "forward" entries
##### Quality Category: Code Smell
It makes sense to handle all related actions in the same place. Thus, the same <action> might logically handle all facets of CRUD on an entity, with no confusion in the naming about which <forward/> handles which facet. But go very far beyond that, and it becomes difficult to maintain a transparent naming convention.

So to ease maintenance, this rule raises an issue when an <action> has more than the allowed number of <forward/> tags.

**Noncompliant Code Example**
```java

With the default threshold of 4:

<action path='/book' type='myapp.BookDispatchAction' name='form' parameter='method'>
  <forward name='create' path='/WEB-INF/jsp/BookCreate.jspx' redirect='false'/>
  <forward name='read' path='/WEB-INF/jsp/BookDetails' redirect='false'/>
  <forward name='update' path='/WEB-INF/jsp/BookUpdate.jspx' redirect='false'/>
  <forward name='delete' path='/WEB-INF/jsp/BookDelete.jspx' redirect='false'/>
  <forward name='authorRead' path='WEB-INF/jsp/AuthorDetails' redirect='false'/>  <!-- Noncompliant -->
</action>


```
**Compliant Solution**
```java
<action path='/book' type='myapp.BookDispatchAction' name='bookForm' parameter='method'>
  <forward name='create' path='/WEB-INF/jsp/BookCreate.jspx' redirect='false'/>
  <forward name='read' path='/WEB-INF/jsp/BookDetails' redirect='false'/>
  <forward name='update' path='/WEB-INF/jsp/BookUpdate.jspx' redirect='false'/>
  <forward name='delete' path='/WEB-INF/jsp/BookDelete.jspx' redirect='false'/>
</action>

<action path='/author' type='myapp.AuthorDispatchAction' name='authorForm' parameter='method'>
  <forward name='authorRead' path='WEB-INF/jsp/AuthorDetails' redirect='false'/>
</action>
```
#### Rule 491: Annotation arguments should appear in the order in which they were declared
##### Quality Category: Code Smell
For optimal code readability, annotation arguments should be specified in the same order that they were declared in the annotation definition.

**Noncompliant Code Example**
```java
@interface Pet {
    String name();
    String surname();
}

@Pet(surname ="", name="") // Noncompliant


```
**Compliant Solution**
```java
@interface Pet {
    String name();
    String surname();
}

@Pet(name ="", surname="") // Compliant
```
#### Rule 492: Default annotation parameter values should not be passed as arguments
##### Quality Category: Code Smell
Specifying the default value for an annotation parameter is redundant. Such values should be omitted in the interests of readability.

**Noncompliant Code Example**
```java
@MyAnnotation(arg = "def")  // Noncompliant
public class MyClass {
  // ...
}
public @interface MyAnnotation {
  String arg() default "def";
}


```
**Compliant Solution**
```java
@MyAnnotation
public class MyClass {
  // ...
}
public @interface MyAnnotation {
  String arg() default "def";
}
```
#### Rule 493: Method parameters should be declared with base types
##### Quality Category: Code Smell
For maximum reusability, methods should accept parameters with as little specialization as possible. So unless specific features from a child class are required by a method, a type higher up the class hierarchy should be used instead.

**Noncompliant Code Example**
```java
public void printSize(ArrayList<Object> list) {  // Collection can be used instead
    System.out.println(list.size());
}

public static void loop(List<Object> list) { // java.lang.Iterable can be used instead
   for (Object o : list) {
     o.toString();
  }
}


```
**Compliant Solution**
```java
public void printSize(Collection<?> list) {  // Collection can be used instead
    System.out.println(list.size());
}

public static void loop(Iterable<?> list) { // java.lang.Iterable can be used instead
   for (Object o : list) {
     o.toString();
  }
}


```
**Exceptions**
```java

Parameters in non-public methods are not checked, because such methods are not intended to be generally reusable. java.lang.String parameters are excluded, because String is immutable and can not be always substituted for more generic type. Parameters used in any other context than method invocation or enhanced for loop are also excluded.
```
#### Rule 494: Fields should not be initialized to default values
##### Quality Category: Code Smell
The compiler automatically initializes class fields to their default values before setting them with any initialization values, so there is no need to explicitly set a field to its default value. Further, under the logic that cleaner code is better code, it's considered poor style to do so.

**Noncompliant Code Example**
```java
public class MyClass {

  int count = 0;  // Noncompliant
  // ...

}


```
**Compliant Solution**
```java
public class MyClass {

  int count;
  // ...

}


```
**Exceptions**
```java

final fields are ignored.
```
#### Rule 495: Multiple loops over the same set should be combined
##### Quality Category: Code Smell
When a method loops multiple over the same set of data, whether it's a list or a set of numbers, it is highly likely that the method could be made more efficient by combining the loops into a single set of iterations.

**Noncompliant Code Example**
```java
public void doSomethingToAList(List<String> strings) {
  for (String str : strings) {
    doStep1(str);
  }
  for (String str : strings) {  // Noncompliant
    doStep2(str);
  }
}


```
**Compliant Solution**
```java
public void doSomethingToAList(List<String> strings) {
  for (String str : strings) {
    doStep1(str);
    doStep2(str);
  }
}
```
#### Rule 496: Classes without "public" constructors should be "final"
##### Quality Category: Code Smell
Classes with only private constructors should be marked final to prevent any mistaken extension attempts.

**Noncompliant Code Example**
```java
public class PrivateConstructorClass {  // Noncompliant
  private PrivateConstructorClass() {
    // ...
  }

  public static int magic(){
    return 42;
  }
}


```
**Compliant Solution**
```java
public final class PrivateConstructorClass {  // Compliant
  private PrivateConstructorClass() {
    // ...
  }

  public static int magic(){
    return 42;
  }
}
```
#### Rule 497: Unnecessary semicolons should be omitted
##### Quality Category: Code Smell
Under the reasoning that cleaner code is better code, the semicolon at the end of a try-with-resources construct should be omitted because it can be omitted.

**Noncompliant Code Example**
```java
try (ByteArrayInputStream b = new ByteArrayInputStream(new byte[10]);  // ignored; this one's required
      Reader r = new InputStreamReader(b);)   // Noncompliant
{
   //do stuff
}


```
**Compliant Solution**
```java
try (ByteArrayInputStream b = new ByteArrayInputStream(new byte[10]);
      Reader r = new InputStreamReader(b))
{
   //do stuff
}
```
#### Rule 498: JUnit assertions should include messages
##### Quality Category: Code Smell
Adding messages to JUnit assertions is an investment in your future productivity. Spend a few seconds writing them now, and you'll save a lot of time on the other end when either the tests fail and you need to quickly diagnose the problem, or when you need to maintain the tests and the assertion messages work as a sort of documentation.

**Noncompliant Code Example**
```java
assertEquals(4, list.size());  // Noncompliant

try {
  fail();  // Noncompliant
} catch (Exception e) {
  assertThat(list.get(0)).isEqualTo("pear");  // Noncompliant
}


```
**Compliant Solution**
```java
assertEquals("There should have been 4 Fruits in the list", 4, list.size());

try {
  fail("And exception is expected here");
} catch (Exception e) {
  assertThat(list.get(0)).as("check first element").overridingErrorMessage("The first element should be a pear, not a %s", list.get(0)).isEqualTo("pear");
}
```
#### Rule 499: Redundant modifiers should not be used
##### Quality Category: Code Smell
The methods declared in an interface are public and abstract by default. Any variables are automatically public static final. There is no need to explicitly declare them so.

Since annotations are implicitly interfaces, the same holds true for them as well.

Similarly, the final modifier is redundant on any method of a final class, and private is redundant on the constructor of an Enum.

**Noncompliant Code Example**
```java
public interface Vehicle {

  public void go(int speed, Direction direction);  // Noncompliant


```
**Compliant Solution**
```java
public interface Vehicle {

  void go(int speed, Direction direction);
```
#### Rule 500: "private" methods that don't access instance data should be "static"
##### Quality Category: Code Smell
private methods that don't access instance data can be static to prevent any misunderstanding about the contract of the method.

**Noncompliant Code Example**
```java
class Utilities {
  private static String magicWord = "magic";

  private String getMagicWord() { // Noncompliant
    return magicWord;
  }

  private void setMagicWord(String value) { // Noncompliant
    magicWord = value;
  }

}


```
**Compliant Solution**
```java
class Utilities {
  private static String magicWord = "magic";

  private static String getMagicWord() {
    return magicWord;
  }

  private static void setMagicWord(String value) {
    magicWord = value;
  }

}


```
**Exceptions**
```java

When java.io.Serializable is implemented the following three methods are excluded by the rule:

private void writeObject(java.io.ObjectOutputStream out) throws IOException;
private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException;
private void readObjectNoData() throws ObjectStreamException;
```
#### Rule 501: Files should not be empty
##### Quality Category: Code Smell
Files with no lines of code clutter a project and should be removed.

**Noncompliant Code Example**
```java
//package org.foo;
//
//public class Bar {}
```
#### Rule 502: Collection methods with O(n) performance should be used carefully
##### Quality Category: Code Smell
The time complexity of method calls on collections is not always obvious. For instance, for most collections the size() method takes constant time, but the time required to execute ConcurrentLinkedQueue.size() is O(n), i.e. directly proportional to the number of elements in the collection. When the collection is large, this could therefore be an expensive operation.

This rule raises an issue when the following O(n) methods are called outside of constructors on class fields:

ArrayList
contains
remove
LinkedList
get
contains
ConcurrentLinkedQueue
size
contains
ConcurrentLinkedDeque
size
contains
CopyOnWriteArrayList
add
contains
remove
CopyOnWriteArraySet
add
contains
remove
**Noncompliant Code Example**
```java
ConcurrentLinkedQueue queue = new ConcurrentLinkedQueue();
//...
log.info("Queue contains " + queue.size() + " elements");  // Noncompliant
```
#### Rule 503: "Exception" should not be caught when not required by called methods
##### Quality Category: Code Smell
Catching Exception seems like an efficient way to handle multiple possible exceptions. Unfortunately, it traps all exception types, both checked and runtime exceptions, thereby casting too broad a net. Indeed, was it really the intention of developers to also catch runtime exceptions? To prevent any misunderstanding, if both checked and runtime exceptions are really expected to be caught, they should be explicitly listed in the catch clause.

This rule raises an issue if Exception is caught when it is not explicitly thrown by a method in the try block.

**Noncompliant Code Example**
```java
try {
  // do something that might throw an UnsupportedDataTypeException or UnsupportedEncodingException
} catch (Exception e) { // Noncompliant
  // log exception ...
}


```
**Compliant Solution**
```java
try {
  // do something
} catch (UnsupportedEncodingException|UnsupportedDataTypeException|RuntimeException e) {
  // log exception ...
}


or if runtime exceptions should not be caught:

try {
  // do something
} catch (UnsupportedEncodingException|UnsupportedDataTypeException e) {
  // log exception ...
}


*See*

MITRE, CWE-396 - Declaration of Catch for Generic Exception
#### Rule 504: "collect" should be used with "Streams" instead of "list::add"
##### Quality Category: Code Smell
While you can use either forEach(list::add) or collect with a Stream, collect is by far the better choice because it's automatically thread-safe and parallellizable.

**Noncompliant Code Example**
```java
List<String> bookNames = new ArrayList<>();
books.stream().filter(book -> book.getIsbn().startsWith("0"))
                .map(Book::getTitle)
                .forEach(bookNames::add);  // Noncompliant


```
**Compliant Solution**
```java
List<String> bookNames = books.stream().filter(book -> book.getIsbn().startsWith("0"))
                .map(Book::getTitle)
                .collect(Collectors.toList());
```
#### Rule 505: Switches should be used for sequences of simple "String" tests
##### Quality Category: Code Smell
Since Java 7, Strings can be used as switch arguments. So when a single String is tested against three or more values in an if/else if structure, it should be converted to a switch instead for greater readability.

Note that this rule is automatically disabled when the project's sonar.java.source is lower than 7.

**Noncompliant Code Example**
```java
if ("red".equals(choice)) {  // Noncompliant
  dispenseRed();
} else if ("blue".equals(choice)) {
  dispenseBlue();
} else if ("yellow".equals(choice)) {
  dispenseYellow();
} else {
  promptUser();
}


```
**Compliant Solution**
```java
switch(choice) {
  case "Red":
    dispenseRed();
    break;
  case "Blue":
    dispenseBlue():
    break;
  case "Yellow":
    dispenseYellow();
    break;
  default:
    promptUser();
    break;
}
```
#### Rule 506: "final" classes should not have "protected" members
##### Quality Category: Code Smell
The difference between private and protected visibility is that child classes can see and use protected members, but they cannot see private ones. Since a final class will have no children, marking the members of a final class protected is confusingly pointless.

Note that the protected members of a class can also be seen and used by other classes that are placed within the same package, this could lead to accidental, unintended access to otherwise private members.

**Noncompliant Code Example**
```java
public final class MyFinalClass {

  protected String name = "Fred";  // Noncompliant
  protected void setName(String name) {  // Noncompliant
    // ...
  }


```
**Compliant Solution**
```java
public final class MyFinalClass {

  private String name = "Fred";
  public void setName(String name) {
    // ...
  }


```
**Exceptions**
```java

Members annotated with Guava's @VisibleForTesting annotation are ignored, as it indicates that visibility has been purposely relaxed to make the code testable.

public final class MyFinalClass {
  @VisibleForTesting
  protected Logger logger; // Compliant

  @VisibleForTesting
  protected int calculateSomethingComplex(String input) { // Compliant
    // ...
  }
}

```
#### Rule 507: Underscores should be used to make large numbers readable
##### Quality Category: Code Smell
Beginning with Java 7, it is possible to add underscores ('_') to numeric literals to enhance readability. The addition of underscores in this manner has no semantic meaning, but makes it easier for maintainers to understand the code.

The number of digits to the left of a decimal point needed to trigger this rule varies by base.

Base	Minimum digits
binary	9
octal	9
decimal	6
hexadecimal	9

It is only the presence of underscores, not their spacing that is scrutinized by this rule.

Note that this rule is automatically disabled when the project's sonar.java.source is lower than 7.

**Noncompliant Code Example**
```java
int i = 10000000;  // Noncompliant; is this 10 million or 100 million?
int  j = 0b01101001010011011110010101011110;  // Noncompliant
long l = 0x7fffffffffffffffL;  // Noncompliant


```
**Compliant Solution**
```java
int i = 10_000_000;
int  j = 0b01101001_01001101_11100101_01011110;
long l = 0x7fff_ffff_ffff_ffffL;
```
#### Rule 508: "Serializable" inner classes of "Serializable" classes should be static
##### Quality Category: Code Smell
Serializing a non-static inner class will result in an attempt at serializing the outer class as well. If the outer class is actually serializable, then the serialization will succeed but possibly write out far more data than was intended.

Making the inner class static (i.e. "nested") avoids this problem, therefore inner classes should be static if possible. However, you should be aware that there are semantic differences between an inner class and a nested one:

 an inner class can only be instantiated within the context of an instance of the outer class.
 a nested (static) class can be instantiated independently of the outer class.
**Noncompliant Code Example**
```java
public class Raspberry implements Serializable {
  // ...

  public class Drupelet implements Serializable {  // Noncompliant; output may be too large
    // ...
  }
}


```
**Compliant Solution**
```java
public class Raspberry implements Serializable {
  // ...

  public static class Drupelet implements Serializable {
    // ...
  }
}


*See*

CERT, SER05-J. - Do not serialize instances of inner classes
#### Rule 509: Classes and methods that rely on the default system encoding should not be used
##### Quality Category: Code Smell
Using classes and methods that rely on the default system encoding can result in code that works fine in its "home" environment. But that code may break for customers who use different encodings in ways that are extremely difficult to diagnose and nearly, if not completely, impossible to reproduce when it's time to fix them.

This rule detects uses of the following classes and methods:

FileReader
FileWriter
 String constructors with a byte[] argument but no Charset argument
String(byte[] bytes)
String(byte[] bytes, int offset, int length)
String.getBytes()
String.getBytes(int srcBegin, int srcEnd, byte[] dst, int dstBegin)
InputStreamReader(InputStream in)
OutputStreamWriter(OutputStream out)
ByteArrayOutputStream.toString()
 Some Formatter constructors
Formatter(String fileName)
Formatter(File file)
Formatter(OutputStream os)
 Some Scanner constructors
Scanner(File source)
Scanner(Path source)
Scanner(InputStream source)
 Some PrintStream constructors
PrintStream(File file)
PrintStream(OutputStream out)
PrintStream(OutputStream out, boolean autoFlush)
PrintStream(String fileName)
 Some PrintWriter constructors
PrintWriter(File file)
PrintWriter(OutputStream out)
PrintWriter(OutputStream out, boolean autoFlush)
PrintWriter(String fileName)
 methods from Apache commons-io library which accept an encoding argument when that argument is null, and overloads of those methods that omit the encoding argument
IOUtils.copy(InputStream, Writer)
IOUtils.copy(Reader, OutputStream)
IOUtils.readLines(InputStream)
IOUtils.toByteArray(Reader)
IOUtils.toByteArray(String)
IOUtils.toCharArray(InputStream)
IOUtils.toInputStream(TypeCriteria.subtypeOf(CharSequence))
IOUtils.toString(byte[])
IOUtils.toString(URI)
IOUtils.toString(URL)
IOUtils.write(char[], OutputStream)
IOUtils.write(CharSequence, OutputStream)
IOUtils.writeLines(Collection, String, OutputStream)
FileUtils.readFileToString(File)
FileUtils.readLines(File)
FileUtils.write(File, CharSequence)
FileUtils.write(File, CharSequence, boolean)
FileUtils.writeStringToFile(File, String)

*See*

CERT, STR04-J. - Use compatible character encodings when communicating string data between JVMs
CERT, STR50-J. - Use the appropriate method for counting characters in a string
#### Rule 510: Simple class names should be used
##### Quality Category: Code Smell
Java's import mechanism allows the use of simple class names. Therefore, using a class' fully qualified name in a file that imports the class is redundant and confusing.

**Noncompliant Code Example**
```java
import java.util.List;
import java.sql.Timestamp;

//...

java.util.List<String> myList;  // Noncompliant
java.sql.Timestamp tStamp; // Noncompliant


```
**Compliant Solution**
```java
import java.util.List;
import java.sql.Timestamp;

//...

List<String> myList;
Timestamp tStamp;
```
#### Rule 511: Variables should not be declared before they are relevant
##### Quality Category: Code Smell
For the sake of clarity, variables should be declared as close to where they're used as possible. This is particularly true when considering methods that contain early returns and the potential to throw exceptions. In these cases, it is not only pointless, but also confusing to declare a variable that may never be used because conditions for an early return are met first.

**Noncompliant Code Example**
```java
public boolean isConditionMet(int a, int b) {
  int difference = a - b;
  MyClass foo = new MyClass(a);  // Noncompliant; not used before early return

  if (difference < 0) {
    return false;
  }

  // ...

  if (foo.doTheThing()) {
    return true;
  }
  return false;
}


```
**Compliant Solution**
```java
public boolean isConditionMet(int a, int b) {
  int difference = a - b;

  if (difference < 0) {
    return false;
  }

  // ...

  MyClass foo = new MyClass(a);
  if (foo.doTheThing()) {
    return true;
  }
  return false;
}
```
#### Rule 512: Extensions and implementations should not be redundant
##### Quality Category: Code Smell
All classes extend Object implicitly. Doing so explicitly is redundant.

Further, declaring the implementation of an interface and one if its parents is also redundant. If you implement the interface, you also implicitly implement its parents and there's no need to do so explicitly.

**Noncompliant Code Example**
```java
public interface MyFace {
  // ...
}

public interface MyOtherFace extends MyFace {
  // ...
}

public class Foo
    extends Object // Noncompliant
    implements MyFace, MyOtherFace {  // Noncompliant
  //...
}


```
**Compliant Solution**
```java
public interface MyFace {
  // ...
}

public interface MyOtherFace extends MyFace {
  // ...
}

public class Foo implements MyOtherFace {
  //...
}
```
#### Rule 513: "==" and "!=" should not be used when "equals" is overridden
##### Quality Category: Code Smell
It is equivalent to use the equality == operator and the equals method to compare two objects if the equals method inherited from Object has not been overridden. In this case both checks compare the object references.

But as soon as equals is overridden, two objects not having the same reference but having the same value can be equal. This rule spots suspicious uses of == and != operators on objects whose equals methods are overridden.

**Noncompliant Code Example**
```java
String firstName = getFirstName(); // String overrides equals
String lastName = getLastName();

if (firstName == lastName) { ... }; // Non-compliant; false even if the strings have the same value


```
**Compliant Solution**
```java
String firstName = getFirstName();
String lastName = getLastName();

if (firstName != null && firstName.equals(lastName)) { ... };


```
**Exceptions**
```java

Comparing two instances of the Class object will not raise an issue:

Class c;
if(c == Integer.class) { // No issue raised
}


Comparing Enum will not raise an issue:

public enum Fruit {
   APPLE, BANANA, GRAPE
}
public boolean isFruitGrape(Fruit candidateFruit) {
  return candidateFruit == Fruit.GRAPE; // it's recommended to activate S4551 to enforce comparison of Enums using ==
}


Comparing with final reference will not raise an issue:

private static final Type DEFAULT = new Type();

void foo(Type other) {
  if (other == DEFAULT) { // Compliant
  //...
  }
}


Comparing with this will not raise an issue:

  public boolean equals(Object other) {
    if (this == other) {  // Compliant
      return false;
    }
 }


Comparing with java.lang.String and boxed types java.lang.Integer, ... will not raise an issue.


*See*

 {rule:squid:S4973} - Strings and Boxed types should be compared using "equals()"
MITRE, CWE-595 - Comparison of Object References Instead of Object Contents
MITRE, CWE-597 - Use of Wrong Operator in String Comparison
CERT, EXP03-J. - Do not use the equality operators when comparing values of boxed primitives
CERT, EXP50-J. - Do not confuse abstract object equality with reference equality

#### Rule 514: An abstract class should have both abstract and concrete methods
##### Quality Category: Code Smell
The purpose of an abstract class is to provide some heritable behaviors while also defining methods which must be implemented by sub-classes.

A class with no abstract methods that was made abstract purely to prevent instantiation should be converted to a concrete class (i.e. remove the abstract keyword) with a private constructor.

A class with only abstract methods and no inheritable behavior should be converted to an interface.

**Noncompliant Code Example**
```java
public abstract class Animal {  // Noncompliant; should be an interface
  abstract void move();
  abstract void feed();
}

public abstract class Color {  // Noncompliant; should be concrete with a private constructor
  private int red = 0;
  private int green = 0;
  private int blue = 0;

  public int getRed() {
    return red;
  }
}


```
**Compliant Solution**
```java
public interface Animal {
  void move();
  void feed();
}

public class Color {
  private int red = 0;
  private int green = 0;
  private int blue = 0;

  private Color () {}

  public int getRed() {
    return red;
  }
}

public abstract class Lamp {

  private boolean switchLamp=false;

  public abstract void glow();

  public void flipSwitch() {
    switchLamp = !switchLamp;
    if (switchLamp) {
      glow();
    }
  }
}
```
#### Rule 515: Sets with elements that are enum values should be replaced with EnumSet
##### Quality Category: Code Smell
When all the elements in a Set are values from the same enum, the Set can be replaced with an EnumSet, which can be much more efficient than other sets because the underlying data structure is a simple bitmap.

**Noncompliant Code Example**
```java
public class MyClass {

  public enum COLOR {
    RED, GREEN, BLUE, ORANGE;
  }

  public void doSomething() {
    Set<COLOR> warm = new HashSet<COLOR>();
    warm.add(COLOR.RED);
    warm.add(COLOR.ORANGE);
  }
}


```
**Compliant Solution**
```java
public class MyClass {

  public enum COLOR {
    RED, GREEN, BLUE, ORANGE;
  }

  public void doSomething() {
    Set<COLOR> warm = EnumSet.of(COLOR.RED, COLOR.ORANGE);
  }
}
```
#### Rule 516: Locale should be used in String operations
##### Quality Category: Code Smell
Failure to specify a locale when calling the methods toLowerCase(), toUpperCase() or format() on String objects means the system default encoding will be used, possibly creating problems with international characters or number representations. For instance with the Turkish language, when converting the small letter 'i' to upper case, the result is capital letter 'I' with a dot over it.

Case conversion without a locale may work fine in its "home" environment, but break in ways that are extremely difficult to diagnose for customers who use different encodings. Such bugs can be nearly, if not completely, impossible to reproduce when it's time to fix them. For locale-sensitive strings, the correct locale should always be used, but Locale.ENGLISH can be used for case-insensitive ones.

**Noncompliant Code Example**
```java
myString.toLowerCase()


```
**Compliant Solution**
```java
myString.toLowerCase(Locale.TR)


*See*

CERT, STR02-J. - Specify an appropriate locale when comparing locale-dependent data
#### Rule 517: Comments should not be located at the end of lines of code
##### Quality Category: Code Smell
This rule verifies that single-line comments are not located at the ends of lines of code. The main idea behind this rule is that in order to be really readable, trailing comments would have to be properly written and formatted (correct alignment, no interference with the visual structure of the code, not too long to be visible) but most often, automatic code formatters would not handle this correctly: the code would end up less readable. Comments are far better placed on the previous empty line of code, where they will always be visible and properly formatted.

**Noncompliant Code Example**
```java
int a1 = b + c; // This is a trailing comment that can be very very long


```
**Compliant Solution**
```java
// This very long comment is better placed before the line of code
int a2 = b + c;
```
#### Rule 518: Track uses of "CHECKSTYLE:OFF" suppression comments
##### Quality Category: Code Smell
This rule allows you to track the use of the Checkstyle suppression comment mechanism.

**Noncompliant Code Example**
```java
// CHECKSTYLE:OFF
```
#### Rule 519: Loggers should be "private static final" and should share a naming convention
##### Quality Category: Code Smell
Regardless of the logging framework in use (logback, log4j, commons-logging, java.util.logging, ...), loggers should be:

private: never be accessible outside of its parent class. If another class needs to log something, it should instantiate its own logger.
static: not be dependent on an instance of a class (an object). When logging something, contextual information can of course be provided in the messages but the logger should be created at class level to prevent creating a logger along with each object.
final: be created once and only once per class.
**Noncompliant Code Example**
```java

With a default regular expression of LOG(?:GER)?:

public Logger logger = LoggerFactory.getLogger(Foo.class);  // Noncompliant


```
**Compliant Solution**
```java
private static final Logger LOGGER = LoggerFactory.getLogger(Foo.class);


```
**Exceptions**
```java

Variables of type org.apache.maven.plugin.logging.Log are ignored.
```
#### Rule 520: Track uses of "NOPMD" suppression comments
##### Quality Category: Code Smell
This rule allows you to track the use of the PMD suppression comment mechanism.

**Noncompliant Code Example**
```java
// NOPMD
```
#### Rule 521: Packages should have a javadoc file 'package-info.java'
##### Quality Category: Code Smell
Each package in a Java project should include a package-info.java file. The purpose of this file is to document the Java package using javadoc and declare package annotations.

Compliant Solution
/**
* This package has non null parameters and is documented.
**/
@ParametersAreNonnullByDefault
package org.foo.bar;

#### Rule 522: The members of an interface or class declaration should appear in a pre-defined order
##### Quality Category: Code Smell
According to the Java Code Conventions as defined by Oracle, the members of a class or interface declaration should appear in the following order in the source files:

 Class and instance variables
 Constructors
 Methods
**Noncompliant Code Example**
```java
public class Foo{
   private int field = 0;
   public boolean isTrue() {...}
   public Foo() {...}                         // Noncompliant, constructor defined after methods
   public static final int OPEN = 4;  //Noncompliant, variable defined after constructors and methods
}


```
**Compliant Solution**
```java
public class Foo{
   public static final int OPEN = 4;
   private int field = 0;
   public Foo() {...}
   public boolean isTrue() {...}
}
```
#### Rule 523: Abstract class names should comply with a naming convention
##### Quality Category: Code Smell
Sharing some naming conventions is a key point to make it possible for a team to efficiently collaborate. This rule allows to check that all abstract class names match a provided regular expression. If a non-abstract class match the regular expression, an issue is raised to suggest to either make it abstract or to rename it.

**Noncompliant Code Example**
```java

With the default regular expression: ^Abstract[A-Z][a-zA-Z0-9]*$:

abstract class MyClass { // Noncompliant
}

class AbstractLikeClass { // Noncompliant
}


```
**Compliant Solution**
```java
abstract class MyAbstractClass {
}

class LikeClass {
}
```
#### Rule 524: Strings literals should be placed on the left side when checking for equality
##### Quality Category: Code Smell
It is preferable to place string literals on the left-hand side of an equals() or equalsIgnoreCase() method call.

This prevents null pointer exceptions from being raised, as a string literal can never be null by definition.

**Noncompliant Code Example**
```java
String myString = null;

System.out.println("Equal? " + myString.equals("foo"));                        // Noncompliant; will raise a NPE
System.out.println("Equal? " + (myString != null && myString.equals("foo")));  // Noncompliant; null check could be removed


```
**Compliant Solution**
```java
System.out.println("Equal?" + "foo".equals(myString));                         // properly deals with the null case
```
#### Rule 525: "throws" declarations should not be superfluous
##### Quality Category: Code Smell
An exception in a throws declaration in Java is superfluous if it is:

 listed multiple times
 a subclass of another listed exception
 a RuntimeException, or one of its descendants
 completely unnecessary because the declared exception type cannot actually be thrown
**Noncompliant Code Example**
```java
void foo() throws MyException, MyException {}  // Noncompliant; should be listed once
void bar() throws Throwable, Exception {}  // Noncompliant; Exception is a subclass of Throwable
void baz() throws RuntimeException {}  // Noncompliant; RuntimeException can always be thrown


```
**Compliant Solution**
```java
void foo() throws MyException {}
void bar() throws Throwable {}
void baz() {}


```
**Exceptions**
```java

The rule will not raise any issue for exceptions that cannot be thrown from the method body:

 in overriding and implementation methods
 in interface default methods
 in non-private methods that only throw, have empty bodies, or a single return statement .
 in overridable methods (non-final, or not member of a final class, non-static, non-private), if the exception is documented with a proper javadoc.
class A extends B {
  @Override
  void doSomething() throws IOException {
    compute(a);
  }

  public void foo() throws IOException {}

  protected void bar() throws IOException {
    throw new UnsupportedOperationException("This method should be implemented in subclasses");
  }

  Object foobar(String s) throws IOException {
    return null;
  }

  /**
   * @throws IOException Overriding classes may throw this exception if they print values into a file
   */
  protected void print() throws IOException { // no issue, method is overridable and the exception has proper javadoc
    System.out.println("foo");
  }
}

```
#### Rule 526: Files should contain an empty newline at the end
##### Quality Category: Code Smell
Some tools work better when files end with an empty line.

This rule simply generates an issue if it is missing.

For example, a Git diff looks like this if the empty line is missing at the end of the file:

+class Test {
+}
\ No newline at end of file

#### Rule 527: Unnecessary imports should be removed
##### Quality Category: Code Smell
The imports part of a file should be handled by the Integrated Development Environment (IDE), not manually by the developer.

Unused and useless imports should not occur if that is the case.

Leaving them in reduces the code's readability, since their presence can be confusing.

**Noncompliant Code Example**
```java
package my.company;

import java.lang.String;        // Noncompliant; java.lang classes are always implicitly imported
import my.company.SomeClass;    // Noncompliant; same-package files are always implicitly imported
import java.io.File;            // Noncompliant; File is not used

import my.company2.SomeType;
import my.company2.SomeType;    // Noncompliant; 'SomeType' is already imported

class ExampleClass {

  public String someString;
  public SomeType something;

}


```
**Exceptions**
```java

Imports for types mentioned in comments, such as Javadocs, are ignored.
```
#### Rule 528: Modifiers should be declared in the correct order
##### Quality Category: Code Smell
The Java Language Specification recommends listing modifiers in the following order:

1. Annotations

2. public

3. protected

4. private

5. abstract

6. static

7. final

8. transient

9. volatile

10. synchronized

11. native

12. strictfp

Not following this convention has no technical impact, but will reduce the code's readability because most developers are used to the standard order.

**Noncompliant Code Example**
```java
static public void main(String[] args) {   // Noncompliant
}


```
**Compliant Solution**
```java
public static void main(String[] args) {   // Compliant
}
```
#### Rule 529: Source code should be indented consistently
##### Quality Category: Code Smell
Proper indentation is a simple and effective way to improve the code's readability. Consistent indentation among the developers within a team also reduces the differences that are committed to source control systems, making code reviews easier.

This rule raises an issue when indentation does not match the configured value. Only the first line of a badly indented section is reported.

**Noncompliant Code Example**
```java

With an indent size of 2:

class Foo {
  public int a;
   public int b;   // Noncompliant, expected to start at column 4

...

  public void doSomething() {
    if(something) {
          doSomethingElse();  // Noncompliant, expected to start at column 6
  }   // Noncompliant, expected to start at column 4
  }
}


```
**Compliant Solution**
```java
class Foo {
  public int a;
  public int b;

...

  public void doSomething() {
    if(something) {
        doSomethingElse();
    }
  }
}
```
#### Rule 530: A close curly brace should be located at the beginning of a line
##### Quality Category: Code Smell
Shared coding conventions make it possible for a team to efficiently collaborate. This rule makes it mandatory to place a close curly brace at the beginning of a line.

**Noncompliant Code Example**
```java
if(condition) {
  doSomething();}


```
**Compliant Solution**
```java
if(condition) {
  doSomething();
}


```
**Exceptions**
```java

When blocks are inlined (open and close curly braces on the same line), no issue is triggered.

if(condition) {doSomething();}

```
#### Rule 531: Close curly brace and the next "else", "catch" and "finally" keywords should be on two different lines
##### Quality Category: Code Smell
Shared coding conventions make it possible for a team to collaborate efficiently.

This rule makes it mandatory to place a closing curly brace and the next else, catch or finally keyword on two different lines.

**Noncompliant Code Example**
```java
public void myMethod() {
  if(something) {
    executeTask();
  } else if (somethingElse) {          // Noncompliant
    doSomethingElse();
  }
  else {                               // Compliant
     generateError();
  }

  try {
    generateOrder();
  } catch (Exception e) {
    log(e);
  }
  finally {
    closeConnection();
  }
}


```
**Compliant Solution**
```java
public void myMethod() {
  if(something) {
    executeTask();
  }
  else if (somethingElse) {
    doSomethingElse();
  }
  else {
     generateError();
  }

  try {
    generateOrder();
  }
  catch (Exception e) {
    log(e);
  }
  finally {
    closeConnection();
  }
}
```
#### Rule 532: Close curly brace and the next "else", "catch" and "finally" keywords should be located on the same line
##### Quality Category: Code Smell
Shared coding conventions make it possible for a team to collaborate efficiently.

This rule makes it mandatory to place closing curly braces on the same line as the next else, catch or finally keywords.

**Noncompliant Code Example**
```java
public void myMethod() {
  if(something) {
    executeTask();
  } else if (somethingElse) {
    doSomethingElse();
  }
  else {                               // Noncompliant
     generateError();
  }

  try {
    generateOrder();
  } catch (Exception e) {
    log(e);
  }
  finally {                            // Noncompliant
    closeConnection();
  }
}


```
**Compliant Solution**
```java
public void myMethod() {
  if(something) {
    executeTask();
  } else if (somethingElse) {
    doSomethingElse();
  } else {
     generateError();
  }

  try {
    generateOrder();
  } catch (Exception e) {
    log(e);
  } finally {
    closeConnection();
  }
}
```
#### Rule 533: An open curly brace should be located at the beginning of a line
##### Quality Category: Code Smell
Shared coding conventions make it possible to collaborate efficiently. This rule makes it mandatory to place the open curly brace at the beginning of a line.

**Noncompliant Code Example**
```java
public void myMethod {  // Noncompliant
  if(something) {  // Noncompliant
    executeTask();
  } else {  // Noncompliant
    doSomethingElse();
  }
}


```
**Compliant Solution**
```java
public void myMethod
{
  if(something)
  {
    executeTask();
  } else
  {
    doSomethingElse();
  }
}
```
#### Rule 534: An open curly brace should be located at the end of a line
##### Quality Category: Code Smell
Shared naming conventions allow teams to collaborate effectively. This rule raises an issue when an open curly brace is not placed at the end of a line of code.

**Noncompliant Code Example**
```java
if(condition)
{
  doSomething();
}


```
**Compliant Solution**
```java
if(condition) {
  doSomething();
}


```
**Exceptions**
```java

When blocks are inlined (left and right curly braces on the same line), no issue is triggered.

if(condition) {doSomething();}

```
#### Rule 535: Tabulation characters should not be used
##### Quality Category: Code Smell
Developers should not need to configure the tab width of their text editors in order to be able to read source code.

So the use of the tabulation character must be banned.
#### Rule 536: Functions should not be defined with a variable number of arguments
##### Quality Category: Code Smell
As stated per effective java :

Varargs methods are a convenient way to define methods that require a variable number of arguments, but they should not be overused. They can produce confusing results if used inappropriately.

**Noncompliant Code Example**
```java
void fun ( String... strings )	// Noncompliant
{
  // ...
}


*See*

 MISRA C:2004, 16.1 - Functions shall not be defined with a variable number of arguments.
 MISRA C++:2008, 8-4-1 - Functions shall not be defined using the ellipsis notation.
CERT, DCL50-CPP. - Do not define a C-style variadic function
#### Rule 537: Track uses of disallowed classes
##### Quality Category: Code Smell
This rule allows banning certain classes.

**Noncompliant Code Example**
```java

Given parameters:

 className:java.lang.String
String name;  // Noncompliant
```
#### Rule 538: Track uses of "@SuppressWarnings" annotations
##### Quality Category: Code Smell
This rule allows you to track the usage of the @SuppressWarnings mechanism.

**Noncompliant Code Example**
```java

With a parameter value of "unused" :

@SuppressWarnings("unused")
@SuppressWarnings("unchecked")  // Noncompliant
```
