/**
 * TEST FILE - Contains intentional vulnerabilities for testing VibeCheck
 * Run: python scripts/scan.py tests/vulnerable.js
 * Expected: Multiple findings at various severity levels
 */

// CRITICAL: Hardcoded API keys
const OPENAI_KEY = "sk-abc123456789012345678901234567890123456789";
const ANTHROPIC_KEY = "sk-ant-abc123-def456-ghi789-jkl012-mno345";
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const STRIPE_KEY = "sk_live_abc123def456ghi789jkl012mno345pqr678";

// CRITICAL: SQL Injection
function getUser(userId) {
    return db.query("SELECT * FROM users WHERE id = " + userId);
}

async function searchUsers(name) {
    const query = `SELECT * FROM users WHERE name = '${name}'`;
    return await db.execute(query);
}

// CRITICAL: Command Injection
function processFile(filename) {
    exec("cat " + filename);
}

// CRITICAL: Dangerous configurations
const corsOptions = {
    origin: "*",
    credentials: true
};

const httpsAgent = new https.Agent({
    rejectUnauthorized: false
});

// HIGH: XSS vulnerabilities
function renderUserContent(content) {
    document.getElementById("output").innerHTML = content;
}

function UserProfile({ bio }) {
    return <div dangerouslySetInnerHTML={{ __html: bio }} />;
}

// HIGH: Insecure deserialization (Python patterns, but showing concept)
// pickle.loads(user_data)  // Would catch in .py file

// HIGH: Weak cryptography
function hashPassword(password) {
    return md5(password);  // Never do this!
}

// MEDIUM: Debug mode
const config = {
    debug: true,
    verbose: true
};

// MEDIUM: Logging sensitive data
function login(username, password) {
    console.log("Login attempt:", username, password);
}

// MEDIUM: Security TODO
// TODO: add authentication to this endpoint
function publicApi() {
    return getAllUserData();
}

// MEDIUM: Non-HTTPS URL
const API_ENDPOINT = "http://api.example.com/v1";

// This file should produce 15+ findings when scanned
