"""Curated CVE dataset with vulnerable code snippets for patch testing.

Each entry has: cwe_id, cwe_name, description, vulnerable_code, expected_fix_pattern.
10 snippets per CWE category × 5 categories = 50 total.
"""

VULNERABLE_SNIPPETS = [
    # === CWE-89: SQL Injection (10 snippets) ===
    {"cwe_id": "CWE-89", "cwe_name": "SQL Injection", "id": "sqli-01",
     "vulnerable_code": 'def get_user(username):\n    query = "SELECT * FROM users WHERE name = \'%s\'" % username\n    cursor.execute(query)\n    return cursor.fetchone()'},
    {"cwe_id": "CWE-89", "cwe_name": "SQL Injection", "id": "sqli-02",
     "vulnerable_code": 'def search_products(term):\n    cursor.execute(f"SELECT * FROM products WHERE name LIKE \'%{term}%\'")\n    return cursor.fetchall()'},
    {"cwe_id": "CWE-89", "cwe_name": "SQL Injection", "id": "sqli-03",
     "vulnerable_code": 'def delete_user(user_id):\n    query = "DELETE FROM users WHERE id = " + str(user_id)\n    cursor.execute(query)'},
    {"cwe_id": "CWE-89", "cwe_name": "SQL Injection", "id": "sqli-04",
     "vulnerable_code": 'def login(username, password):\n    query = "SELECT * FROM users WHERE username=\'" + username + "\' AND password=\'" + password + "\'"\n    cursor.execute(query)\n    return cursor.fetchone()'},
    {"cwe_id": "CWE-89", "cwe_name": "SQL Injection", "id": "sqli-05",
     "vulnerable_code": 'def update_email(user_id, email):\n    cursor.execute("UPDATE users SET email = \'%s\' WHERE id = %s" % (email, user_id))'},
    {"cwe_id": "CWE-89", "cwe_name": "SQL Injection", "id": "sqli-06",
     "vulnerable_code": 'def get_orders(status):\n    query = "SELECT * FROM orders WHERE status = \'{}\'" .format(status)\n    cursor.execute(query)\n    return cursor.fetchall()'},
    {"cwe_id": "CWE-89", "cwe_name": "SQL Injection", "id": "sqli-07",
     "vulnerable_code": 'def count_by_category(cat):\n    cursor.execute("SELECT COUNT(*) FROM items WHERE category = \'" + cat + "\'")\n    return cursor.fetchone()[0]'},
    {"cwe_id": "CWE-89", "cwe_name": "SQL Injection", "id": "sqli-08",
     "vulnerable_code": 'def find_user_by_email(email):\n    sql = f"SELECT id, name FROM users WHERE email = \'{email}\'"\n    cursor.execute(sql)\n    return cursor.fetchone()'},
    {"cwe_id": "CWE-89", "cwe_name": "SQL Injection", "id": "sqli-09",
     "vulnerable_code": 'def insert_comment(post_id, text):\n    cursor.execute("INSERT INTO comments (post_id, text) VALUES (%s, \'%s\')" % (post_id, text))'},
    {"cwe_id": "CWE-89", "cwe_name": "SQL Injection", "id": "sqli-10",
     "vulnerable_code": 'def get_report(date_from, date_to):\n    q = "SELECT * FROM reports WHERE date BETWEEN \'" + date_from + "\' AND \'" + date_to + "\'"\n    cursor.execute(q)\n    return cursor.fetchall()'},

    # === CWE-79: XSS (10 snippets) ===
    {"cwe_id": "CWE-79", "cwe_name": "Cross-Site Scripting", "id": "xss-01",
     "vulnerable_code": 'function showMessage(msg) {\n    document.getElementById("output").innerHTML = msg;\n}'},
    {"cwe_id": "CWE-79", "cwe_name": "Cross-Site Scripting", "id": "xss-02",
     "vulnerable_code": 'function displaySearch(query) {\n    document.write("<h2>Results for: " + query + "</h2>");\n}'},
    {"cwe_id": "CWE-79", "cwe_name": "Cross-Site Scripting", "id": "xss-03",
     "vulnerable_code": '$(document).ready(function() {\n    var name = getUrlParam("name");\n    $("#greeting").html("Welcome, " + name + "!");\n});'},
    {"cwe_id": "CWE-79", "cwe_name": "Cross-Site Scripting", "id": "xss-04",
     "vulnerable_code": '@app.route("/profile")\ndef profile():\n    name = request.args.get("name")\n    return render_template_string("<h1>Hello " + name + "</h1>")'},
    {"cwe_id": "CWE-79", "cwe_name": "Cross-Site Scripting", "id": "xss-05",
     "vulnerable_code": 'function updateBio(text) {\n    document.getElementById("bio").innerHTML = text;\n}'},
    {"cwe_id": "CWE-79", "cwe_name": "Cross-Site Scripting", "id": "xss-06",
     "vulnerable_code": 'function renderComment(comment) {\n    var el = document.createElement("div");\n    el.innerHTML = "<p>" + comment.text + "</p>";\n    document.body.appendChild(el);\n}'},
    {"cwe_id": "CWE-79", "cwe_name": "Cross-Site Scripting", "id": "xss-07",
     "vulnerable_code": 'function showError(err) {\n    document.write("<div class=\'error\'>" + err + "</div>");\n}'},
    {"cwe_id": "CWE-79", "cwe_name": "Cross-Site Scripting", "id": "xss-08",
     "vulnerable_code": '@app.route("/search")\ndef search():\n    q = request.args.get("q", "")\n    return render_template_string(f"<p>Searching for: {q}</p>")'},
    {"cwe_id": "CWE-79", "cwe_name": "Cross-Site Scripting", "id": "xss-09",
     "vulnerable_code": 'function setTitle(title) {\n    document.getElementById("page-title").innerHTML = title;\n}'},
    {"cwe_id": "CWE-79", "cwe_name": "Cross-Site Scripting", "id": "xss-10",
     "vulnerable_code": '$(function() {\n    var feedback = getUrlParam("msg");\n    $(".notification").html(feedback);\n});'},

    # === CWE-120: Buffer Overflow (10 snippets, C) ===
    {"cwe_id": "CWE-120", "cwe_name": "Buffer Overflow", "id": "bof-01",
     "vulnerable_code": 'void greet(char *name) {\n    char buf[64];\n    strcpy(buf, name);\n    printf("Hello, %s!\\n", buf);\n}'},
    {"cwe_id": "CWE-120", "cwe_name": "Buffer Overflow", "id": "bof-02",
     "vulnerable_code": 'void concat_path(char *dir, char *file) {\n    char path[256];\n    strcpy(path, dir);\n    strcat(path, "/");\n    strcat(path, file);\n}'},
    {"cwe_id": "CWE-120", "cwe_name": "Buffer Overflow", "id": "bof-03",
     "vulnerable_code": 'char *read_input() {\n    char buf[128];\n    gets(buf);\n    return strdup(buf);\n}'},
    {"cwe_id": "CWE-120", "cwe_name": "Buffer Overflow", "id": "bof-04",
     "vulnerable_code": 'void log_message(char *level, char *msg) {\n    char log_entry[256];\n    sprintf(log_entry, "[%s] %s", level, msg);\n    write_log(log_entry);\n}'},
    {"cwe_id": "CWE-120", "cwe_name": "Buffer Overflow", "id": "bof-05",
     "vulnerable_code": 'void process_name(char *input) {\n    char first[32], last[32];\n    strcpy(first, input);\n    strcpy(last, input);\n}'},
    {"cwe_id": "CWE-120", "cwe_name": "Buffer Overflow", "id": "bof-06",
     "vulnerable_code": 'void build_query(char *table, char *field) {\n    char query[512];\n    sprintf(query, "SELECT %s FROM %s", field, table);\n}'},
    {"cwe_id": "CWE-120", "cwe_name": "Buffer Overflow", "id": "bof-07",
     "vulnerable_code": 'void copy_header(char *src) {\n    char header[64];\n    strcpy(header, src);\n}'},
    {"cwe_id": "CWE-120", "cwe_name": "Buffer Overflow", "id": "bof-08",
     "vulnerable_code": 'int main() {\n    char username[32];\n    printf("Enter username: ");\n    gets(username);\n    authenticate(username);\n}'},
    {"cwe_id": "CWE-120", "cwe_name": "Buffer Overflow", "id": "bof-09",
     "vulnerable_code": 'void format_output(char *data) {\n    char output[128];\n    sprintf(output, "Result: %s (processed)", data);\n    display(output);\n}'},
    {"cwe_id": "CWE-120", "cwe_name": "Buffer Overflow", "id": "bof-10",
     "vulnerable_code": 'void merge_strings(char *a, char *b) {\n    char result[64];\n    strcpy(result, a);\n    strcat(result, b);\n}'},

    # === CWE-22: Path Traversal (10 snippets) ===
    {"cwe_id": "CWE-22", "cwe_name": "Path Traversal", "id": "path-01",
     "vulnerable_code": 'def read_file(filename):\n    path = "/var/data/" + filename\n    with open(path) as f:\n        return f.read()'},
    {"cwe_id": "CWE-22", "cwe_name": "Path Traversal", "id": "path-02",
     "vulnerable_code": '@app.route("/download")\ndef download():\n    name = request.args.get("file")\n    return send_file(os.path.join("/uploads", name))'},
    {"cwe_id": "CWE-22", "cwe_name": "Path Traversal", "id": "path-03",
     "vulnerable_code": 'def get_template(name):\n    path = "templates/" + name\n    with open(path) as f:\n        return f.read()'},
    {"cwe_id": "CWE-22", "cwe_name": "Path Traversal", "id": "path-04",
     "vulnerable_code": 'def save_upload(filename, data):\n    path = os.path.join("/uploads", filename)\n    with open(path, "wb") as f:\n        f.write(data)'},
    {"cwe_id": "CWE-22", "cwe_name": "Path Traversal", "id": "path-05",
     "vulnerable_code": 'def read_config(name):\n    with open("config/" + name + ".yaml") as f:\n        return yaml.safe_load(f)'},
    {"cwe_id": "CWE-22", "cwe_name": "Path Traversal", "id": "path-06",
     "vulnerable_code": 'def serve_static(path):\n    full_path = "/var/www/static/" + path\n    with open(full_path, "rb") as f:\n        return f.read()'},
    {"cwe_id": "CWE-22", "cwe_name": "Path Traversal", "id": "path-07",
     "vulnerable_code": 'def load_plugin(name):\n    module_path = "plugins/" + name + ".py"\n    with open(module_path) as f:\n        exec(f.read())'},
    {"cwe_id": "CWE-22", "cwe_name": "Path Traversal", "id": "path-08",
     "vulnerable_code": 'def get_log(date):\n    path = "/var/log/app/" + date + ".log"\n    with open(path) as f:\n        return f.read()'},
    {"cwe_id": "CWE-22", "cwe_name": "Path Traversal", "id": "path-09",
     "vulnerable_code": 'def read_report(report_id):\n    path = "reports/" + report_id + ".pdf"\n    with open(path, "rb") as f:\n        return f.read()'},
    {"cwe_id": "CWE-22", "cwe_name": "Path Traversal", "id": "path-10",
     "vulnerable_code": 'def delete_temp(filename):\n    os.remove("/tmp/" + filename)'},

    # === CWE-327: Weak Cryptography (10 snippets) ===
    {"cwe_id": "CWE-327", "cwe_name": "Insecure Cryptography", "id": "crypto-01",
     "vulnerable_code": 'import hashlib\ndef hash_password(password):\n    return hashlib.md5(password.encode()).hexdigest()'},
    {"cwe_id": "CWE-327", "cwe_name": "Insecure Cryptography", "id": "crypto-02",
     "vulnerable_code": 'import hashlib\ndef verify_integrity(data):\n    return hashlib.sha1(data.encode()).hexdigest()'},
    {"cwe_id": "CWE-327", "cwe_name": "Insecure Cryptography", "id": "crypto-03",
     "vulnerable_code": 'import hashlib\ndef generate_token(user_id):\n    return hashlib.md5(str(user_id).encode()).hexdigest()'},
    {"cwe_id": "CWE-327", "cwe_name": "Insecure Cryptography", "id": "crypto-04",
     "vulnerable_code": 'import hashlib\ndef checksum(file_content):\n    return hashlib.md5(file_content).hexdigest()'},
    {"cwe_id": "CWE-327", "cwe_name": "Insecure Cryptography", "id": "crypto-05",
     "vulnerable_code": 'import hashlib\ndef hash_email(email):\n    return hashlib.sha1(email.lower().encode()).hexdigest()'},
    {"cwe_id": "CWE-327", "cwe_name": "Insecure Cryptography", "id": "crypto-06",
     "vulnerable_code": 'import hashlib\ndef sign_message(msg, key):\n    return hashlib.md5((msg + key).encode()).hexdigest()'},
    {"cwe_id": "CWE-327", "cwe_name": "Insecure Cryptography", "id": "crypto-07",
     "vulnerable_code": 'import hashlib\ndef derive_key(password, salt):\n    return hashlib.sha1((password + salt).encode()).hexdigest()'},
    {"cwe_id": "CWE-327", "cwe_name": "Insecure Cryptography", "id": "crypto-08",
     "vulnerable_code": 'import hashlib\ndef session_id(username):\n    return hashlib.md5(username.encode()).hexdigest()[:16]'},
    {"cwe_id": "CWE-327", "cwe_name": "Insecure Cryptography", "id": "crypto-09",
     "vulnerable_code": 'import hashlib\ndef api_key_hash(key):\n    return hashlib.sha1(key.encode()).hexdigest()'},
    {"cwe_id": "CWE-327", "cwe_name": "Insecure Cryptography", "id": "crypto-10",
     "vulnerable_code": 'import hashlib\ndef cache_key(data):\n    return hashlib.md5(str(data).encode()).hexdigest()'},
]


def get_snippets(cwe_filter=None):
    """Get vulnerable code snippets, optionally filtered by CWE."""
    if cwe_filter:
        return [s for s in VULNERABLE_SNIPPETS if s["cwe_id"] == cwe_filter]
    return VULNERABLE_SNIPPETS


def get_cwe_categories():
    """Return list of unique CWE categories."""
    return sorted(set(s["cwe_id"] for s in VULNERABLE_SNIPPETS))
