import argparse, base64, hashlib, hmac, re, secrets, sys

TPL_PATH = "nocopy_template.html"
BEGIN = "<!-- nocopy-protect start -->"
END   = "<!-- nocopy-protect end -->"

def err(action: str, path: str, msg: str) -> None:
    """
    Print a standardized error message to stderr.

    Args:
        action (str): Context/action.
        path   (str): Related file path or identifier.
        msg    (str): Human-readable error details.

    Returns:
        None
    """
    print(f"[error] {action} {path}: {msg}", file=sys.stderr)

def load_template() -> str:
    """
    Load the HTML protection template from TPL_PATH.

    Returns:
        str: The template contents with placeholders (__SALT__, __HASH__, __ITER__).
    """
    try:
        with open(TPL_PATH, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        err("template", TPL_PATH, "file not found")
        sys.exit(1)

def derive(password: str, salt: bytes, iterations: int = 120000) -> bytes:
    """
    Derive a hash from the given password.

    Returns:
        bytes: 32-byte derived key.
    """
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)

def already_protected(html: str) -> bool:
    """
    Check if the HTML already contains the protection block markers.

    Args:
        html (str): HTML file content.

    Returns:
        bool: True if protection block is found, False otherwise.
    """
    return (BEGIN in html) and (END in html)

def inject(html: str, password: str) -> str:
    """
    Insert the protection block into the <head> of the HTML.

    Args:
        html (str): Original HTML content.
        password (str): Password for unlocking.

    Returns:
        str: Modified HTML with protection block injected.
    """
    if already_protected(html):
        return html
    salt = secrets.token_bytes(16)
    iterations = 120000
    digest = derive(password, salt, iterations)
    
    tpl = load_template()
    block = (tpl
             .replace("__SALT__", base64.b64encode(salt).decode())
             .replace("__HASH__", base64.b64encode(digest).decode())
             .replace("__ITER__", str(iterations)))
    
    # insert after <head>
    if re.search(r"<head[^>]*>", html, flags=re.IGNORECASE):
        return re.sub(r"(<head[^>]*>)", r"\1\n" + block, html, count=1, flags=re.IGNORECASE)
    # if no <head>
    return block + "\n" + html

def extract_block(html: str):
    """
    Find the injected protection block inside the HTML.

    Args:
        html (str): HTML file content.

    Returns:
        re.Match | None: Regex match object if block is found, otherwise None.
    """
    return re.search(re.escape(BEGIN) + r"(.*?)" + re.escape(END), html, flags=re.S)

def parse_params(guard_block):
    """
    Parse params from the injected block.

    Args:
        guard_block (str): HTML protection block (between BEGIN and END).

    Returns:
        tuple[bytes, bytes, int] | None
    """
    s_match = re.search(r'salt_b64:\s*[\'"]([^\'"]+)[\'"]', guard_block)
    h_match = re.search(r'hash_b64:\s*[\'"]([^\'"]+)[\'"]', guard_block)
    i_match = re.search(r'iter:\s*(\d+)', guard_block)
    if not (s_match and h_match and i_match):
        return None
    try:
        salt = base64.b64decode(s_match.group(1))
        digest = base64.b64decode(h_match.group(1))
        iterations = int(i_match.group(1))
    except Exception:
        return None
    return (salt, digest, iterations)

def verify_password(html: str, password: str) -> bool:
    """
    Verify that the given password matches the stored hash in the HTML block.

    Args:
        html (str): HTML file content (with protection block).
        password (str): Password entered by user.

    Returns:
        bool: True if password is correct, False otherwise.
    """
    m = extract_block(html)
    if not m:
        return False

    params = parse_params(m.group(0))
    if params is None:
        return False
    salt, stored_digest, iterations = params

    try:
        calc_digest = derive(password, salt, iterations)
    except Exception:
        return False

    return hmac.compare_digest(calc_digest, stored_digest)

def remove(html: str) -> str:
    """
    Remove the protection block from the HTML.

    Args:
        html (str): HTML file content.

    Returns:
        str: HTML without the protection block.
    """
    pattern = rf'\r?\n?{re.escape(BEGIN)}.*?{re.escape(END)}\r?\n?'
    return re.sub(pattern, "", html, flags=re.S)

def process_file(path: str, mode: str, password: str | None) -> int:
    """
    Process HTML file according to the mode.

    Args:
        path: Path to HTML file.
        mode: "enable" | "disable" | "status".
        password: Password string or None.

    Returns:
        int: Exit code (0 = success).
    """
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            html = f.read()
    except OSError as e:
        err("read", path, str(e))
        return 1

    if mode == "status":
        print(f"[status] {path}: {'protected' if already_protected(html) else 'unprotected'}")
        return 0

    if mode == "enable":
        if password is None:
            err("enable", path, "password required (--password or -p)")
            return 1
        if already_protected(html):
            print(f"[enable] {path}: already protected (no changes)")
            return 0
        new_html = inject(html, password)
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(new_html)
        except OSError as e:
            err("write", path, str(e))
            return 1
        print(f"[enable] {path}: protection injected")
        return 0

    if mode == "disable":
        if not already_protected(html):
            print(f"[disable] {path}: no protection block found (no changes)")
            return 0
        if password is None or not verify_password(html, password):
            err("disable", path, "wrong password")
            return 1
        new_html = remove(html)
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(new_html)
        except OSError as e:
            err("write", path, str(e))
            return 1
        print(f"[disable] {path}: protection removed")
        return 0

    err("cli", path, f"unknown mode: {mode}")
    return 1

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["enable", "disable", "status"])
    parser.add_argument("path")
    parser.add_argument("--password", "-p")
    args = parser.parse_args()

    try:
        exit_code = process_file(args.path, args.mode, args.password)
    except Exception as e:
        err("unexpected", args.path, str(e))
        exit_code = 1
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
