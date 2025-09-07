import argparse, re, sys

TPL_PATH = "nocopy_template.html"
BEGIN = "<!-- nocopy-protect start -->"
END   = "<!-- nocopy-protect end -->"

def load_template() -> str:
    """
    Load the HTML protection template from TPL_PATH.

    Returns:
        str: The template contents with placeholders (__SALT__, __HASH__, __ITER__).
    """
    with open(TPL_PATH, 'r', encoding='utf-8') as f:
        return f.read()

def derive() -> bytes:
    """
    Derive a hash from the given password.

    Returns:
        bytes: 32-byte derived key.
    """
    pass

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
    block = load_template()
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
    pass

def parse_params():
    """
    Parse params from the injected block.

    Returns:
    """
    pass

def verify_password(html: str, password: str) -> bool:
    """
    Verify that the given password matches the stored hash in the HTML block.

    Args:
        html (str): HTML file content (with protection block).
        password (str): Password entered by user.

    Returns:
        bool: True if password is correct, False otherwise.
    """
    pass

def remove(html: str) -> str:
    """
    Remove the protection block from the HTML.

    Args:
        html (str): HTML file content.

    Returns:
        str: HTML without the protection block.
    """
    pass

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
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        html = f.read()

    if mode == "status":
        print(f"[status] {path}: {'protected' if already_protected(html) else 'unprotected'}")
        return 0

    if mode == "enable":
        if already_protected(html):
            print(f"[enable] {path}: already protected (no changes)")
            return 0
        new_html = inject(html, password or "")
        with open(path, "w", encoding="utf-8") as f:
            f.write(new_html)
        print(f"[enable] {path}: protection injected")
        return 0

    if mode == "disable":
        if not already_protected(html):
            print(f"[disable] {path}: no protection block found (no changes)")
            return 0
        new_html = remove(html)
        with open(path, "w", encoding="utf-8") as f:
            f.write(new_html)
        print(f"[disable] {path}: protection removed")
        return 0

    print(f"[error] unknown mode: {mode}")
    return 2

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["enable", "disable", "status"])
    parser.add_argument("file")
    args = parser.parse_args()

    exit_code = process_file(args.file, args.mode, None)
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
