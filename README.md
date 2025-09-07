# NoCopy HTML Script

## Overview

This project provides a Python script that injects a **no-copy protection block** into any HTML document.  
By default, text selection and copying are disabled. Copy protection can only be disabled with the correct password.

- Passwords are verified on the client side using **PBKDF2 with SHA-256**.
- The protection status is clearly indicated through a floating menu in the top-right corner of the page.

## Usage

```bash
python main.py [command] [-p PASSWORD | --password PASSWORD] [path-to-html]
```

## Commands

- `enable` - inject protection into the HTML document
- `disable` - remove protection block from the HTML document
- `status` - check if protection is currently enabled

## Examples

```bash
python main.py enable index.html -p mysecret
```

```bash
python main.py disable index.html -p mysecret
```

```bash
python main.py status index.html
```

## Files

- `main.py` - core program logic (CLI for injection, removal, and status check)
- `nocopy_template.html` - HTML/JS template injected into target documents
- `index.html` - example page for quick testing

## License

This project is published for non-commercial, educational use only.
