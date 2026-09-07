"""
safe.py - Secure, Hardened Python Reference Implementation
Demonstrates remediation best practices: environment variables for secrets,
parameterized SQL queries, safe literal evaluation, and hardened subprocess execution.
"""

import os
import sys
import json
import ast
import subprocess
import requests

# 1. Secure Secret Management via Environment Variables
API_KEY = os.getenv("API_KEY", "")
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD", "")
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY", "")


def authenticate_user(cursor, username: str, password_hash: str):
    # 2. Parameterized SQL Query (Prevents SQL Injection)
    query = "SELECT id, username, role FROM users WHERE username = ? AND password_hash = ?"
    cursor.execute(query, (username, password_hash))
    return cursor.fetchone()


def execute_safe_calculation(user_math_expr: str):
    # 3. Safe parsing with ast.literal_eval (Restricted to safe Python literals)
    try:
        result = ast.literal_eval(user_math_expr)
        return result
    except (ValueError, SyntaxError) as err:
        return {"error": "Invalid mathematical expression format"}


def ping_server_safe(target_host: str):
    # 4. Safe Subprocess with shell=False and list arguments (Prevents command injection)
    # Validates target_host parameter
    if not target_host or any(char in target_host for char in [";", "&", "|", "`", "$"]):
        raise ValueError("Invalid target host characters detected")

    result = subprocess.run(
        ["ping", "-c", "1", target_host],
        capture_output=True,
        text=True,
        check=False,
        shell=False
    )
    return result.returncode == 0


if __name__ == "__main__":
    print("Running secure reference application.")
