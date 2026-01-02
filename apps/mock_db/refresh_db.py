#!/usr/bin/env python3
"""
Refresh Mock SQLite Database
=============================

Creates a test database with sample data for testing DELETE protections.

Usage:
  python refresh_db.py
"""

import sqlite3
import os
from pathlib import Path

DB_PATH = Path(__file__).parent / "test.db"


def create_database():
    """Create fresh database with test tables and data."""

    # Remove existing database
    if DB_PATH.exists():
        os.remove(DB_PATH)
        print(f"Removed existing database: {DB_PATH}")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Create users table
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Create products table
    cursor.execute("""
        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            stock INTEGER DEFAULT 0,
            category TEXT
        )
    """)

    # Create orders table
    cursor.execute("""
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            status TEXT DEFAULT 'pending',
            ordered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        )
    """)

    # Insert sample users
    users = [
        ("Alice Smith", "alice@example.com", "admin"),
        ("Bob Jones", "bob@example.com", "user"),
        ("Charlie Brown", "charlie@example.com", "user"),
        ("Diana Prince", "diana@example.com", "moderator"),
        ("Eve Wilson", "eve@example.com", "user"),
    ]
    cursor.executemany(
        "INSERT INTO users (name, email, role) VALUES (?, ?, ?)",
        users
    )

    # Insert sample products
    products = [
        ("Laptop", 999.99, 50, "electronics"),
        ("Mouse", 29.99, 200, "electronics"),
        ("Keyboard", 79.99, 150, "electronics"),
        ("Monitor", 299.99, 75, "electronics"),
        ("Desk Chair", 199.99, 30, "furniture"),
        ("Standing Desk", 499.99, 20, "furniture"),
        ("Coffee Mug", 12.99, 500, "accessories"),
        ("Notebook", 5.99, 1000, "accessories"),
    ]
    cursor.executemany(
        "INSERT INTO products (name, price, stock, category) VALUES (?, ?, ?, ?)",
        products
    )

    # Insert sample orders
    orders = [
        (1, 1, 1, "completed"),
        (1, 2, 2, "completed"),
        (2, 3, 1, "pending"),
        (3, 4, 1, "shipped"),
        (4, 5, 1, "pending"),
        (5, 6, 1, "cancelled"),
        (2, 7, 3, "completed"),
        (3, 8, 10, "pending"),
    ]
    cursor.executemany(
        "INSERT INTO orders (user_id, product_id, quantity, status) VALUES (?, ?, ?, ?)",
        orders
    )

    conn.commit()
    conn.close()

    print(f"Created database: {DB_PATH}")
    print(f"  - users: 5 rows")
    print(f"  - products: 8 rows")
    print(f"  - orders: 8 rows")
    print()
    print("Test commands:")
    print(f'  sqlite3 {DB_PATH} "SELECT * FROM users;"')
    print(f'  sqlite3 {DB_PATH} "DELETE FROM users WHERE id = 1;"')


if __name__ == "__main__":
    create_database()
