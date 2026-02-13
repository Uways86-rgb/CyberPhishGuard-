import sqlite3

def inspect_database(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Get all table names
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()

    print("Database Tables Summary:")
    print("=" * 50)

    for table in tables:
        table_name = table[0]
        print(f"\nTable: {table_name}")

        # Get column info
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = cursor.fetchall()

        print("Columns:")
        for col in columns:
            col_id, col_name, col_type, not_null, default_val, is_pk = col
            pk_str = " (PRIMARY KEY)" if is_pk else ""
            null_str = " NOT NULL" if not_null else ""
            default_str = f" DEFAULT {default_val}" if default_val is not None else ""
            print(f"  - {col_name}: {col_type}{null_str}{default_str}{pk_str}")

        # Get row count
        cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
        row_count = cursor.fetchone()[0]
        print(f"Row count: {row_count}")

    conn.close()

if __name__ == "__main__":
    inspect_database("mysite/db.sqlite3")
