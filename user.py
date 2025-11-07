import sqlite3

DB_PATH = "users.db"   # change to your DB file name if different

def add_column(cursor, table, column, col_type):
    try:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type};")
        print(f"[OK] Added column '{column}'")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            print(f"[SKIP] Column '{column}' already exists")
        else:
            raise e

def migrate():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    print("🔧 Updating transactions table...")

    add_column(cursor, "transactions", "mode", "TEXT")
    add_column(cursor, "transactions", "hw_class", "TEXT")
    add_column(cursor, "transactions", "tx_type", "TEXT")

    conn.commit()
    conn.close()

    print("✅ Migration complete!")

if __name__ == "__main__":
    migrate()
