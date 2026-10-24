import sqlite3

TABLE = "users"


def vuln_concat(cur, name):
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")  # expect: CM-A001


def vuln_fstring(cur, uid):
    cur.execute(f"SELECT * FROM users WHERE id = {uid}")  # expect: CM-A001


def vuln_percent(cur, uid):
    cur.execute("DELETE FROM users WHERE id = %s" % uid)  # expect: CM-A001


def vuln_format(cur, name):
    cur.execute("SELECT * FROM users WHERE name = '{}'".format(name))  # expect: CM-A001


def vuln_built_variable(conn, name):
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return conn.execute(query).fetchall()  # expect: CM-A001


def vuln_text(session, sort):
    from sqlalchemy import text
    return session.execute(text(f"SELECT * FROM users ORDER BY {sort}"))  # expect: CM-A001


def safe_param(cur, name):
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))


def safe_constant_table(cur, uid):
    # fp-fixed: interpolating an UPPER_CASE module constant is not user input
    cur.execute(f"SELECT * FROM {TABLE} WHERE id = ?", (uid,))


def safe_static_query(cur):
    query = "SELECT count(*) FROM users"
    return cur.execute(query).fetchone()


def safe_word_select(items):
    label = "Select an option from " + str(len(items))
    return label


def safe_logging_sql(logger, uid):
    logger.debug("running SELECT for id %s", uid)


def safe_executemany(cur, rows):
    cur.executemany("INSERT INTO items (sku, qty) VALUES (?, ?)", rows)
