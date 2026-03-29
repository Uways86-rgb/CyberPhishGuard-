try:
    import MySQLdb  # noqa: F401
except ModuleNotFoundError:
    import pymysql
    pymysql.install_as_MySQLdb()
