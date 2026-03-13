import oracledb

oracledb.init_oracle_client(
    lib_dir=r"C:\instantclient-basic-windows.x64-19.30.0.0.0dbru\instantclient_19_30"
)

connection = oracledb.connect(
    user="trustlink",
    password="trust123",
    dsn="localhost:1521/XE"
)

print("Oracle database connected")