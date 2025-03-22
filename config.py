class Config:
    # MySQL数据库连接配置
    MYSQL_HOST = 'localhost'    # 数据库服务器地址，本地为localhost
    MYSQL_PORT = 3306          # MySQL默认端口号
    MYSQL_USER = 'root'        # 数据库用户名
    MYSQL_PASSWORD = '123456'  # 数据库密码，需要替换为你实际的密码
    MYSQL_DB = 'cve_database'  # 我们之前创建的数据库名称
    
    # SQLAlchemy配置
    # 构建数据库URI，格式为：mysql+pymysql://用户名:密码@主机:端口/数据库名
    SQLALCHEMY_DATABASE_URI = f'mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DB}'
    
    # 关闭SQLAlchemy的事件系统，可以减少内存占用
    SQLALCHEMY_TRACK_MODIFICATIONS = False