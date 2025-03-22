# from app import create_app, db
# from app.models import CVE  # 导入 CVE 模型

# def init_database():
#     app = create_app()
#     with app.app_context():
#         print("开始初始化数据库...")
#         print(f"使用模型: {CVE.__name__}")  # 显示使用的模型名称
        
#         # 删除现有的表
#         db.drop_all()
#         print("删除旧表")
        
#         # 创建新表
#         db.create_all()
#         print(f"根据 {CVE.__name__} 模型创建新表")
        
#         # 验证表结构
#         from sqlalchemy import text
#         with db.engine.connect() as conn:
#             result = conn.execute(text('DESCRIBE cves'))
#             columns = result.fetchall()
#             print("\n创建的表结构:")
#             for column in columns:
#                 print(column)

#             # 验证是否符合模型定义
#             print("\n验证表结构是否符合模型定义:")
#             model_columns = [column.name for column in CVE.__table__.columns]
#             print(f"模型定义的字段: {model_columns}")

# if __name__ == '__main__':
#     init_database()


# init_db.py
# from app import create_app, db
# from app.models import CVE

# def init_database():
#     app = create_app()
#     with app.app_context():
#         print("开始初始化数据库...")
#         db.drop_all()
#         db.create_all()
        
#         # 验证表结构
#         from sqlalchemy import text
#         with db.engine.connect() as conn:
#             result = conn.execute(text('DESCRIBE cves'))
#             columns = result.fetchall()
#             print("\n创建的表结构:")
#             for column in columns:
#                 print(column)

# if __name__ == '__main__':
#     init_database()

from app import create_app, db
from app.models import CVE  # 导入所有模型

def init_database():
    app = create_app()
    with app.app_context():
        print("开始初始化数据库...")
        
        # 删除现有的表
        db.drop_all()
        print("已删除所有现有表")
        
        # 创建新表
        db.create_all()
        print("已创建新表")
        
        # 验证所有表的结构
        from sqlalchemy import text
        with db.engine.connect() as conn:
            # 获取所有表名
            result = conn.execute(text('SHOW TABLES'))
            tables = result.fetchall()
            
            print("\n创建的所有表:")
            for table in tables:
                table_name = table[0]
                print(f"\n表名: {table_name}")
                print("-" * 50)
                
                # 显示每个表的结构
                result = conn.execute(text(f'DESCRIBE {table_name}'))
                columns = result.fetchall()
                for column in columns:
                    print(column)

            # 验证表结构是否符合模型定义
            print("\n验证表结构是否符合模型定义:")
            
            # CVE表
            print("\nCVE表字段:")
            cve_columns = [column.name for column in CVE.__table__.columns]
            print(f"模型定义的字段: {cve_columns}")
            
            # # CWE表
            # print("\nCWE表字段:")
            # cwe_columns = [column.name for column in CWE.__table__.columns]
            # print(f"模型定义的字段: {cwe_columns}")
            
            # # 关联表
            # print("\n关联表字段:")
            # association_columns = [column.name for column in CVE_CWE.__table__.columns]
            # print(f"模型定义的字段: {association_columns}")

if __name__ == '__main__':
    init_database()