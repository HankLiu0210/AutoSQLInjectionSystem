from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from config import Config

# 创建SQLAlchemy实例，但暂不初始化
db = SQLAlchemy()

def create_app():
    """
    应用工厂函数，用于创建Flask应用实例
    返回: Flask应用实例
    """
    # 创建Flask应用实例
    app = Flask(__name__)
    
    # 从Config类加载配置
    app.config.from_object(Config)
    
    # 初始化扩展
    # CORS: 允许跨域请求，方便前后端分离开发
    CORS(app)
    # 初始化SQLAlchemy，建立数据库连接
    db.init_app(app)
    
    # 注册蓝图（后面会创建）
    # 蓝图用于组织相关的路由和视图函数
    from app.routes import api
    app.register_blueprint(api.bp)
    
    # 创建所有数据库表
    with app.app_context():
        db.create_all()
    
    return app