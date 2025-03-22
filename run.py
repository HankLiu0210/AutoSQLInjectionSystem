from app import create_app

# 创建Flask应用实例
app = create_app()

if __name__ == '__main__':
    # 以调试模式运行应用
    # debug=True 意味着：
    # 1. 代码修改后自动重启服务器
    # 2. 显示详细的错误信息
    # 3. 提供调试器界面
    app.run(
        host='127.0.0.1',  # 监听的地址
        port=5000,         # 监听的端口
        debug=True         # 开启调试模式
    )