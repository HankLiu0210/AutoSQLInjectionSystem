import os

def print_directory_tree(path, indent="", max_depth=3, current_depth=0, max_files=5):
    """打印目录树结构"""
    if current_depth > max_depth:
        return
    
    try:
        # 获取目录内容
        items = os.listdir(path)
        files = []
        dirs = []
        
        for item in items:
            item_path = os.path.join(path, item)
            if os.path.isfile(item_path):
                files.append(item)
            elif os.path.isdir(item_path):
                dirs.append(item)
        
        # 先处理目录
        for i, dir_name in enumerate(sorted(dirs)):
            dir_path = os.path.join(path, dir_name)
            print(f"{indent}├── {dir_name}/")
            # 为最后一个目录使用不同的缩进
            next_indent = indent + ("│   " if i < len(dirs) - 1 or files else "    ")
            print_directory_tree(dir_path, next_indent, max_depth, current_depth + 1, max_files)
        
        # 处理文件
        for i, file_name in enumerate(sorted(files)):
            if i >= max_files:
                print(f"{indent}├── ... ({len(files) - max_files} more files)")
                break
            print(f"{indent}├── {file_name}")
            
    except Exception as e:
        print(f"Error accessing {path}: {str(e)}")

# 使用函数
path = r"C:/Projects/AutoSQLInjectionSystem/cvelistV5-main"
print("CVE List V5 Directory Structure:")
print_directory_tree(path)
