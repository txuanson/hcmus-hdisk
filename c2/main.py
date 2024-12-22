import os
import sys
import time
import random
import struct
import hashlib
import platform
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class MyFS:
    HEADER_SIZE = 1024  # Kích thước header
    MAX_FILES = 99      # Số file tối đa
    FILE_ENTRY_SIZE = 512  # Kích thước mỗi entry trong bảng file
    
    def __init__(self, main_volume_path, metadata_volume_path):
        self.main_path = main_volume_path
        self.metadata_path = metadata_volume_path
        self.system_info = self._get_system_info()
        self.password = None
        self.fernet = None
        
    def _get_system_info(self):
        """Lấy thông tin hệ thống để xác thực máy tính"""
        info = {
            'machine_id': platform.node(),
            'cpu_id': platform.processor(),
            'disk_serial': self._get_disk_serial()
        }
        return hashlib.sha256(str(info).encode()).hexdigest()
    
    def _get_disk_serial(self):
        """Lấy serial number của ổ đĩa"""
        # Implementation depends on OS
        if sys.platform == 'win32':
            import win32api
            return win32api.GetVolumeInformation("C:\\")[1]
        return "unknown"

    def format_volume(self, password):
        """Khởi tạo volume MyFS mới"""
        # Tạo header cho main volume
        header = struct.pack(
            "256s99i99q",
            self.system_info.encode(),  # System info
            *([0] * 99),  # File status array
            *([0] * 99)   # File offsets array
        )
        
        # Tạo encryption key từ password
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
        # Lưu metadata được mã hóa
        with open(self.metadata_path, 'wb') as f:
            f.write(salt)
            f.write(key)
            
        # Khởi tạo main volume
        with open(self.main_path, 'wb') as f:
            f.write(header)
            
    def authenticate(self, password):
        """Xác thực người dùng và thiết lập encryption key"""
        if not os.path.exists(self.metadata_path):
            raise Exception("Metadata file not found")
            
        with open(self.metadata_path, 'rb') as f:
            salt = f.read(16)
            stored_key = f.read()
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
        if key != stored_key:
            raise Exception("Invalid password")
            
        self.password = password
        self.fernet = Fernet(key)
        
    def import_file(self, source_path, file_password=None):
        """Import file vào MyFS"""
        if len(self.list_files()) >= self.MAX_FILES:
            raise Exception("Maximum number of files reached")
            
        file_size = os.path.getsize(source_path)
        if file_size > 4 * 1024 * 1024 * 1024:  # 4GB
            raise Exception("File too large")
            
        # Đọc nội dung file
        with open(source_path, 'rb') as f:
            content = f.read()
            
        # Mã hóa nếu cần
        if file_password:
            content = self._encrypt_file_content(content, file_password)
            
        # Lưu thông tin file
        file_info = {
            'name': os.path.basename(source_path),
            'original_path': os.path.abspath(source_path),
            'size': file_size,
            'attributes': os.stat(source_path),
            'encrypted': bool(file_password)
        }
        
        # Thêm vào MyFS
        self._add_file_entry(file_info, content)
        
    def export_file(self, file_index, target_path, file_password=None):
        """Export file từ MyFS ra ngoài"""
        file_info, content = self._get_file_entry(file_index)
        
        if file_info['encrypted'] and not file_password:
            raise Exception("Password required for encrypted file")
            
        if file_info['encrypted']:
            content = self._decrypt_file_content(content, file_password)
            
        with open(target_path, 'wb') as f:
            f.write(content)
            
        # Khôi phục attributes
        os.chmod(target_path, file_info['attributes'].st_mode)
        os.utime(target_path, (file_info['attributes'].st_atime, file_info['attributes'].st_mtime))
        
    def list_files(self):
        """Liệt kê danh sách files trong MyFS"""
        files = []
        with open(self.main_path, 'rb') as f:
            header = f.read(self.HEADER_SIZE)
            status_array = struct.unpack("99i", header[256:256+396])
            
            for i, status in enumerate(status_array):
                if status == 1:  # File exists
                    file_info = self._get_file_entry(i)[0]
                    files.append({
                        'index': i,
                        'name': file_info['name'],
                        'size': file_info['size'],
                        'encrypted': file_info['encrypted']
                    })
        return files
        
    def _encrypt_file_content(self, content, password):
        """Mã hóa nội dung file"""
        key = hashlib.sha256(password.encode()).digest()
        f = Fernet(base64.urlsafe_b64encode(key))
        return f.encrypt(content)
        
    def _decrypt_file_content(self, content, password):
        """Giải mã nội dung file"""
        key = hashlib.sha256(password.encode()).digest()
        f = Fernet(base64.urlsafe_b64encode(key))
        return f.decrypt(content)
        
    def verify_integrity(self):
        """Kiểm tra tính toàn vẹn của hệ thống"""
        # Kiểm tra system info
        with open(self.main_path, 'rb') as f:
            stored_system_info = struct.unpack("256s", f.read(256))[0].decode().strip('\x00')
            
        if stored_system_info != self.system_info:
            raise Exception("System verification failed")
            
        # Kiểm tra các file entries
        for file in self.list_files():
            try:
                self._get_file_entry(file['index'])
            except:
                return False
        return True
        
    def self_check(self):
        """Kiểm tra tính toàn vẹn của chương trình"""
        current_hash = hashlib.sha256(open(sys.argv[0], 'rb').read()).hexdigest()
        original_hash = "YOUR_ORIGINAL_HASH_HERE"  # Replace with actual hash
        
        if current_hash != original_hash:
            # Tự khôi phục từ backup
            backup_path = "path_to_backup"  # Replace with actual path
            if os.path.exists(backup_path):
                import shutil
                shutil.copy2(backup_path, sys.argv[0])
            sys.exit(1)

class SmartOTP:
    def __init__(self):
        self.attempts = 0
        self.last_x = None
        self.timestamp = None
        
    def generate_challenge(self):
        """Tạo số ngẫu nhiên X có 4 chữ số"""
        self.last_x = random.randint(1000, 9999)
        self.timestamp = time.time()
        return self.last_x
        
    def verify_response(self, y):
        """Kiểm tra response Y"""
        if time.time() - self.timestamp > 20:
            return False
            
        if not (10000000 <= y <= 99999999):
            return False
            
        expected_y = self._calculate_y(self.last_x)
        if y != expected_y:
            self.attempts += 1
            if self.attempts >= 3:
                sys.exit(1)
            return False
            
        return True
        
    def _calculate_y(self, x):
        """Tính toán Y từ X theo thuật toán phức tạp"""
        # Implementation of your complex algorithm here
        # This is just a simple example
        seed = int(time.time() * 1000) & 0xFFFFFFFF
        random.seed(seed)
        base = random.randint(10000000, 99999999)
        return (base + x * x) % 100000000

        # Khởi tạo MyFS
myfs = MyFS("X:\\MyFS.dat", "Y:\\metadata.dat")

# Format volume mới
myfs.format_volume("master_password")

# Xác thực người dùng
myfs.authenticate("master_password")

# Import file với mật khẩu riêng
myfs.import_file("path/to/file", "file_password")

# Export file
myfs.export_file(0, "path/to/export", "file_password")