import os
import shutil
import json
import hashlib
from cryptography.fernet import Fernet
import random
import time

class MyFS:
    def __init__(self, volume_x, volume_y):
        self.volume_x = volume_x  # Volume chứa MyFS.Dat
        self.volume_y = volume_y  # Volume chứa metadata mã hóa
        self.myfs_file = os.path.join(self.volume_x, 'MyFS.Dat')
        self.metadata_file = os.path.join(self.volume_y, 'MyFS_Metadata.json')
        self.master_key = None
        self.load_metadata()

    def load_metadata(self):
        if os.path.exists(self.metadata_file):
            with open(self.metadata_file, 'r') as f:
                self.metadata = json.load(f)
        else:
            self.metadata = {
                "files": {},  # Lưu thông tin file
                "system_info": {},  # Thông tin máy tính
                "password": None  # Mật khẩu truy xuất hệ thống
            }

    def save_metadata(self):
        with open(self.metadata_file, 'w') as f:
            json.dump(self.metadata, f, indent=4)

    def set_master_password(self, password):
        self.master_key = hashlib.sha256(password.encode()).hexdigest()
        self.metadata['password'] = self.master_key
        self.save_metadata()
        print("Master password set successfully.")

    def check_master_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest() == self.metadata.get('password')

    def create_volume(self):
        if not os.path.exists(self.volume_x):
            os.makedirs(self.volume_x)
        if not os.path.exists(self.volume_y):
            os.makedirs(self.volume_y)

        with open(self.myfs_file, 'wb') as f:
            f.write(b'')

        self.metadata['system_info'] = {
            "machine_name": os.uname().nodename,
            "os": os.uname().sysname,
        }
        self.save_metadata()
        print("Volume created and formatted successfully.")

    def import_file(self, file_path):
        if len(self.metadata['files']) >= 99:
            print("Cannot add more files. Maximum limit reached.")
            return

        file_name = os.path.basename(file_path)
        file_key = Fernet.generate_key()
        cipher = Fernet(file_key)

        with open(file_path, 'rb') as f:
            file_data = f.read()

        encrypted_data = cipher.encrypt(file_data)

        with open(self.myfs_file, 'ab') as f:
            f.write(encrypted_data)

        self.metadata['files'][file_name] = {
            "original_path": file_path,
            "file_key": file_key.decode(),
            "size": len(file_data)
        }
        self.save_metadata()
        print(f"File {file_name} imported successfully.")

    def export_file(self, file_name, export_path):
        if file_name not in self.metadata['files']:
            print("File not found in MyFS.")
            return

        file_info = self.metadata['files'][file_name]
        file_key = file_info['file_key'].encode()
        cipher = Fernet(file_key)

        with open(self.myfs_file, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = cipher.decrypt(encrypted_data)

        with open(os.path.join(export_path, file_name), 'wb') as f:
            f.write(decrypted_data)

        print(f"File {file_name} exported successfully to {export_path}.")

    def list_files(self):
        print("Files in MyFS:")
        for file_name, info in self.metadata['files'].items():
            print(f"- {file_name}: {info['size']} bytes, Original Path: {info['original_path']}")

    def delete_file(self, file_name):
        if file_name in self.metadata['files']:
            del self.metadata['files'][file_name]
            self.save_metadata()
            print(f"File {file_name} deleted from MyFS.")
        else:
            print("File not found in MyFS.")

    def generate_smart_otp(self, x):
        random.seed(x)
        otp = random.randint(10000000, 99999999)
        return otp

    def validate_otp(self, x, y):
        return self.generate_smart_otp(x) == y

# Example usage
if __name__ == "__main__":
    myfs = MyFS(volume_x="/path/to/volumeX", volume_y="/path/to/volumeY")
    myfs.create_volume()
    myfs.set_master_password("my_secure_password")
    myfs.import_file("/path/to/import/file.txt")
    myfs.list_files()
    otp_x = random.randint(1000, 9999)
    print(f"Generated OTP challenge: {otp_x}")
    user_otp = int(input("Enter the OTP: "))
    if myfs.validate_otp(otp_x, user_otp):
        print("OTP validated successfully.")
    else:
        print("Invalid OTP.")
