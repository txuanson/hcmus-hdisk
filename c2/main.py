from menu import Menu
import os
import platform
from hashlib import md5
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

PASSWORD_PADDING = b'\x00' * 16

def encrypt(data, password):
  key = SHA256.new(md5(password).digest()).digest()
  encryptor = AES.new(key, AES.MODE_ECB)
  padded_data = pad(data, AES.block_size)
  ciphertext = encryptor.encrypt(padded_data)

  return ciphertext

def decrypt(data, password):
  key = SHA256.new(md5(password).digest()).digest()
  decryptor = AES.new(key, AES.MODE_ECB)
  padded_data = decryptor.decrypt(data)
  return unpad(padded_data, AES.block_size)

def set_bit(value, bit):
  return value | (1<<bit)

def clear_bit(value, bit):
  return value & ~(1<<bit)

class Volume:
  def get_sysinfo(self):
    return platform.node()+"|"+platform.system()+"|"+platform.release()+"|"+platform.version()+"|"+platform.machine()+"|"+platform.processor()+"|"+platform.architecture()[0]

  def _init(self, name, password):
    self.name = name.split(".")[0]
    self.password = md5(password).digest() if len(password) > 0 else PASSWORD_PADDING
    self.dat_dest = f"{self.name}.dat"
    self.volume_dest = f"{self.name}.vol"

    # Collect computer information
    self.sysinfo = self.get_sysinfo()
    self.sysinfo_size = len(self.sysinfo)
    self.entry_table = EntryTable(self.dat_dest)
    self.entry_table_size = 0
    self.entry_table_start_at = 28 + self.sysinfo_size

  def _save_to_disk(self):
    with open(self.volume_dest, 'wb') as f:
      f.write(self.entry_table_size.to_bytes(4))
      f.write(self.entry_table_start_at.to_bytes(4))
      f.write(self.password)
      f.write(self.sysinfo_size.to_bytes(4))
      f.write(self.sysinfo.encode('ascii'))
      f.write(self.entry_table._export())

  def _add_password(self, password):
    self.password = md5(password).digest()
    self.is_password_protected = True
  
  def _remove_password(self):
    self.password = PASSWORD_PADDING
    self.is_password_protected = False

  def _import(self, volume_dest, dat_dest):
    self.volume_dest = volume_dest
    self.dat_dest = dat_dest

    # Read volume info from volume_dest
    with open(volume_dest, 'rb') as f:
      # Get entry table info
      self.entry_table_size = int.from_bytes(f.read(4))
      self.entry_table_start_at = int.from_bytes(f.read(4))

      # Read volume password
      self.is_password_protected = False
      self.password = f.read(16)
      if (self.password != PASSWORD_PADDING):
        self.is_password_protected = True
        raw_password = input("Enter password: ").encode('ascii')
        if md5(raw_password).digest() != self.password:
          print("Password is incorrect!")
          return

      # Read system information
      self.sysinfo_size = int.from_bytes(f.read(4))
      self.sysinfo = f.read(self.sysinfo_size).decode('ascii')

      # Compare system information
      if self.sysinfo != self.get_sysinfo():
        print("System information does not match!")
        return

      # Read entry table
      self.entry_table = EntryTable(self.dat_dest)
      while entry_status := f.read(1):
        file_size = int.from_bytes(f.read(4))
        offset = int.from_bytes(f.read(4))
        name_length = int.from_bytes(f.read(1))
        password = f.read(16)
        name = f.read(name_length).decode('ascii')

        entry = Entry(self.dat_dest, int.from_bytes(entry_status), name, offset, file_size, password)
        
        self.entry_table._add_entry(entry)

  def _import_file(self, source):
    with open(source, 'rb') as f:
      data = f.read()
    entry = Entry(self.dat_dest, 0, os.path.basename(source), 0, len(data), PASSWORD_PADDING)
    entry._import(source)
    self.entry_table._add_entry(entry)

  def _list_entries(self):
    for entry in self.entry_table._get_entries():
      print("------------------------")
      print(f"Name: {entry.name}")
      print(f"Size: {entry.size}")
      print(f"Offset: {entry.offset}")
      print(f"Password protected: {entry._is_encrypted()}")
      print(f"Deleted: {entry._is_deleted()}")
      print("------------------------")
    input()

  def load_entry_from_dat(self, name):
    entry = self.entry_table._find_by_name(name)
    entry._load_from_dat()

  def format(self):
    with open(self.volume_dest, 'wb') as f:
      f.write(b'\x00'*4)
      f.write(b'\x00'*4)
      f.write(self.password)
      f.write(self.sysinfo_size.to_bytes(4))
      f.write(self.sysinfo.encode('ascii'))
    self.entry_table = EntryTable(self.dat_dest)
    

class Entry:
  def __init__(self, dat_dest, status, name, offset, size, password):
    self.status = status
    self.dat_dest = dat_dest
    self.name = name
    self.offset = offset
    self.size = size
    self.password = password

  def _is_deleted(self):
    return self.status & 1 != 0

  def _is_encrypted(self):
    return self.status & 2 != 0

  def _export(self, dest):
    if self.data is None:
      raise Exception("Data not found!")
    if _is_encrypted():
      return decrypt(data, self.password)
    return data

  def _import(self, source):
    with open(source, "rb") as f:
      self.data = f.read()

  def _export(self, dest):
    with open(dest, "wb") as f:
      f.write(self.data)

  def _encrypt(self, password):
    self.data = encrypt(self.data, password)
    self.status = set_bit(self.status, 1)

  def _decrypt(self, password):
    self.status = clear_bit(self.status, 1)
    self.data = decrypt(self.data, password)

  def _remove_encrypt(self, password):
    self.data = decrypt(self.data, password)
    self.status = clear_bit(self.status, 1)
    self.password = PASSWORD_PADDING

  def _remove(self):
    self.status = set_bit(self.status, 0)

  def _recover(self):
    self.status = clear_bit(self.status, 0)

  def _save_to_dat(self):
    if not hasattr(self, 'data'):
      return
    with open(self.dat_dest, "wb") as f:
      f.seek(self.offset)
      f.write(self.data)

  def _load_from_dat(self):
    with open(self.dat_dest, "rb") as f:
      f.seek(self.offset)
      self.data = f.read(self.size)

class EntryTable:
  def __init__(self, dat_dest):
    self.dat_dest = dat_dest
    self.entries = []
  def _add_entry(self, entry):
    self.entries.append(entry)

  def _get_entries(self):
    return self.entries
  
  def _export(self):
    output = b""
    if len(self.entries) == 0:
      open(self.dat_dest, 'a').close()
    for entry in self.entries:
      output += entry.status.to_bytes(1)
      output += entry.size.to_bytes(4)
      output += entry.offset.to_bytes(4)
      output += len(entry.name).to_bytes(1)
      output += entry.password
      output += entry.name.encode('ascii')
      entry._save_to_dat()
    return output

  def _find_by_name(self, name):
    for entry in self.entries:
      if entry.name == name:
        return entry

VOLUME = Volume()

def create_volume():
  name = input("Enter Volume Name: ")
  password = input("Enter Volume Password: ").encode('ascii')
  VOLUME._init(name, password)
  VOLUME._save_to_disk()

def create_volume_password():
  password = input("Enter Volume Password: ")
  VOLUME._add_password(password.encode('ascii'))
  VOLUME._save_to_disk()

def remove_volume_password():
  VOLUME._remove_password()
  VOLUME._save_to_disk()

def import_file():
  source = input("Enter File Source: ")
  VOLUME._import_file(source)
  VOLUME._save_to_disk()

def delete_file():
  entry_name = input("Enter Entry Name: ")
  entry = VOLUME.entry_table._find_by_name(entry_name)
  if entry is None:
    print("Entry not found!")
    return
  entry._remove()
  VOLUME._save_to_disk()

def encrypt_file(entry):
  password = input("Enter Entry Password: ").encode('ascii')
  entry._encrypt(password)
  VOLUME._save_to_disk()

def export_file(entry):
  dest = input("Enter File Destination: ")
  entry._export(dest)

def select_entry():
  entry_name = input("Enter Entry Name: ")
  entry = VOLUME.entry_table._find_by_name(entry_name)
  if entry is None:
    print("Entry not found!")
    return
  VOLUME.load_entry_from_dat(entry_name)
  if entry._is_encrypted():
    password = input("Enter Entry Password: ").encode('ascii')
    entry._decrypt(password)

  menu = Menu(title=entry_name)

  menu.add_option("Export", lambda: export_file(entry), {})
  if entry._is_encrypted():
    menu.add_option("Change Password", lambda: encrypt_file(entry), {})
    menu.add_option("Remove Encryption", lambda: entry._remove_encrypt(password), {})
  else:
    menu.add_option("Encrypt", lambda: encrypt_file(entry), {})
  
  menu.add_option("Exit", lambda: exit(0), {})

  menu.open()

def recover_file():
  entry_name = input("Enter Entry Name: ")
  entry = VOLUME.entry_table._find_by_name(entry_name)
  if entry is None:
    print("Entry not found!")
    return
  entry._recover()
  VOLUME._save_to_disk()

def select_volume():
  volume_dest = input("Enter Volume Destination: ")
  while True:
    if os.path.exists(volume_dest):
      break
    else:
      print("Volume not found!")
      volume_dest = input("Enter Volume Destination again: ")
    
  dat_dest = input("Enter Data Destination: ")
  while True:
    if os.path.exists(dat_dest):
      break
    else:
      print("Data not found!")
      dat_name = input("Enter Data Destination again: ")

  VOLUME._import(volume_dest, dat_dest)

  menu = Menu(title=volume_dest)

  menu.add_option("Format Volume", lambda: VOLUME.format(), {})
  if VOLUME.is_password_protected:
    menu.add_option("Edit Volume Password", lambda: create_volume_password(), {})
    menu.add_option("Remove Volume Password", lambda: remove_volume_password(), {})
  else:
    menu.add_option("Create Volume Password", lambda: create_volume_password(), {})

  menu.add_option("List Entries", lambda: VOLUME._list_entries(), {})
  menu.add_option("Import File", lambda: import_file(), {})
  menu.add_option("Select Entry", lambda: select_entry(), {})
  menu.add_option("Delete File", lambda: delete_file(), {})
  menu.add_option("Recover File", lambda: recover_file(), {})
  
  menu.add_option("Exit", lambda: exit(0), {})
  menu.open()

if __name__ == '__main__':
  menu = Menu(title="HCMUS Disk Manager")
  menu.add_option("Create Volume", lambda: create_volume(), {})
  menu.add_option("Open Volume", lambda: select_volume(), {})
  menu.add_option("Exit", lambda: exit(0), {})

  menu.open()
