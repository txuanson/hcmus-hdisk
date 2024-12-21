import os

def recover_images(disk_image_file):
    jpg_signature = b'\xff\xd8\xff'
    png_signature = b'\x89PNG\r\n\x1a\n'
    jpg_extension = '.jpg'
    png_extension = '.png'

    with open(disk_image_file, 'rb') as file:
        data = file.read()

    index = 0
    recovered_files = []

    while index < len(data):
        if data[index:index+3] == jpg_signature:
            end = data.find(jpg_signature, index+3)
            if end == -1:
                end = len(data)
            jpg_file = data[index:end]
            filename = f'recovered_{index}{jpg_extension}'
            with open(filename, 'wb') as f:
                f.write(jpg_file)
            recovered_files.append(filename)
            index = end
        elif data[index:index+8] == png_signature:
            end = data.find(png_signature, index+8)
            if end == -1:
                end = len(data)
            png_file = data[index:end]
            filename = f'recovered_{index}{png_extension}'
            with open(filename, 'wb') as f:
                f.write(png_file)
            recovered_files.append(filename)
            index = end
        else:
            index += 1

    return recovered_files

# Example usage
disk_image_file = './b1/image00.vol'
recovered_files = recover_images(disk_image_file)
print(f'Recovered files: {recovered_files}')

