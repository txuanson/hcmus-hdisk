import os
import argparse

def recover_images(disk_image_file, output_dir='.'):
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
            filename = os.path.join(output_dir, f'recovered_{index}{jpg_extension}')
            with open(filename, 'wb') as f:
                f.write(jpg_file)
            recovered_files.append(filename)
            index = end
        elif data[index:index+8] == png_signature:
            end = data.find(png_signature, index+8)
            if end == -1:
                end = len(data)
            png_file = data[index:end]
            filename = os.path.join(output_dir, f'recovered_{index}{png_extension}')
            with open(filename, 'wb') as f:
                f.write(png_file)
            recovered_files.append(filename)
            index = end
        else:
            index += 1

    return recovered_files


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input_file', help='Path to the disk image file')
    parser.add_argument('-o', '--output_dir', help='Path to the output directory', default='.')
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()

    if args.input_file is None:
        print('Please provide the path to the disk image file')
        exit(1)

    # Ensure the output directory exists
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)

    recovered_files = recover_images(args.input_file, args.output_dir)
    for file in recovered_files:
        print(f'Recovered file: {file}')

