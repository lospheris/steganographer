from PIL import Image
import random
import numpy
from Crypto import Random

def create_random_image(width, height, depth):
    rng = Random.new()
    data = numpy.zeros((height, width, depth), dtype=numpy.uint8)
    for h in range(height):
        for w in range(width):
            for color in range(depth):
                data[h][w][color] = ord(rng.read(1))
    return data

def save_image_from_array(data):
    image = Image.fromarray(data, 'RGB')
    image.save('Image.png')

if __name__ == "__main__":
    data = create_random_image(1920, 1080, 3)
    save_image_from_array(data)
