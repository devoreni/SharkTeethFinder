import boto3
import os
from dotenv import dotenv_values
import cv2
from PIL import Image
from pillow_heif import register_heif_opener
import numpy as np
import io

register_heif_opener()

def get_image(image_bytes: bytes, original_filename: str):
    secrets = dotenv_values('.env')

    # Create AWS Rekognition Client
    rekognition_client = boto3.client('rekognition',
                                      aws_access_key_id=secrets['AWS_ACCESS_KEY_ID'],
                                      aws_secret_access_key=secrets['AWS_SECRET_ACCESS_KEY'],
                                      region_name='us-east-1')

    # Set the target class
    target_class = 'Zebra'

    image = None
    # Convert to jpg
    if original_filename.lower().endswith('.heic'):
        pil_image = Image.open(io.BytesIO(image_bytes))
        image_np_rgb = np.array(pil_image.convert('RGB'))
        image = cv2.cvtColor(image_np_rgb, cv2.COLOR_RGB2BGR)
    else:
        image_np = np.frombuffer(image_bytes, np.uint8)
        image = cv2.imdecode(image_np, cv2.IMREAD_COLOR)

    if image is None:
        return None, 0


    h, w, c = image.shape
    _, buffer = cv2.imencode('.jpg', image)

    # Convert buffer to bytes
    image_bytes = buffer.tobytes()

    # Detect objects
    obj_count = 0
    try:
        response = rekognition_client.detect_labels(Image={'Bytes': image_bytes}, MinConfidence=50)
        for label in response['Labels']:
            if label['Name'] == target_class:
                for instance_nmr in range(len(label['Instances'])):
                    bbox = label['Instances'][instance_nmr]['BoundingBox']
                    left_bound = int(float(bbox['Left']) * w)
                    upper_bound = int(float(bbox['Top']) * h)
                    right_bound = int(float(bbox['Width']) * w + left_bound)
                    lower_bound = int(float(bbox['Height']) * h + upper_bound)
                    # print(left_bound, upper_bound, width, height)

                    cv2.rectangle(image, (left_bound, upper_bound), (right_bound, lower_bound), (0, 255, 0), 2)
                    obj_count += 1
    except Exception as e:
        print(f'An error occurred: {e}')
        return image, 0

    return image, obj_count

if __name__ == '__main__':
    get_image(bytes(0), 'z1.jpg')
