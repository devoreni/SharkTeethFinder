import boto3
import os
from dotenv import dotenv_values
import cv2

def get_image(image: str):
    secrets = dotenv_values('.env')

    # Create AWS Rekognition Client
    rekognition_client = boto3.client('rekognition',
                                      aws_access_key_id=secrets['AWS_ACCESS_KEY_ID'],
                                      aws_secret_access_key=secrets['AWS_SECRET_ACCESS_KEY'],
                                      region_name='us-east-1')

    # Set the target class
    target_class = 'Zebra'

    # Load Image
    image = cv2.imread(os.path.join(os.path.dirname(__file__), 'test_images', 'z6.jpg'))
    h, w, c = image.shape[:3]

    # Convert to jpg
    _, buffer = cv2.imencode('.jpg', image)

    # Convert buffer to bytes
    image_bytes = buffer.tobytes()

    # Detect objects
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
    cv2.imshow('frame', image)
    cv2.waitKey(0)

