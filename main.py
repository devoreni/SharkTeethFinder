import boto3
import os
from dotenv import dotenv_values
import cv2

secrets = dotenv_values('.env')

# Create AWS Rokognition Client
rekognition_client = boto3.client('rekognition',
                                  aws_access_key_id=secrets['AWS_ACCESS_KEY_ID'],
                                  aws_secret_access_key=secrets['AWS_SECRET_ACCESS_KEY'])

# Set the target class

# Load Image

# Convert to jpg

# Convert buffer to bytes

# Detect objects

# Write detections
