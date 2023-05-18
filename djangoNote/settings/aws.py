from djangoNote.settings.settings import DEBUG, BASE_DIR
import boto3
from storages.backends.s3boto3 import S3Boto3Storage

import environ

# reading .env file
env = environ.Env()
environ.Env.read_env()

AWS_ACCESS_KEY_ID = env("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = env("AWS_SECRET_ACCESS_KEY")

DEFAULT_FILE_STORAGE = "storages.backends.s3boto3.S3Boto3Storage"

AWS_STORAGE_BUCKET_NAME = "dj-note-sh"
AWS_S3_REGION_NAME = "eu-west-2"
AWS_S3_CUSTOM_DOMAIN = f"{AWS_STORAGE_BUCKET_NAME}.s3.amazonaws.com"
AWS_S3_SECURE_URLS = True
STATICFILES_STORAGE = "storages.backends.s3boto3.S3Boto3Storage"
