from django.core.files.storage import FileSystemStorage
from storages.backends.s3boto3 import S3Boto3Storage
from storages.utils import clean_name


class OverwriteFileSystemStorage(FileSystemStorage):
    def get_available_name(self, name, max_length=None):
        if self.exists(name):
            self.delete(name)
        return name


class CustomS3Storage(S3Boto3Storage):
    def copy(self, from_path, to_path):
        from_path = self._normalize_name(clean_name(from_path))
        to_path = self._normalize_name(clean_name(to_path))

        result = self.connection.meta.client.copy_object(
            Bucket=self.bucket.name,
            Key=to_path,
            CopySource={
                'Bucket': self.bucket.name,
                'Key': from_path,
            },
        )

        if result['ResponseMetadata']['HTTPStatusCode'] != 200:
            raise Exception("Copy operation failed:", result)

        return to_path
