from django.core.files.storage import FileSystemStorage

class OverwriteFileSystemStorage(FileSystemStorage):
    def get_available_name(self, name, max_length=None):
        if self.exists(name):
            self.delete(name)
        return name
