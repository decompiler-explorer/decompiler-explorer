import re

from django.conf import settings
from django.core.files.storage import default_storage
from django.core.management.base import BaseCommand
from django.db import transaction

from explorer.models import (
    Binary,
    Decompilation,
    binary_upload_path,
    decompilation_upload_path,
)


class Command(BaseCommand):
    help = "Moves from legacy flat file structure to prefix subfolders"

    def _copy_object(self, from_path: str, to_path: str) -> str:
        if hasattr(default_storage, 'copy'):
            result_name = default_storage.copy(from_path, to_path)
        else:
            with default_storage.open(from_path) as f:
                result_name = default_storage.save(to_path, f)
        return result_name


    def handle(self, *args, **options):
        # Select all files that aren't in a XX/ subdirectory
        candidate_binaries = Binary.objects.filter(file__gt=f'{settings.UPLOAD_COMPILED_PATH}/000')
        candidate_binary_count = candidate_binaries.count()
        for i,binary in enumerate(candidate_binaries):
            print(f'Processing binary {i}/{candidate_binary_count}...', end='\r')

            if binary.file.name != f'{settings.UPLOAD_COMPILED_PATH}/{binary.hash}':
                print(f'Heuristic was wrong for {binary.file.name}')
                continue

            with transaction.atomic():
                # copy file, update in db, delete old file
                original_path = binary.file.name
                new_path = binary_upload_path(binary, '')
                final_path = self._copy_object(original_path, new_path)
                binary.file.name = final_path
                binary.save(update_fields=['file'])
                default_storage.delete(original_path)


        candidate_decompilations = Decompilation.objects.filter(file__gt=f'{settings.UPLOAD_DECOMPILED_PATH}/000')
        candidate_decompilation_count = candidate_decompilations.count()
        for i,decomp in enumerate(candidate_decompilations):
            print(f'Processing decompilation {i}/{candidate_decompilation_count}...', end='\r')

            if re.match(f'^{settings.UPLOAD_DECOMPILED_PATH}/[0-9a-f]{{64}}$', decomp.decompiled_file.name):
                print(f'Heuristic was wrong for {decomp.decompiled_file.name}')
                continue

            with transaction.atomic():
                # copy file, update in db, delete old file
                original_path = decomp.decompiled_file.name
                new_path = decompilation_upload_path(decomp, '')
                final_path = self._copy_object(original_path, new_path)
                decomp.decompiled_file.name = final_path
                decomp.save(update_fields=['decompiled_file'])
                default_storage.delete(original_path)
