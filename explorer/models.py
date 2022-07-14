import hashlib
import itertools
import uuid

from datetime import timedelta

from django.conf import settings
from django.db import models
from django.db.models.signals import post_save
from django.db.models.constraints import UniqueConstraint, CheckConstraint
from django.dispatch import receiver
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


def binary_upload_path(instance, filename):
    return f"{settings.UPLOAD_COMPILED_PATH}/{instance.hash}"

def decompilation_upload_path(instance, filename):
    ctx = hashlib.sha256()
    for data in instance.decompiled_file.chunks(1024):
        ctx.update(data)
    return f"{settings.UPLOAD_DECOMPILED_PATH}/{ctx.hexdigest()}"


class Binary(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    file = models.FileField(upload_to=binary_upload_path, max_length=255)
    created = models.DateTimeField('Compile Date', default=timezone.now, editable=False)
    hash = models.CharField(max_length=128, editable=False, unique=True, blank=False, null=False)
    featured = models.BooleanField(default=False)
    featured_name = models.TextField(max_length=128, null=True)

    def __str__(self):
        return f'Binary: {self.hash}'


class Decompiler(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    version = models.CharField('Version Major.minor.patch', max_length=255)
    revision = models.CharField('Specific revision label', max_length=255, blank=True)
    url = models.URLField(max_length=255)
    last_health_check = models.DateTimeField(default=timezone.now, editable=False)
    featured = models.BooleanField('Featured on homepage', default=True)
    created = models.DateTimeField(default=timezone.now, editable=False)

    def __str__(self):
        return f'Decompiler: {self.name} {self.version} {self.revision[:8]}'

    def __lt__(self, other):
        if not isinstance(other, (Decompiler,)):
            return False
        this_version = list(itertools.chain(*[v.split('-') for v in self.version.split('.')]))
        other_version = list(itertools.chain(*[v.split('-') for v in other.version.split('.')]))
        for i in range(min(len(this_version), len(other_version))):
            try:
                if int(this_version[i]) < int(other_version[i]):
                    return True
                elif int(this_version[i]) > int(other_version[i]):
                    return False
            except:
                if this_version[i] < other_version[i]:
                    return True
                elif this_version[i] > other_version[i]:
                    return False
        return len(this_version) < len(other_version)

    @classmethod
    def healthy_latest_versions(cls):
        latest_versions = {}
        healthy_cutoff = timezone.now() - timedelta(minutes=1)

        for decompiler in Decompiler.objects.filter(last_health_check__gte=healthy_cutoff):
            if decompiler.name not in latest_versions or latest_versions[decompiler.name] < decompiler:
                latest_versions[decompiler.name] = decompiler
        return latest_versions.values()


class DecompilationRequest(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    binary = models.ForeignKey(Binary, related_name='decompilation_requests', on_delete=models.CASCADE)
    decompiler = models.ForeignKey(Decompiler, related_name='decompilation_requests', on_delete=models.SET_NULL, null=True, editable=False)
    created = models.DateTimeField(default=timezone.now, editable=False)
    completed = models.BooleanField(default=False, editable=False)
    last_attempted = models.DateTimeField(default='0001-01-01 00:00:00', editable=False)

    def __str__(self):
        return f'<Decompilation Request: {self.id}>'

    class Meta:
        constraints = [
            UniqueConstraint(fields=['binary', 'decompiler'], name='unique_binary_decompiler')
        ]


class Decompilation(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    request = models.OneToOneField(DecompilationRequest, related_name="decompilation", on_delete=models.PROTECT)
    binary = models.ForeignKey(Binary, related_name='decompilations', on_delete=models.CASCADE, editable=False)
    #TODO: rename to contents
    decompiled_file = models.FileField(upload_to=decompilation_upload_path, max_length=255, null=True)
    decompiler = models.ForeignKey(Decompiler, related_name='decompilations', null=True, on_delete=models.SET_NULL, editable=False)
    error = models.TextField('Error Message', null=True)
    created = models.DateTimeField('Decompile Date', default=timezone.now, editable=False)
    analysis_time = models.FloatField(default=0)

    def __str__(self):
        return f'<Decompilation: {self.id}>'

    class Meta:
        constraints = [
            UniqueConstraint(fields=['binary', 'decompiler'], name='unique_binary_decompilation'),
            CheckConstraint(check=(
                    models.Q(decompiled_file='', error__isnull=False) |
                    (~models.Q(decompiled_file='') & models.Q(error__isnull=True))
                ),
                name='decompiled_file_or_error'
            )
        ]

    @property
    def succeeded(self) -> bool:
        return not self.failed

    @property
    def failed(self) -> bool:
        return self.error is not None or self.decompiled_file is None

@receiver(post_save, sender=Binary)
def create_decompilation_requests(sender, instance, created, *args, **kwargs):
    for decompiler in Decompiler.healthy_latest_versions():
        if not DecompilationRequest.objects.filter(binary=instance, decompiler=decompiler).exists():
            DecompilationRequest.objects.create(binary=instance, decompiler=decompiler)


@receiver(post_save, sender=Decompilation)
def complete_decompilation_request(sender, instance, created, *args, **kwargs):
    if not created:
        return
    req = instance.request
    req.completed = True
    req.save()
