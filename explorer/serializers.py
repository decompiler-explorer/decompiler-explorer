import hashlib
from django.conf import settings
from rest_framework import serializers
from rest_framework.reverse import reverse

from explorer.models import Decompilation, Binary, DecompilationRequest, Decompiler

from explorer.mixins import WriteOnceMixin


class DecompilerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Decompiler
        fields = ['id', 'name', 'version', 'revision', 'url']


class DecompilationSerializer(WriteOnceMixin, serializers.ModelSerializer):
    url = serializers.SerializerMethodField()
    download_url = serializers.SerializerMethodField()
    decompiler = DecompilerSerializer(read_only=True)

    class Meta:
        model = Decompilation
        fields = ['id', 'binary', 'created', 'url', 'decompiler', 'error', 'decompiled_file', 'download_url', 'analysis_time']
        read_only_fields = ['created']
        extra_kwargs = {'decompiled_file': {'write_only': True}}

    def get_url(self, obj: Decompilation):
        binary = obj.binary
        return reverse('decompilation-detail', args=[binary.pk, obj.pk], request=self.context['request'])

    def get_download_url(self, obj: Decompilation):
        if settings.USING_S3:
            if obj.decompiled_file.name:
                return obj.decompiled_file.url
            return None

        binary = obj.binary
        return reverse('decompilation-download', args=[binary.pk, obj.pk], request=self.context['request'])


class BinarySerializer(WriteOnceMixin, serializers.ModelSerializer):
    download_url = serializers.SerializerMethodField()
    decompilations_url = serializers.SerializerMethodField()

    class Meta:
        model = Binary
        fields = ['id', 'download_url', 'decompilations_url', 'file']
        extra_kwargs = {'file': {'write_only': True}}

    def create(self, validated_data):
        hash_obj = hashlib.sha256()
        for chunk in validated_data['file'].chunks():
            hash_obj.update(chunk)
        file_hash = hash_obj.hexdigest()
        try:
            binary = Binary._default_manager.get(hash=file_hash)
            binary.save()
            return binary
        except Binary.DoesNotExist:
            validated_data['hash'] = file_hash
            return super().create(validated_data)

    def get_download_url(self, obj):
        if settings.USING_S3:
            return obj.file.url

        return reverse('binary-download', args=[obj.pk], request=self.context['request'])

    def get_decompilations_url(self, obj):
        return reverse('decompilation-list', args=[obj.pk], request=self.context['request'])


class DecompilationRequestSerializer(serializers.ModelSerializer):
    download_url = serializers.SerializerMethodField()
    binary_id = serializers.SerializerMethodField()
    completion_url = serializers.SerializerMethodField()

    class Meta:
        model = DecompilationRequest
        fields = ['id', 'binary_id', 'decompiler', 'created', 'last_attempted', 'download_url', 'completion_url']

    def get_download_url(self, obj):
        if settings.USING_S3:
            return obj.binary.file.url

        return reverse('binary-download', args=[obj.binary.pk], request=self.context['request'])

    def get_completion_url(self, obj):
        return reverse('decompilationrequest-complete', args=[obj.pk], request=self.context['request'])

    def get_binary_id(self, obj):
        return obj.binary.pk
