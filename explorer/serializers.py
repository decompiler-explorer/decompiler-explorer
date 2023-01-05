import hashlib
from rest_framework import serializers
from rest_framework.reverse import reverse

from explorer.models import Decompilation, Binary, DecompilationRequest, Decompiler, \
    create_decompilation_requests

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
        fields = ['id', 'binary', 'created', 'url', 'decompiler', 'error', 'decompiled_file', 'request', 'download_url', 'analysis_time']
        read_only_fields = ['created']
        extra_kwargs = {'decompiled_file': {'write_only': True}}

    def get_url(self, obj: Decompilation):
        binary = obj.binary
        return reverse('decompilation-detail', args=[binary.pk, obj.pk], request=self.context['request'])

    def get_download_url(self, obj: Decompilation):
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
        return reverse('binary-download', args=[obj.pk], request=self.context['request'])

    def get_decompilations_url(self, obj):
        return reverse('decompilation-list', args=[obj.pk], request=self.context['request'])


class DecompilationRequestSerializer(serializers.ModelSerializer):
    download_url = serializers.SerializerMethodField()
    decompilations_url = serializers.SerializerMethodField()
    binary_id = serializers.SerializerMethodField()

    class Meta:
        model = DecompilationRequest
        fields = ['id', 'binary_id', 'decompiler', 'created', 'last_attempted', 'download_url', 'decompilations_url']

    def get_download_url(self, obj):
        return reverse('binary-download', args=[obj.binary.pk], request=self.context['request'])

    def get_decompilations_url(self, obj):
        return reverse('decompilation-list', args=[obj.binary.pk], request=self.context['request'])

    def get_binary_id(self, obj):
        return obj.binary.pk
