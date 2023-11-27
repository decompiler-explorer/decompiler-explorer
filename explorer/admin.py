from django.contrib import admin
from django.utils import timezone
from django.utils.safestring import mark_safe

from rest_framework.reverse import reverse

from .models import Decompilation, DecompilationRequest, Decompiler, Binary


@admin.register(DecompilationRequest)
class DecompilationRequestAdmin(admin.ModelAdmin):
	model = DecompilationRequest
	ordering = ('-created', 'decompiler')
	list_display = ('created', 'decompiler', '_binary', 'last_attempted', 'id')
	raw_id_fields = ('binary',)

	def _binary(self, instance):
		return mark_safe(f'<a href="/?id={instance.binary.id}">{instance.binary.id}</a>')


@admin.register(Decompilation)
class DecompilationAdmin(admin.ModelAdmin):
	model = Decompilation
	ordering = ('-created', 'decompiler')
	list_display = ('created', 'decompiler', '_binary', '_succeeded', 'id')
	raw_id_fields = ('binary',)

	def _binary(self, instance):
		return mark_safe(f'<a href="/?id={instance.binary.id}">{instance.binary.id}</a>')

	def _succeeded(self, instance):
		return instance.succeeded
	_succeeded.boolean = True


@admin.register(Decompiler)
class DecompilerAdmin(admin.ModelAdmin):
	model = Decompiler
	ordering = ('name', '-last_health_check', 'version')
	list_display = ('name', 'version', '_revision', 'id', '_active', 'created')

	def _revision(self, instance):
		if instance.revision is None:
			return "<none>"
		if len(instance.revision) < 10:
			return instance.revision
		return instance.revision[:10] + '...'

	def _active(self, instance):
		if (timezone.now() - instance.last_health_check).seconds < 60:
			return True
		return False
	_active.boolean = True


@admin.register(Binary)
class BinaryAdmin(admin.ModelAdmin):
	model = Binary
	ordering = ('-created', 'hash')
	list_display = ('created', '_file', '_id')
	list_filter = ('featured',)
	search_fields = ('id', 'hash')

	def _file(self, instance):
		download_url = reverse('binary-download', args=[instance.pk])
		return mark_safe(f'<a href="{download_url}">{instance.file}</a>')

	def _id(self, instance):
		return mark_safe(f'<a href="/?id={instance.id}">{instance.id}</a>')
