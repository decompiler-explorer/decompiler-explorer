from django.contrib import admin
from django.utils import timezone
from django.utils.safestring import mark_safe

from .models import Decompilation, DecompilationRequest, Decompiler, Binary


@admin.register(DecompilationRequest)
class DecompilationRequestAdmin(admin.ModelAdmin):
	model = DecompilationRequest
	ordering = ('-created', 'decompiler')
	list_display = ('created', 'decompiler', '_binary', 'completed', 'last_attempted', 'id')

	def _binary(self, instance):
		return mark_safe(f'<a href="/?id={instance.binary.id}">{instance.binary.id}</a>')


@admin.register(Decompilation)
class DecompilationAdmin(admin.ModelAdmin):
	model = Decompilation
	ordering = ('-created', 'decompiler')
	list_display = ('created', 'decompiler', '_binary', '_succeeded', 'id')

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
	list_display = ('created', 'file', '_id')

	def _id(self, instance):
		return mark_safe(f'<a href="/?id={instance.id}">{instance.id}</a>')
