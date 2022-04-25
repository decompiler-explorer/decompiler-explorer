from django.contrib import admin

from .models import Decompilation, DecompilationRequest, Decompiler, Binary


@admin.register(DecompilationRequest)
class DecompilationRequestAdmin(admin.ModelAdmin):
	model = DecompilationRequest
	ordering = ('-created', 'decompiler')
	list_display = ('created', 'decompiler', 'binary', 'completed', 'id')


@admin.register(Decompilation)
class DecompilationAdmin(admin.ModelAdmin):
	model = Decompilation
	ordering = ('-created', 'decompiler')
	list_display = ('created', 'decompiler', 'binary', 'id')


@admin.register(Decompiler)
class DecompilerAdmin(admin.ModelAdmin):
	model = Decompiler
	ordering = ('name', '-last_health_check', 'version')
	list_display = ('name', 'version', 'revision', 'id')


@admin.register(Binary)
class BinaryAdmin(admin.ModelAdmin):
	model = Binary
	ordering = ('-created', 'hash')
	list_display = ('created', 'file', 'id')
