from django.contrib import admin

from .models import Decompilation, DecompilationRequest, Decompiler, Binary

admin.site.register(DecompilationRequest)
admin.site.register(Decompilation)
admin.site.register(Decompiler)
admin.site.register(Binary)
