from django.forms import model_to_dict
from django.http import FileResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone

from rest_framework import viewsets, permissions, mixins
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny, IsAdminUser
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Binary, Decompilation, DecompilationRequest, Decompiler
from .serializers import DecompilationRequestSerializer, DecompilationSerializer, BinarySerializer, \
    DecompilerSerializer
from decompiler_explorer.throttle import AnonBurstRateThrottle, AnonSustainedRateThrottle

from .permissions import IsWorkerOrAdmin, ReadOnly

class DecompilationRequestViewSet(mixins.CreateModelMixin, mixins.RetrieveModelMixin, mixins.ListModelMixin, viewsets.GenericViewSet):
    serializer_class = DecompilationRequestSerializer
    permission_classes = [IsWorkerOrAdmin]

    def get_queryset(self):
        queryset = DecompilationRequest.objects.all()
        completed_str = self.request.query_params.get('completed')
        if completed_str is not None:
            completed = completed_str.lower() in ['true', '1']
            queryset = queryset.filter(completed=completed)

        decompiler_name = self.request.query_params.get('decompiler')
        if decompiler_name is not None:
            queryset = queryset.filter(decompiler__id=decompiler_name)
        return queryset


class DecompilerViewSet(mixins.CreateModelMixin, mixins.RetrieveModelMixin, mixins.ListModelMixin, viewsets.GenericViewSet):
    serializer_class = DecompilerSerializer
    queryset = Decompiler.objects.all()
    permission_classes = [IsWorkerOrAdmin|ReadOnly]

    @action(methods=['GET'], detail=True)
    def health_check(self, *args, **kwargs):
        instance = self.get_object()
        instance.last_health_check = timezone.now()
        instance.save(update_fields=['last_health_check'])
        return Response()


class BinaryViewSet(mixins.CreateModelMixin, mixins.RetrieveModelMixin, mixins.ListModelMixin, viewsets.GenericViewSet):
    queryset = Binary.objects.all()
    serializer_class = BinarySerializer
    throttle_classes = [AnonBurstRateThrottle, AnonSustainedRateThrottle]

    def get_permissions(self):
        if self.action == 'create':
            permission_classes = [AllowAny]
        else:
            permission_classes = [IsWorkerOrAdmin]
        return [permission() for permission in permission_classes]

    @action(methods=['GET'], detail=True)
    def download(self, *args, **kwargs):
        instance = self.get_object()
        handle = instance.file.open()

        response = FileResponse(handle, content_type='application/octet-stream')
        response['Content-Length'] = instance.file.size
        response['Content-Disposition'] = f'attachment; filename="{instance.file.name}"'
        return response


class DecompilationViewSet(viewsets.ModelViewSet):
    queryset = Decompilation.objects.none()
    serializer_class = DecompilationSerializer

    def get_permissions(self):
        if self.action == 'create':
            permission_classes = [IsWorkerOrAdmin]
        elif self.action in ['retrieve', 'list', 'download', 'rerun']:
            permission_classes = [AllowAny]
        else:
            permission_classes = [IsAdminUser]
        return [permission() for permission in permission_classes]

    def get_queryset(self):
        binary = self.get_binary()
        return Decompilation.objects.filter(binary=binary)

    @action(methods=['GET'], detail=True)
    def download(self, *args, **kwargs):
        instance = self.get_object()
        handle = instance.decompiled_file.open()

        response = FileResponse(handle, content_type='application/octet-stream')
        response['Content-Length'] = instance.decompiled_file.size
        response['Content-Disposition'] = f'attachment; filename="{instance.decompiled_file.name}"'
        return response

    @action(methods=['POST'], detail=True)
    def rerun(self, *args, **kwargs):
        instance = self.get_object()
        req = instance.request
        if not req.completed:
            return Response(status=400)
        self.perform_destroy(instance)
        req.created = timezone.now()
        req.completed = False
        req.save()
        return Response()


    def get_binary(self):
        binary_id = self.kwargs.get('binary_id')
        return get_object_or_404(Binary, id=binary_id)

    def perform_create(self, serializer):
        decomp_req = serializer.validated_data['request']
        serializer.save(binary=self.get_binary(), decompiler=decomp_req.decompiler)


class IndexView(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'explorer/index.html'
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        decompilers = sorted(Decompiler.healthy_latest_versions(), key=lambda d: d.name.lower())

        decompilers_json = {}
        for d in decompilers:
            decompilers_json[d.name] = model_to_dict(d)

        featured_binaries = sorted(Binary.objects.filter(featured=True), key=lambda b: b.featured_name)

        return Response({
            'serializer': BinarySerializer(),
            'decompilers': decompilers,
            'decompilers_json': decompilers_json,
            'featured_binaries': featured_binaries
        })

class FaqView(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'explorer/faq.html'
    def get(self, request):
        return Response({
            'serializer': BinarySerializer(),
            'decompilers': Decompiler.healthy_latest_versions(),
        })
