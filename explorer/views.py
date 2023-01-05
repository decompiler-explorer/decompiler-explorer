import datetime
from collections import OrderedDict

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

from .models import Binary, Decompilation, DecompilationRequest, Decompiler, rerun_decompilation_request
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
            queryset = queryset.filter(decompilation__isnull=(not completed))

        decompiler_id = self.request.query_params.get('decompiler')
        if decompiler_id is not None:
            queryset = queryset.filter(decompiler__id=decompiler_id)
            queryset = queryset.filter(last_attempted__lt=timezone.now() - datetime.timedelta(seconds=300))
            if queryset.count() > 0:
                earliest = queryset.order_by('created')[0]
                earliest.last_attempted = timezone.now()
                earliest.save()
                return [earliest]

        return queryset.order_by('created')


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

    def perform_create(self, serializer):
        name = serializer.validated_data['name']
        # Request featured status of previous version of this
        latest = None
        for decompiler in Decompiler.objects.filter(name=name):
            if latest is None or latest < decompiler:
                latest = decompiler

        featured = False
        if latest is not None and latest.featured:
            featured = True

        serializer.save(featured=featured)


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

    @action(methods=['POST'], detail=True)
    def rerun_all(self, *args, **kwargs):
        instance = self.get_object()
        # Create requests for all healthy decomps

        # TODO: Whenever multi-version is ready, use all or something?
        for decompiler in Decompiler.healthy_latest_versions().values():
            try:
                rerun_decompilation_request(instance, decompiler)
            except ValueError:
                pass
        return Response()


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
        queryset = Decompilation.objects.filter(binary=binary)
        completed_str = self.request.query_params.get('completed')
        if completed_str is not None:
            completed = completed_str.lower() in ['true', '1']
            queryset = queryset.filter(request__decompilation__isnull=(not completed))

            # TODO: Whenever multi-version is ready, remove this nonsense
            # Filter decomps for which there is an active request for a newer decompiler
            results = []
            for q in queryset.all():
                print(f"{q.binary.id} with {q.decompiler}")
                if q.decompiler in Decompiler.healthy_latest_versions().values():
                    results.append(q)
                    continue

                latest = True
                same_decomp = DecompilationRequest.objects.filter(binary=binary, decompiler__name=q.decompiler.name).exclude(decompiler=q.decompiler)
                for req in same_decomp:
                    print(f"{q.decompiler} vs {req.decompiler}")
                    if q.decompiler < req.decompiler:
                        print("Old req found, this one is out!!")
                        latest = False
                        break
                if latest:
                    results.append(q)

            return results

        return queryset

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
        req: DecompilationRequest = instance.request

        # TODO: Whenever multi-version is ready, use the one they request
        new_decompiler = Decompiler.healthy_latest_versions().get(req.decompiler.name, None)
        if new_decompiler is None:
            return Response({
                "error": "Not re-running decompliation for decompiler with no active runners."
            }, status=400)

        binary = req.binary
        rerun_decompilation_request(binary, new_decompiler)
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
        # TODO: Whenever multi-version is ready, show em all
        decompilers = sorted(Decompiler.healthy_latest_versions().values(), key=lambda d: d.name.lower())

        decompilers_json = {}
        for d in decompilers:
            decompilers_json[d.name] = model_to_dict(d)

        featured_binaries = sorted(Binary.objects.filter(featured=True), key=lambda b: b.featured_name)
        queue = DecompilationRequest.get_queue()
        show_banner = False
        if queue['general']['oldest_unfinished'] is not None:
            show_banner = queue['general']['oldest_unfinished'] < timezone.now() - datetime.timedelta(minutes=10)

        return Response({
            'serializer': BinarySerializer(),
            'decompilers': decompilers,
            'decompilers_json': decompilers_json,
            'featured_binaries': featured_binaries,
            'show_banner': show_banner
        })


class FaqView(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'explorer/faq.html'
    def get(self, request):
        return Response({
            'serializer': BinarySerializer(),
            # TODO: Whenever multi-version is ready, ???
            'decompilers': Decompiler.healthy_latest_versions().values(),
        })


class QueueView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        return Response(DecompilationRequest.get_queue())
