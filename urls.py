from django.urls import path, include

from .views import (
    AuditSheetCommentViewSet,
    AuditSheetViewSet,
    AuditHoursMonitorViewset, 
    IndustryViewSet, 
    AuditSheetMetricViewSet,
    ReportViewSet,
    AuditSheetHealthSystemViewSet,
    ListUsersViewset,
    )

from rest_framework.routers import DefaultRouter


router = DefaultRouter()

router.register(r'industry', IndustryViewSet, basename="industry")
router.register(r'audithours', AuditHoursMonitorViewset, basename='audithours')
router.register(r'metric', AuditSheetMetricViewSet, basename='metric')
router.register(r'report', ReportViewSet, basename='report')
router.register(r'comment', AuditSheetCommentViewSet, basename='comment')
router.register(r'health-system', AuditSheetHealthSystemViewSet, basename='health_system')
router.register(r'cqusers', ListUsersViewset , basename='cquser_all')
router.register(r'', AuditSheetViewSet, basename="auditsheet")



urlpatterns = [
    path('', include(router.urls)),
]