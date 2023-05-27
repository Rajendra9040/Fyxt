from django.urls import path, include

from cqdashboard.views import (
    ManagerChartUploadViewSet, ManagerDashboard, SplitAuditViewSet, TeamViewSet,
    SpecialtyViewSet, HealthSystemViewSet, HospitalViewSet, DepartmentViewSet,
    ProviderViewSet, InsuranceViewSet, EhrViewSet
)

from rest_framework.routers import DefaultRouter


router = DefaultRouter()
router.register(r'charts/files', ManagerChartUploadViewSet, basename="chart-files")
router.register(r'charts', ManagerDashboard, basename="charts")
router.register(r'split-audit', SplitAuditViewSet, basename="split-audit")
router.register(r'teams', TeamViewSet, basename="teams")
router.register(r'specialties', SpecialtyViewSet, basename="manager-specialties")
router.register(r'accounts/healthsystem', HealthSystemViewSet, basename="health-system")
router.register(r'accounts/hospital', HospitalViewSet, basename="hospital")
router.register(r'accounts/department', DepartmentViewSet, basename="department")
router.register(r'accounts/provider', ProviderViewSet, basename="provider")
router.register(r'insurance', InsuranceViewSet, basename="insurance")
router.register(r'ehr', EhrViewSet, basename="ehr")



urlpatterns = [

    path('', include(router.urls)),

]