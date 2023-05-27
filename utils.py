from cqclient.models import HealthSystem, Hospital, Department

# from cqclient import models.HealthSystem


def department_inactive_spoc_user(pk):

    dept_user_ids = [each_['user__id']  for dept in Department.objects.filter(id=pk) for each_ in dept.spoc.values('user__id')]
    provider_user_ids = [each_['user__id']  for dept in Department.objects.filter(id=pk) for each_ in dept.providers.values('user__id')]

    user_ids = list(set(dept_user_ids + provider_user_ids))

    return user_ids


def hospital_inactive_spoc_user(pk):

    hos_user_ids =  [each['user__id'] for hos in Hospital.objects.filter(id=pk) for each in hos.spoc.values('user__id')]

    # Department and Provider users:
    department_ids = [dept.id for dept in Department.objects.filter(hospital=pk)]
    dept_provider_user_ids = [spoc_ for id_ in department_ids for spoc_ in department_inactive_spoc_user(id_)]

    user_ids = list(set(hos_user_ids + dept_provider_user_ids))

    return user_ids


def health_system_inactive_spoc_user(pk):

    hs_user_ids = [each['user__id'] for hs in HealthSystem.objects.filter(id=pk) for each in hs.spoc.values('user__id')]

    # Hospital, Department and Provider users:
    hospital_ids = [hosp.id for hosp in Hospital.objects.filter(health_system=pk)]
    hosp_dept_provides_user_ids = [spoc_ for id_ in hospital_ids for spoc_ in hospital_inactive_spoc_user(id_)]

    user_ids = list(set(hs_user_ids + hosp_dept_provides_user_ids))

    return user_ids