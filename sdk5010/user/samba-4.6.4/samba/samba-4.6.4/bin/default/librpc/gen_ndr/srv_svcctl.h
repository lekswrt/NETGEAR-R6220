#include "bin/default/librpc/gen_ndr/ndr_svcctl.h"
#ifndef __SRV_SVCCTL__
#define __SRV_SVCCTL__
WERROR _svcctl_CloseServiceHandle(struct pipes_struct *p, struct svcctl_CloseServiceHandle *r);
WERROR _svcctl_ControlService(struct pipes_struct *p, struct svcctl_ControlService *r);
WERROR _svcctl_DeleteService(struct pipes_struct *p, struct svcctl_DeleteService *r);
WERROR _svcctl_LockServiceDatabase(struct pipes_struct *p, struct svcctl_LockServiceDatabase *r);
WERROR _svcctl_QueryServiceObjectSecurity(struct pipes_struct *p, struct svcctl_QueryServiceObjectSecurity *r);
WERROR _svcctl_SetServiceObjectSecurity(struct pipes_struct *p, struct svcctl_SetServiceObjectSecurity *r);
WERROR _svcctl_QueryServiceStatus(struct pipes_struct *p, struct svcctl_QueryServiceStatus *r);
WERROR _svcctl_SetServiceStatus(struct pipes_struct *p, struct svcctl_SetServiceStatus *r);
WERROR _svcctl_UnlockServiceDatabase(struct pipes_struct *p, struct svcctl_UnlockServiceDatabase *r);
WERROR _svcctl_NotifyBootConfigStatus(struct pipes_struct *p, struct svcctl_NotifyBootConfigStatus *r);
WERROR _svcctl_SCSetServiceBitsW(struct pipes_struct *p, struct svcctl_SCSetServiceBitsW *r);
WERROR _svcctl_ChangeServiceConfigW(struct pipes_struct *p, struct svcctl_ChangeServiceConfigW *r);
WERROR _svcctl_CreateServiceW(struct pipes_struct *p, struct svcctl_CreateServiceW *r);
WERROR _svcctl_EnumDependentServicesW(struct pipes_struct *p, struct svcctl_EnumDependentServicesW *r);
WERROR _svcctl_EnumServicesStatusW(struct pipes_struct *p, struct svcctl_EnumServicesStatusW *r);
WERROR _svcctl_OpenSCManagerW(struct pipes_struct *p, struct svcctl_OpenSCManagerW *r);
WERROR _svcctl_OpenServiceW(struct pipes_struct *p, struct svcctl_OpenServiceW *r);
WERROR _svcctl_QueryServiceConfigW(struct pipes_struct *p, struct svcctl_QueryServiceConfigW *r);
WERROR _svcctl_QueryServiceLockStatusW(struct pipes_struct *p, struct svcctl_QueryServiceLockStatusW *r);
WERROR _svcctl_StartServiceW(struct pipes_struct *p, struct svcctl_StartServiceW *r);
WERROR _svcctl_GetServiceDisplayNameW(struct pipes_struct *p, struct svcctl_GetServiceDisplayNameW *r);
WERROR _svcctl_GetServiceKeyNameW(struct pipes_struct *p, struct svcctl_GetServiceKeyNameW *r);
WERROR _svcctl_SCSetServiceBitsA(struct pipes_struct *p, struct svcctl_SCSetServiceBitsA *r);
WERROR _svcctl_ChangeServiceConfigA(struct pipes_struct *p, struct svcctl_ChangeServiceConfigA *r);
WERROR _svcctl_CreateServiceA(struct pipes_struct *p, struct svcctl_CreateServiceA *r);
WERROR _svcctl_EnumDependentServicesA(struct pipes_struct *p, struct svcctl_EnumDependentServicesA *r);
WERROR _svcctl_EnumServicesStatusA(struct pipes_struct *p, struct svcctl_EnumServicesStatusA *r);
WERROR _svcctl_OpenSCManagerA(struct pipes_struct *p, struct svcctl_OpenSCManagerA *r);
WERROR _svcctl_OpenServiceA(struct pipes_struct *p, struct svcctl_OpenServiceA *r);
WERROR _svcctl_QueryServiceConfigA(struct pipes_struct *p, struct svcctl_QueryServiceConfigA *r);
WERROR _svcctl_QueryServiceLockStatusA(struct pipes_struct *p, struct svcctl_QueryServiceLockStatusA *r);
WERROR _svcctl_StartServiceA(struct pipes_struct *p, struct svcctl_StartServiceA *r);
WERROR _svcctl_GetServiceDisplayNameA(struct pipes_struct *p, struct svcctl_GetServiceDisplayNameA *r);
WERROR _svcctl_GetServiceKeyNameA(struct pipes_struct *p, struct svcctl_GetServiceKeyNameA *r);
WERROR _svcctl_GetCurrentGroupeStateW(struct pipes_struct *p, struct svcctl_GetCurrentGroupeStateW *r);
WERROR _svcctl_EnumServiceGroupW(struct pipes_struct *p, struct svcctl_EnumServiceGroupW *r);
WERROR _svcctl_ChangeServiceConfig2A(struct pipes_struct *p, struct svcctl_ChangeServiceConfig2A *r);
WERROR _svcctl_ChangeServiceConfig2W(struct pipes_struct *p, struct svcctl_ChangeServiceConfig2W *r);
WERROR _svcctl_QueryServiceConfig2A(struct pipes_struct *p, struct svcctl_QueryServiceConfig2A *r);
WERROR _svcctl_QueryServiceConfig2W(struct pipes_struct *p, struct svcctl_QueryServiceConfig2W *r);
WERROR _svcctl_QueryServiceStatusEx(struct pipes_struct *p, struct svcctl_QueryServiceStatusEx *r);
WERROR _EnumServicesStatusExA(struct pipes_struct *p, struct EnumServicesStatusExA *r);
WERROR _EnumServicesStatusExW(struct pipes_struct *p, struct EnumServicesStatusExW *r);
WERROR _svcctl_SCSendTSMessage(struct pipes_struct *p, struct svcctl_SCSendTSMessage *r);
const struct api_struct *svcctl_get_pipe_fns(int *n_fns);
struct rpc_srv_callbacks;
NTSTATUS rpc_svcctl_init(const struct rpc_srv_callbacks *rpc_srv_cb);
NTSTATUS rpc_svcctl_shutdown(void);
#endif /* __SRV_SVCCTL__ */