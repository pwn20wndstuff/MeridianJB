
#define offsetof_p_pid (unsigned)(0x10)    // proc_t::p_pid
#define offsetof_task (unsigned)(0x18)    // proc_t::task
#define offsetof_p_uid (unsigned)(0x30)    // proc_t::p_uid
#define offsetof_p_gid (unsigned)(0x34)    // proc_t::p_uid
#define offsetof_p_ruid (unsigned)(0x38)    // proc_t::p_uid
#define offsetof_p_rgid (unsigned)(0x3c)    // proc_t::p_uid
#define offsetof_p_svuid (unsigned)(0x40)    // proc_t::p_uid
#define offsetof_p_svgid (unsigned)(0x44)    // proc_t::p_uid
#define offsetof_p_ucred (unsigned)(0x100)    // proc_t::p_ucred
#define offsetof_p_csflags (unsigned)(0x2a8)    // proc_t::p_csflags
#define offsetof_itk_self (unsigned)(0xD8)    // task_t::itk_self (convert_task_to_port)
#define offsetof_itk_sself (unsigned)(0xE8)    // task_t::itk_sself (task_get_special_port)
#define offsetof_itk_bootstrap (unsigned)0x2b8    // task_t::itk_bootstrap (task_get_special_port)
#define offsetof_itk_space (unsigned)((kCFCoreFoundationVersionNumber >= 1443.00) ? (0x308) : (0x300))    // task_t::itk_space
#define offsetof_bsd_info (unsigned)((kCFCoreFoundationVersionNumber >= 1443.00) ? (0x368) : (0x360))    // task_t::bsd_info
#define offsetof_ip_mscount (unsigned)(0x9C)    // ipc_port_t::ip_mscount (ipc_port_make_send)
#define offsetof_ip_srights (unsigned)(0xA0)    // ipc_port_t::ip_srights (ipc_port_make_send)
#define offsetof_ip_kobject (unsigned)(0x68)    // ipc_port_t::ip_kobject
#define offsetof_p_textvp (unsigned)(0x248)    // proc_t::p_textvp
#define offsetof_p_textoff (unsigned)(0x250)    // proc_t::p_textoff
#define offsetof_p_cputype (unsigned)(0x2c0)    // proc_t::p_cputype
#define offsetof_p_cpu_subtype (unsigned)(0x2c4)    // proc_t::p_cpu_subtype
#define offsetof_special (unsigned)(2 * sizeof(long))    // host::special
#define offsetof_ipc_space_is_table (unsigned)(0x20)    // ipc_space::is_table?..

#define offsetof_ucred_cr_uid (unsigned)(0x18)    // ucred::cr_uid
#define offsetof_ucred_cr_ruid (unsigned)(0x1c)    // ucred::cr_ruid
#define offsetof_ucred_cr_svuid (unsigned)(0x20)    // ucred::cr_svuid
#define offsetof_ucred_cr_ngroups (unsigned)(0x24)    // ucred::cr_ngroups
#define offsetof_ucred_cr_groups (unsigned)(0x28)    // ucred::cr_groups
#define offsetof_ucred_cr_rgid (unsigned)(0x68)    // ucred::cr_rgid
#define offsetof_ucred_cr_svgid (unsigned)(0x6c)    // ucred::cr_svgid

#define offsetof_v_type (unsigned)(0x70)    // vnode::v_type
#define offsetof_v_id (unsigned)(0x74)    // vnode::v_id
#define offsetof_v_ubcinfo (unsigned)(0x78)    // vnode::v_ubcinfo

#define offsetof_ubcinfo_csblobs (unsigned)(0x50)    // ubc_info::csblobs

#define offsetof_csb_cputype (unsigned)(0x8)    // cs_blob::csb_cputype
#define offsetof_csb_flags (unsigned)((kCFCoreFoundationVersionNumber >= 1450.14) ? (0xc) : (0x12))    // cs_blob::csb_flags
#define offsetof_csb_base_offset (unsigned)((kCFCoreFoundationVersionNumber >= 1450.14) ? (0x10) : (0x16))    // cs_blob::csb_base_offset
#define offsetof_csb_entitlements_offset (unsigned)(0x98)    // cs_blob::csb_entitlements
#define offsetof_csb_signer_type (unsigned)(0xA0)    // cs_blob::csb_signer_type
#define offsetof_csb_platform_binary (unsigned)(0xA4)    // cs_blob::csb_platform_binary
#define offsetof_csb_platform_path (unsigned)(0xA8)    // cs_blob::csb_platform_path

#define offsetof_t_flags (unsigned)(0x3a0)    // task::t_flags
