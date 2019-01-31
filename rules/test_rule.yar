/**
proc_id, proc_path, proc_guid. proc_cmdline, proc_cd, proc_user, proc_time, proc_md5, proc_sha256,proc_regmod_count,proc_regmod,proc_remotethread,proc_remotethread_count,proc_filemod,proc_filemod_count,proc_netconn,proc_netconn_count,proc_modload,proc_modload_count,proc_rawaccess,proc_rawaccess_count,proc_procaccess,proc_procaccess_count
parent_,grand_,ggrand_
child_path,child_guids,child_count
computer_name
**/

rule winword_cmd: winword cmd
{
    meta:
        reference = "process_name:winword.exe  childproc_name:cmd.exe"
    strings:
        $proc_path1 = /proc_path=[^\n]+winword\.exe/ nocase
        $child_path1 = /child_path=[^\n]+cmd\.exe/ nocase

    condition:
        any of ($proc_path*) and
        any of ($child_path*)
}
