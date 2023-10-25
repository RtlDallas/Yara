rule Jomungand_Spoofer_Function 
{
    strings:
        $start_spoofer_function = { 41 5B 48 83 C4 08 48 8B 44 24 18 4C 8B 10 4C 89 14 24 }
	$end_spoofer_function = { 4C 8B 50 08 4C 89 58 08 48 89 58 10 }

    condition:
        $start_spoofer_function or $end_spoofer_function
}

rule Jomungand_Indirect_Syscall 
{
    strings:
        $indirect_syscall_stub = { 48 89  15 87 2F 00 00 }

    condition:
        $indirect_syscall_stub
}

rule Jomungand_Hash_Function
{
    strings:
	$hash_NtAlloc = { 4C C3 93 67 }
	$hash_NtProtect = { C8 62 29 08 }
	$hash_NtSetCtx = { D0 E0 8B 30 }       
    condition:
	2 of them
}
