# Android Process Injection Tool - Pseudocode

## Main Entry Point
```
FUNCTION main(argc, argv):
    IF argc < 3 THEN
        PRINT "Usage: injectso <process_name> <library_path>"
        EXIT(1)
    END IF
    
    target_process_name = argv[1]
    library_path = argv[2]
    
    // Find target process
    target_pid = find_pid_of(target_process_name)
    IF target_pid == -1 THEN
        PRINT "Process not found: " + target_process_name
        EXIT(1)
    END IF
    
    PRINT "[+] Found process: " + target_process_name + " PID: " + target_pid
    
    // Perform injection
    result = inject_process(target_pid, library_path)
    IF result == SUCCESS THEN
        PRINT "[+] Injection successful!"
    ELSE
        PRINT "[-] Injection failed"
        EXIT(1)
    END IF
END FUNCTION
```

## Process Discovery
```
FUNCTION find_pid_of(process_name):
    proc_dir = opendir("/proc")
    IF proc_dir == NULL THEN
        RETURN -1
    END IF
    
    WHILE entry = readdir(proc_dir) DO
        IF entry.name is_numeric THEN
            pid = convert_to_int(entry.name)
            cmdline_path = "/proc/" + pid + "/cmdline"
            
            file = fopen(cmdline_path, "r")
            IF file != NULL THEN
                buffer = read_line(file)
                fclose(file)
                
                IF buffer CONTAINS process_name THEN
                    closedir(proc_dir)
                    RETURN pid
                END IF
            END IF
        END IF
    END WHILE
    
    closedir(proc_dir)
    RETURN -1
END FUNCTION
```

## Library Address Resolution
```
FUNCTION get_library_address(pid, library_name):
    maps_path = "/proc/" + pid + "/maps"
    file = fopen(maps_path, "r")
    IF file == NULL THEN
        RETURN 0
    END IF
    
    WHILE line = read_line(file) DO
        IF line CONTAINS library_name THEN
            // Parse address range (e.g., "b6f00000-b6f50000")
            tokens = split(line, " -")
            base_address = hex_to_int(tokens[0])
            fclose(file)
            RETURN base_address
        END IF
    END WHILE
    
    fclose(file)
    RETURN 0
END FUNCTION
```

## Main Injection Function
```
FUNCTION inject_process(target_pid, library_path):
    // Step 1: Attach to target process
    IF ptrace_attach(target_pid) != SUCCESS THEN
        PRINT "[-] Failed to attach to process"
        RETURN FAILURE
    END IF
    
    // Step 2: Get current register state
    original_regs = ptrace_getregs(target_pid)
    IF original_regs == NULL THEN
        ptrace_detach(target_pid)
        RETURN FAILURE
    END IF
    
    // Step 3: Find libc and linker addresses
    libc_base = get_library_address(target_pid, "/system/lib/libc.so")
    linker_base = get_library_address(target_pid, "/system/bin/linker")
    
    IF libc_base == 0 OR linker_base == 0 THEN
        PRINT "[-] Failed to find required libraries"
        ptrace_detach(target_pid)
        RETURN FAILURE
    END IF
    
    // Step 4: Resolve function addresses
    mmap_addr = libc_base + MMAP_OFFSET
    dlopen_addr = linker_base + DLOPEN_OFFSET
    dlsym_addr = linker_base + DLSYM_OFFSET
    
    // Step 5: Allocate memory in target process
    remote_memory = call_remote_mmap(target_pid, mmap_addr, SHELLCODE_SIZE)
    IF remote_memory == 0 THEN
        PRINT "[-] Failed to allocate memory in target process"
        ptrace_detach(target_pid)
        RETURN FAILURE
    END IF
    
    PRINT "[+] Remote memory allocated at: " + hex(remote_memory)
    
    // Step 6: Inject shellcode
    shellcode = prepare_injection_shellcode(library_path, dlopen_addr, dlsym_addr)
    write_memory(target_pid, remote_memory, shellcode)
    
    // Step 7: Execute injected code
    execute_remote_code(target_pid, remote_memory)
    
    // Step 8: Restore original state and detach
    ptrace_setregs(target_pid, original_regs)
    ptrace_detach(target_pid)
    
    PRINT "[+] Injection completed successfully"
    RETURN SUCCESS
END FUNCTION
```

## Remote Function Calling
```
FUNCTION call_remote_mmap(pid, mmap_addr, size):
    // Prepare registers for mmap call
    // mmap(NULL, size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
    
    regs.r0 = 0                    // addr = NULL
    regs.r1 = size                 // length
    regs.r2 = 0x7                  // prot = PROT_READ|PROT_WRITE|PROT_EXEC
    regs.r3 = 0x22                 // flags = MAP_PRIVATE|MAP_ANONYMOUS
    regs.r4 = -1                   // fd = -1
    regs.r5 = 0                    // offset = 0
    regs.pc = mmap_addr            // Jump to mmap
    regs.lr = 0                    // Return address (will cause crash, but we'll catch it)
    
    // Set registers and continue execution
    ptrace_setregs(pid, regs)
    ptrace_cont(pid)
    
    // Wait for syscall completion
    waitpid(pid, &status, 0)
    
    // Get return value
    result_regs = ptrace_getregs(pid)
    RETURN result_regs.r0
END FUNCTION
```

## Shellcode Preparation
```
FUNCTION prepare_injection_shellcode(library_path, dlopen_addr, dlsym_addr):
    shellcode = EMPTY_BUFFER
    
    // Embedded ARM assembly shellcode that will:
    // 1. Call dlopen(library_path, RTLD_NOW)
    // 2. Get library handle
    // 3. Optionally call dlsym to resolve symbols
    // 4. Execute library initialization
    
    // Store function addresses
    shellcode.dlopen_addr = dlopen_addr
    shellcode.dlsym_addr = dlsym_addr
    
    // Store library path
    shellcode.library_path = library_path
    
    // ARM instructions for calling dlopen
    shellcode.instructions = [
        // Load library path address into r0
        "ldr r0, =library_path",
        // Load RTLD_NOW flag into r1  
        "mov r1, #2",
        // Call dlopen
        "blx dlopen_addr",
        // Store handle in r4
        "mov r4, r0",
        // Infinite loop (for debugging)
        "b ."
    ]
    
    RETURN shellcode
END FUNCTION
```

## Memory Management
```
FUNCTION write_memory(pid, address, data):
    word_count = length(data) / 4
    FOR i = 0 TO word_count DO
        word = extract_word(data, i * 4)
        ptrace_poke_text(pid, address + (i * 4), word)
    END FOR
END FUNCTION

FUNCTION read_memory(pid, address, size):
    buffer = EMPTY_BUFFER
    word_count = size / 4
    FOR i = 0 TO word_count DO
        word = ptrace_peek_text(pid, address + (i * 4))
        append_word(buffer, word)
    END FOR
    RETURN buffer
END FUNCTION
```

## Ptrace Wrapper Functions
```
FUNCTION ptrace_attach(pid):
    result = ptrace(PTRACE_ATTACH, pid, NULL, NULL)
    IF result == -1 THEN
        RETURN FAILURE
    END IF
    
    // Wait for process to stop
    waitpid(pid, &status, 0)
    RETURN SUCCESS
END FUNCTION

FUNCTION ptrace_detach(pid):
    ptrace(PTRACE_DETACH, pid, NULL, NULL)
END FUNCTION

FUNCTION ptrace_getregs(pid):
    regs = EMPTY_REGISTER_STRUCT
    result = ptrace(PTRACE_GETREGS, pid, NULL, &regs)
    IF result == -1 THEN
        RETURN NULL
    END IF
    RETURN regs
END FUNCTION

FUNCTION ptrace_setregs(pid, regs):
    result = ptrace(PTRACE_SETREGS, pid, NULL, &regs)
    RETURN result
END FUNCTION

FUNCTION ptrace_cont(pid):
    ptrace(PTRACE_CONT, pid, NULL, NULL)
END FUNCTION
```

## Error Handling
```
FUNCTION die(message, function_name, line_number):
    error_msg = strerror(errno)
    PRINT "[-] Failed at line " + line_number + " in " + function_name + ": " + error_msg
    PRINT "[-] " + message
    EXIT(1)
END FUNCTION
```

## Usage Example
```
// Command line usage:
// ./injectso com.example.app /data/local/tmp/malicious.so

// This would:
// 1. Find the PID of "com.example.app"
// 2. Attach to that process using ptrace
// 3. Inject shellcode that calls dlopen("/data/local/tmp/malicious.so")
// 4. Execute the injected library code within the target process
// 5. Detach from the process
```
