# WHR-CAT

*This was a reverse engineering challenge from [Grey Cat the flag CTF 2025](https://ctftime.org/event/2765). Join me in this journey of Virtual Machines*
### Description

"My cat got encrypted, can you help to recover my cat :(
(After recovering the flag, run strings | grep grey to get the flag)"

### TL;DR
This is a VM challenge, where the author implemented a custom binary file format with segments, an instruction set and custom encryption in the VM's bytecode which was used to encrypt the flag and produce the flag.enc file. Read the full solution to find out my unintended which saved me lots of time ;) 
### Initial Analysis
Initially we're given 3 files:

```
.rw-rw-r-- 1.9M kali 31 May 19:06 catt.enc
.rw-rw-r--  519 kali 31 May 19:06 chall.sad
.rwxrwxr-x  23k kali 31 May 19:06 runner
```

The file `runner` is a dynamically linked, stripped ELF binary. The other two files are labeled as just "data". Simply running this ELF binary gives us the following output:

`Usage: ./sad <name>.sad <arguments>`

Immediately I got the feeling that this is a VM challenge, but of course to verify this I had to analyze the binary using Ghidra. This is the main function (after some time renaming some variables and functions):

```C

int main(int argc,char *argv)

{
  int success;
  size_t sVar1;
  long in_FS_OFFSET;
  int local_84;
  int i;
  int ret;
  int local_78;
  int local_74;
  char *user_input_file;
  FILE *file_data;
  long local_60;
  undefined8 buf1;
  undefined8 buf2;
  long local_48;
  void *local_40;
  undefined8 magic_bytes;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  if (argc < 2) {
    display_usage();
    success = 0;
  }
  else {
    local_30 = 0;
    magic_bytes = 0x444153; // "SAD"
    user_input_file = *(char **)(argv + 8);
    for (i = 2; i < argc; i = i + 1) {
      *(undefined8 *)(argv + (long)i * 8 + -0x10) = *(undefined8 *)(argv + (long)i * 8);
    }
    file_data = fopen(user_input_file,"r");
    if (file_data == (FILE *)0x0) {
      printf("%s: no such file or directory\n",user_input_file);
      success = -1;
    }
    else {
      ret = fseek(file_data,0,2);
      if (ret == 0) {
        local_60 = ftell(file_data);
        if (local_60 == -1) {
          puts("An error occured");
        }
        rewind(file_data);
        local_28 = 0;
        local_20 = 0;
        sVar1 = fread(&local_28,1,0x10,file_data);
        local_78 = (int)sVar1;
        if (local_78 == 0x10) {
          success = memcmp(&magic_bytes,&local_28,0x10);
          if (success == 0) {
            sVar1 = fread(&local_84,4,1,file_data);
            local_78 = (int)sVar1;
            if (local_78 == 1) {
              buf1 = safe_calloc(local_84 << 2);
              buf2 = safe_calloc(local_84 << 3);
              load_program_segments(buf1,buf2,local_84,file_data);
              local_48 = ftell(file_data);
              local_74 = (int)local_60 - (int)local_48;
              local_40 = (void *)safe_calloc(local_74);
              if (local_40 == (void *)0x0) {
                puts("An error occured");
                fclose(file_data);
                success = -1;
              }
              else {
                sVar1 = fread(local_40,1,(long)local_74,file_data);
                local_78 = (int)sVar1;
                if (local_78 == local_74) {
                  execute_bytecode(buf1,buf2,local_84,local_40,argc + -2,argv);
                  secure_free_memory(buf1,local_84 << 2);
                  secure_free_memory(buf2,local_84 << 3);
                  fclose(file_data);
                  file_data = (FILE *)0x0;
                  success = 0;
                }
                else {
                  puts("An error occured");
                  fclose(file_data);
                  success = -1;
                }
              }
            }
            else {
              puts("An error occured");
              fclose(file_data);
              success = -1;
            }
          }
          else {
            puts("Invalid file signature!");
            fclose(file_data);
            success = -1;
          }
        }
        else {
          puts("Invalid file!");
          fclose(file_data);
          success = -1;
        }
      }
      else {
        puts("An error occured");
        success = -1;
      }
    }
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return success;
}
```

As you can see the binary does the following:
+ Checks for a .sad file in the CLI arguments
+ Opens the file, and verifies that its first bytes match the "SAD" magic bytes
+ Loads some data from the file segments
+ Loads bytecode and executes it

### execute_bytecode() function

If you want to look into how this VM works, here is the function which executes the bytecode:

```C

void execute_bytecode(long buf1,long buf2,int param_3,long param_4,int param_5,long param_6)

{
  undefined1 uVar1;
  int iVar2;
  long *plVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  undefined8 *puVar6;
  long lVar7;
  long in_FS_OFFSET;
  int i;
  int local_5ffc;
  long *heap;
  undefined1 registers [16];
  undefined8 modulo;
  long local_5e08;
  long rip;
  undefined1 stack [8016];
  long heap_stuff [1002];
  undefined1 local_1f58 [8008];
  long canary;
  byte opcode;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  init_registers(registers);
  init_stack(stack);
  init_stack(heap_stuff);
  stack_push(stack,heap_stuff);
  stack_push(heap_stuff,0xffffffffffffffff);
  for (i = 0; i < param_5; i = i + 1) {
    stack_push(heap_stuff,*(undefined8 *)(param_6 + (long)i * 8));
  }
  rip = 0;
  heap = heap_stuff;
  while (iVar2 = stack_is_empty(stack), iVar2 == 0) {
    opcode = *(byte *)(param_4 + rip);
    iVar2 = (int)rip;
    if (opcode == 0x99) {
      opcode = read_byte(param_4,iVar2 + 1);
      local_5e08 = 0;
      syscall((long)registers,heap,(ulong)opcode);
      if (local_5e08 == -1) break;
      rip = rip + 2;
    }
    else if (opcode < 0x9a) {
      if (opcode == 0x40) {
        rip = *heap;
        if (rip == -1) break;
        heap = (long *)stack_pop(stack);
      }
      else if (opcode < 0x41) {
        if (opcode == 0x3f) {
          lVar7 = read_qword_le(param_4,iVar2 + 1);
          init_stack(local_1f58);
          stack_push(stack,local_1f58);
          stack_push(local_1f58,rip + 9);
          rip = lVar7 + rip;
        }
        else if (opcode < 0x40) {
          if (opcode == 0x3e) {
            lVar7 = read_qword_le(param_4,iVar2 + 1);
            uVar1 = read_byte(param_4,(int)rip + 9);
            uVar4 = get_register_pointer(registers,uVar1);
            uVar1 = read_byte(param_4,(int)rip + 10);
            uVar5 = get_register_pointer(registers,uVar1);
            iVar2 = not_equal_compare(uVar4,uVar5);
            if (iVar2 == 0) {
              rip = rip + 0xb;
            }
            else {
              rip = lVar7 + rip;
            }
          }
          else if (opcode < 0x3f) {
            if (opcode == 0x3d) {
              lVar7 = read_qword_le(param_4,iVar2 + 1);
              uVar1 = read_byte(param_4,(int)rip + 9);
              uVar4 = get_register_pointer(registers,uVar1);
              uVar1 = read_byte(param_4,(int)rip + 10);
              uVar5 = get_register_pointer(registers,uVar1);
              iVar2 = equal_compare(uVar4,uVar5);
              if (iVar2 == 0) {
                rip = rip + 0xb;
              }
              else {
                rip = lVar7 + rip;
              }
            }
            else if (opcode < 0x3e) {
              if (opcode == 0x3c) {
                lVar7 = read_qword_le(param_4,iVar2 + 1);
                uVar1 = read_byte(param_4,(int)rip + 9);
                uVar4 = get_register_pointer(registers,uVar1);
                uVar1 = read_byte(param_4,(int)rip + 10);
                uVar5 = get_register_pointer(registers,uVar1);
                iVar2 = less_equal_compare(uVar4,uVar5);
                if (iVar2 == 0) {
                  rip = rip + 0xb;
                }
                else {
                  rip = lVar7 + rip;
                }
              }
              else if (opcode < 0x3d) {
                if (opcode == 0x3b) {
                  lVar7 = read_qword_le(param_4,iVar2 + 1);
                  uVar1 = read_byte(param_4,(int)rip + 9);
                  uVar4 = get_register_pointer(registers,uVar1);
                  uVar1 = read_byte(param_4,(int)rip + 10);
                  uVar5 = get_register_pointer(registers,uVar1);
                  iVar2 = greater_equal_compare(uVar4,uVar5);
                  if (iVar2 == 0) {
                    rip = rip + 0xb;
                  }
                  else {
                    rip = lVar7 + rip;
                  }
                }
                else if (opcode < 0x3c) {
                  if (opcode == 0x3a) {
                    lVar7 = read_qword_le(param_4,iVar2 + 1);
                    uVar1 = read_byte(param_4,(int)rip + 9);
                    uVar4 = get_register_pointer(registers,uVar1);
                    uVar1 = read_byte(param_4,(int)rip + 10);
                    uVar5 = get_register_pointer(registers,uVar1);
                    iVar2 = less_than_compare(uVar4,uVar5);
                    if (iVar2 == 0) {
                      rip = rip + 0xb;
                    }
                    else {
                      rip = lVar7 + rip;
                    }
                  }
                  else if (opcode < 0x3b) {
                    if (opcode == 0x39) {
                      lVar7 = read_qword_le(param_4,iVar2 + 1);
                      uVar1 = read_byte(param_4,(int)rip + 9);
                      uVar4 = get_register_pointer(registers,uVar1);
                      uVar1 = read_byte(param_4,(int)rip + 10);
                      uVar5 = get_register_pointer(registers,uVar1);
                      iVar2 = greater_than_compare(uVar4,uVar5);
                      if (iVar2 == 0) {
                        rip = rip + 0xb;
                      }
                      else {
                        rip = lVar7 + rip;
                      }
                    }
                    else if (opcode < 0x3a) {
                      if (opcode == 0x38) {
                        lVar7 = read_qword_le(param_4,iVar2 + 1);
                        rip = lVar7 + rip;
                      }
                      else if (opcode < 0x39) {
                        if (opcode == 0x23) {
                          uVar1 = read_byte(param_4,iVar2 + 1);
                          uVar4 = get_register_pointer(registers,uVar1);
                          uVar5 = read_qword_le(param_4,(int)rip + 2);
                          store_qword(uVar4,uVar5);
                          rip = rip + 10;
                        }
                        else if (opcode < 0x24) {
                          if (opcode == 0x22) {
                            uVar1 = read_byte(param_4,iVar2 + 1);
                            plVar3 = (long *)get_register_pointer(registers,uVar1);
                            iVar2 = FUN_001016f3(param_4,(int)rip + 2);
                            if (plVar3 == &local_5e08) {
                              for (local_5ffc = 0; local_5ffc < param_3; local_5ffc = local_5ffc + 1
                                  ) {
                                if (iVar2 == *(int *)(buf1 + (long)local_5ffc * 4)) {
                                  local_5e08 = *(long *)(buf2 + (long)local_5ffc * 8);
                                }
                              }
                            }
                            else {
                              store_dword(plVar3,iVar2);
                            }
                            rip = rip + 6;
                          }
                          else if (opcode < 0x23) {
                            if (opcode == 0x21) {
                              uVar1 = read_byte(param_4,iVar2 + 1);
                              uVar4 = get_register_pointer(registers,uVar1);
                              uVar1 = read_byte(param_4,(int)rip + 2);
                              store_byte(uVar4,uVar1);
                              rip = rip + 3;
                            }
                            else if (opcode < 0x22) {
                              if (opcode == 0x20) {
                                uVar1 = read_byte(param_4,iVar2 + 1);
                                uVar4 = get_register_pointer(registers,uVar1);
                                uVar1 = read_byte(param_4,(int)rip + 2);
                                uVar5 = get_register_pointer(registers,uVar1);
                                copy_register(uVar4,uVar5);
                                rip = rip + 3;
                              }
                              else if (opcode < 0x21) {
                                if (opcode == 0x19) {
                                  uVar1 = read_byte(param_4,iVar2 + 1);
                                  puVar6 = (undefined8 *)get_register_pointer(registers,uVar1);
                                  uVar4 = stack_pop_wrapper(heap);
                                  *puVar6 = uVar4;
                                  rip = rip + 2;
                                }
                                else if (opcode < 0x1a) {
                                  if (opcode == 0x18) {
                                    uVar1 = read_byte(param_4,iVar2 + 1);
                                    uVar4 = get_register_pointer(registers,uVar1);
                                    stack_push_wrapper(heap,uVar4);
                                    rip = rip + 2;
                                  }
                                  else if (opcode < 0x19) {
                                    if (opcode == 0x17) {
                                      uVar1 = read_byte(param_4,iVar2 + 1);
                                      uVar4 = get_register_pointer(registers,uVar1);
                                      uVar1 = read_byte(param_4,(int)rip + 2);
                                      uVar5 = get_register_pointer(registers,uVar1);
                                      bitwise_xor_operation(uVar4,uVar5);
                                      rip = rip + 3;
                                    }
                                    else if (opcode < 0x18) {
                                      if (opcode == 0x16) {
                                        uVar1 = read_byte(param_4,iVar2 + 1);
                                        uVar4 = get_register_pointer(registers,uVar1);
                                        uVar1 = read_byte(param_4,(int)rip + 2);
                                        uVar5 = get_register_pointer(registers,uVar1);
                                        bitwise_and_operation(uVar4,uVar5);
                                        rip = rip + 3;
                                      }
                                      else if (opcode < 0x17) {
                                        if (opcode == 0x15) {
                                          uVar1 = read_byte(param_4,iVar2 + 1);
                                          uVar4 = get_register_pointer(registers,uVar1);
                                          uVar1 = read_byte(param_4,(int)rip + 2);
                                          uVar5 = get_register_pointer(registers,uVar1);
                                          bitwise_or_operation(uVar4,uVar5);
                                          rip = rip + 3;
                                        }
                                        else if (opcode < 0x16) {
                                          if (opcode == 0x14) {
                                            uVar1 = read_byte(param_4,iVar2 + 1);
                                            uVar4 = get_register_pointer(registers,uVar1);
                                            uVar1 = read_byte(param_4,(int)rip + 2);
                                            uVar5 = get_register_pointer(registers,uVar1);
                                            float_div_operation(uVar4,uVar5);
                                            rip = rip + 3;
                                          }
                                          else if (opcode < 0x15) {
                                            if (opcode == 0x13) {
                                              uVar1 = read_byte(param_4,iVar2 + 1);
                                              uVar4 = get_register_pointer(registers,uVar1);
                                              uVar1 = read_byte(param_4,(int)rip + 2);
                                              uVar5 = get_register_pointer(registers,uVar1);
                                              modulo = div_mod_operation(uVar4,uVar5);
                                              rip = rip + 3;
                                            }
                                            else if (opcode < 0x14) {
                                              if (opcode == 0x12) {
                                                uVar1 = read_byte(param_4,iVar2 + 1);
                                                uVar4 = get_register_pointer(registers,uVar1);
                                                uVar1 = read_byte(param_4,(int)rip + 2);
                                                uVar5 = get_register_pointer(registers,uVar1);
                                                mul_operation(uVar4,uVar5);
                                                rip = rip + 3;
                                              }
                                              else if (opcode < 0x13) {
                                                if (opcode == 0x10) {
                                                  uVar1 = read_byte(param_4,iVar2 + 1);
                                                  uVar4 = get_register_pointer(registers,uVar1);
                                                  uVar1 = read_byte(param_4,(int)rip + 2);
                                                  uVar5 = get_register_pointer(registers,uVar1);
                                                  add_operation(uVar4,uVar5);
                                                  rip = rip + 3;
                                                }
                                                else if (opcode == 0x11) {
                                                  uVar1 = read_byte(param_4,iVar2 + 1);
                                                  uVar4 = get_register_pointer(registers,uVar1);
                                                  uVar1 = read_byte(param_4,(int)rip + 2);
                                                  uVar5 = get_register_pointer(registers,uVar1);
                                                  sub_operation(uVar4,uVar5);
                                                  rip = rip + 3;
                                                }
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  if (canary == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

The VM uses a register file, a stack and a second memory space (which I labeled as heap-stuff lol). There is also a custom syscall table which you can find in my disassembler.


### Disassembler

In order to solve this, I created a segment parser and disassembler in python. Initially I tasked Claude to do it but the result sucked so I turned to writing much of it myself, leaving just the laborious parts to the LLM.  I used u32 and u64 from the pwntools library for unpacking the data.  

```Python
from pwn import u32, u64

def get_register_pointer(param_2):
    registers = [
        'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9',
        'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'r16'
    ]
    
    value_to_index = {
        0x41: 0,  # 65
        0x42: 1,  # 66
        0x43: 2,  # 67
        0x44: 3,  # 68
        0x45: 4,  # 69
        0x46: 5,  # 70
        0x47: 6,  # 71
        0x48: 7,  # 72
        0x49: 8,  # 73
        0x4a: 9,  # 74
        0x4b: 10, # 75
        0x4c: 11, # 76
        0x4d: 12, # 77
        0x4e: 13, # 78
        0x4f: 14, # 79
        0x50: 15, # 80
        0x60: 16, # 96
        0x61: 0,  # 97
        0x62: 1,  # 98
        0x63: 2,  # 99
        0x64: 3,  # 100
        0x65: 4,  # 101
        0x66: 5,  # 102
        0x67: 6,  # 103
        0x68: 7,  # 104
        0x69: 8,  # 105
        0x6a: 9,  # 106
        0x6b: 10, # 107
        0x6c: 11, # 108
        0x6d: 12, # 109
        0x6e: 13, # 110
        0x6f: 14, # 111
        0x70: 15, # 112
        0x71: 16  # 113
    }
    
    return registers[value_to_index[param_2]] if param_2 in value_to_index else None





class segment:
    def __init__(self, size, data):
        self.size = size
        self.data = data

file = b""

with open('chall.sad', 'rb') as f:
    file = f.read()


sys = {
    1: 'puts()',
    2: 'fopen()',
    3: 'fread()',
    4: 'fwrite()',
    5: 'fclose()',
    6: 'malloc()',
    7: 'memset()',
    8: 'ftell()',
    9: 'Error ?'

}


ins = {
    0x10: "ADD",         # reg, reg
    0x11: "SUB",         # reg, reg
    0x12: "MUL",         # reg, reg
    0x13: "DIV",         # reg, reg
    0x14: "FLOAT_DIV",   # reg, reg
    0x15: "OR",          # reg, reg
    0x16: "AND",         # reg, reg
    0x17: "XOR",         # reg, reg
    0x18: "PUSH",        # reg
    0x19: "POP",         # reg
    0x20: "MOV",         # reg, reg
    0x21: "MOVB",        # reg, byte
    0x22: "MOVW",        # reg, dword
    0x23: "MOVQ",        # reg, qword
    0x38: "JMP",         # qword (offset)
    0x39: "JG",          # qword, reg, reg (unknown comparison)
    0x3A: "JL",          # qword, reg, reg (jump if less than)
    0x3B: "JGE",         # qword, reg, reg (jump if greater equal)
    0x3C: "JLE",         # qword, reg, reg (jump if less equal)
    0x3D: "JE",          # qword, reg, reg (jump if equal)
    0x3E: "JNE",         # qword, reg, reg (jump if not equal)
    0x3F: "CALL",        # qword (offset)
    0x40: "RET",         # no operands
    0x99: "SYSCALL",     # byte (syscall number)
}


def get_instruction_size(opcode):
    if opcode == 0x40:
        return 1
    elif opcode in [0x99, 0x18, 0x19]:
        return 2
    elif opcode in [0x20, 0x21] or (0x10 <= opcode <= 0x17):
        return 3
    elif opcode == 0x22:
        return 6
    elif opcode == 0x23:
        return 10
    elif 0x39 <= opcode <= 0x3E:
        return 11


def disassemble(bytecode):
    address = 0
    while bytecode != b"":
        op = bytecode[0]
        #print(f"op = {op}")
        size = get_instruction_size(op)
        #print(f"size = {size}")
        instruction = bytecode[:size]
        if ins[op] in ["ADD", "XOR", "OR", "AND", "MUL", "SUB", "MOV", "DIV"]:
            print(f"  {address:04x}: {ins[op]} {get_register_pointer(instruction[1])}, {get_register_pointer(instruction[2])}")
        elif ins[op] in ["JL", "JG", "JGE", "JLE", "JE", "JNE"]:
            print(f"  {address:04x}: {ins[op]} {get_register_pointer(instruction[-1])}, {get_register_pointer(instruction[-2])}, {hex(u64(instruction[1:-2]))}")
        elif ins[op] in ["MOVB", "MOVQ", "MOVW"]:
            print(f"  {address:04x}: {ins[op]} {get_register_pointer(instruction[1])}, {instruction[2:].hex()}")
        elif ins[op] in ["POP", "PUSH"]:
            print(f"  {address:04x}: {ins[op]} {get_register_pointer(instruction[1])}")
        elif ins[op] == "SYSCALL":
            no = instruction[1]
            print(f"  {address:04x}: {ins[op]} {no} ({sys[no]} operation)\n")
        else:
            print(f"  {address:04x}: {ins[op]} {instruction[1:].hex()}\n")
        bytecode = bytecode[size:]
        address = address + size


i = 0

magic_bytes = file[:16]

i=16

segments = u32(file[16:20])

i=20

s1 = segment(0, b"") 
s2 = segment(0, b"") 
s3 = segment(0, b"") 
s4 = segment(0, b"") 



# Segment 1

s1.size = u32(file[i:i+4])

i=i+4

s1.data = file[i:(s1.size+i)]

i=i+s1.size


# Segment 2

s2.size = u32(file[i:i+4])

i=i+4

s2.data = file[i:(s2.size+i)]

i=i+s2.size

# Segment 3
s3.size = u32(file[i:i+4])

i=i+4

s3.data = file[i:(s3.size+i)]

i=i+s3.size


# Segment 4

s4.size = u32(file[i:i+4])

i=i+4

s4.data = file[i:(s4.size+i)]

i=i+s4.size


bytecode = file[i:]



print(f"Magic Bytes: {magic_bytes}")
print(f"Number of segments: {segments}\n\n")

print(f"S1 size {s1.size}")
print(f"S1 data {s1.data}\n\n")

print(f"S2 size {s2.size}")
print(f"S2 data {s2.data}\n\n")

print(f"S3 size {s3.size}")
print(f"S3 data {s3.data}\n\n")

print(f"S4 size {s4.size}")
print(f"S4 data {s4.data}\n\n")

print(f"Bytecode size: {len(bytecode)}")

print("\n\n++++++++++++ DISASSEMBLY ++++++++++++\n\n")

disassemble(bytecode)
```

### The unintended ;)

Now, I'm still a n00b reverser so writing a disassembler was not an easy task, it took a few hours. However, while writing it I was thinking about how the author generated the encrypted flag file. He must have ran a command like:

`./runner chall.sad ./catt ./catt.enc`

In this case `./catt` is the plain text flag. Then, an idea came to my mind: what if the encryption was symmetric and I just ran the binary on the catt.enc to encrypt it twice, basically decrypting it? 
Running `mv catt.enc catt && ./runner chall.sad ./catt ./catt.enc` encrypts the file twice but no flag :( the encryption was not symmetric after all.

But wait! Who says I can only encrypt the file twice? What if the encryption is not symmetric, but sort of "circles around"? So I made this very simple bash script to keep encrypting the file and look for the flag:

```bash
#!/bin/bash
while :
do
./runner ./chall.sad ./catt ./catt.enc
strings ./catt.enc | grep grey
rm ./catt
mv ./catt.enc ./catt
done
```

The script didn't give me the flag after a few seconds, so I just forgot about it and moved on with the disassembler. However, after a couple of hours I turned back to the terminal I left behind and saw this glorious view:

```
./try.sh
grey{wHy_1_d0_th1s_To_myself_263fea308}
grey{wHy_1_d0_th1s_To_myself_263fea308}
grey{wHy_1_d0_th1s_To_myself_263fea308}
grey{wHy_1_d0_th1s_To_myself_263fea308}
grey{wHy_1_d0_th1s_To_myself_263fea308}
grey{wHy_1_d0_th1s_To_myself_263fea308}
grey{wHy_1_d0_th1s_To_myself_263fea308}
```

The script worked! The encryption does circle around!

### The Disassembly

After 2 hours of working on my solve.py  (and before realizing I had already solved the challenge without knowing it) I managed to get a pretty good disassembly:

##### Binary Segments & Info
```
Magic Bytes: b'SAD\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
Number of segments: 4


S1 size 2
S1 data b'r\x00'


S2 size 2
S2 data b'w\x00'


S3 size 11
S3 data b'googoogaga\x00'


S4 size 5
S4 data b'sDda\x00'


Bytecode size: 463
```

##### Disassembly

```css
  0000: POP r1
  0002: POP r0
  0004: MOVB r2, 00
  0007: PUSH r0
  0009: MOVW r16, 14000000
  000f: PUSH r16
  0011: SYSCALL 2 (fopen() operation)

  0013: JE r2, r0, 0x1bb ; jump to EXIT
  001e: MOV r4, r0
  0021: PUSH r1
  0023: MOVW r16, 1a000000
  0029: PUSH r16
  002b: SYSCALL 2 (fopen() operation)

  002d: JE r2, r0, 0x1a1 ; jump to EXIT
  0038: MOV r5, r0
  003b: PUSH r4
  003d: SYSCALL 8 (ftell() operation)

  003f: MOV r6, r0
  0042: MOVB r0, 02
  0045: PUSH r0
  0047: SYSCALL 6 (malloc() operation)

  0049: JE r2, r0, 0x185 ; jump to EXIT
  0054: MOV r7, r0
  0057: MOVW r16, 2f000000
  005d: PUSH r16
  005f: POP r8
  0061: MOVQ r10, 0000000000000000
  
  
LOOP:

  006b: PUSH r7
  006d: MOVQ r0, 0200000000000000
  0077: PUSH r0
  0079: PUSH r4
  007b: SYSCALL 3 (fread() operation)

  007d: MOVQ r1, 0200000000000000
  0087: JNE r1, r0, 0x147
  0092: MOV r15, r8
  0095: MOV r11, r15
  0098: MOVB r1, 01
  009b: ADD r15, r1
  009e: MOV r12, r15
  00a1: ADD r15, r1
  00a4: MOV r13, r15
  00a7: ADD r15, r1
  00aa: MOV r14, r15
  00ad: MOV r15, r7
  00b0: ADD r15, r1
  00b3: MOV r0, r7
  00b6: MOV r1, r15
  00b9: MOVQ r2, ff00000000000000
  00c3: AND r11, r2
  00c6: AND r0, r2
  00c9: MUL r0, r11
  00cc: AND r12, r2
  00cf: MUL r1, r12
  00d2: ADD r0, r1
  00d5: MOVQ r2, 0001000000000000
  00df: DIV r0, r2
  00e2: MOV r0, r2
  00e5: MOVW r16, 20000000
  00eb: PUSH r16
  00ed: POP r3
  00ef: ADD r3, r10
  00f2: MOV r3, r3
  00f5: MOVQ r2, ff00000000000000
  00ff: AND r3, r2
  0102: XOR r0, r3
  0105: MOVQ r2, 0100000000000000
  010f: ADD r10, r2
  0112: MOVQ r2, 0a00000000000000
  011c: DIV r10, r2
  011f: MOV r10, r2
  0122: MOV r9, r0
  0125: MOV r0, r7
  0128: MOV r1, r15
  012b: MOVQ r2, ff00000000000000
  0135: AND r13, r2
  0138: AND r0, r2
  013b: MUL r0, r13
  013e: AND r14, r2
  0141: MUL r1, r14
  0144: ADD r0, r1
  0147: MOVQ r2, 0001000000000000
  0151: DIV r0, r2
  0154: MOV r0, r2
  0157: MOVW r16, 20000000
  015d: PUSH r16
  015f: POP r3
  0161: ADD r3, r10
  0164: MOV r3, r3
  0167: MOVQ r2, ff00000000000000
  0171: AND r3, r2
  0174: XOR r0, r3
  0177: MOVQ r2, 0100000000000000
  0181: ADD r10, r2
  0184: MOVQ r2, 0a00000000000000
  018e: DIV r10, r2
  0191: MOV r10, r2
  0194: MOV r7, r9
  0197: MOV r15, r0
  019a: PUSH r7
  019c: MOVQ r1, 0200000000000000
  01a6: PUSH r1
  01a8: PUSH r5
  01aa: SYSCALL 4 (fwrite() operation)

  01ac: MOVB r7, 00
  01af: MOVB r15, 00
  01b2: SUB r6, r1
  01b5: MOVQ r1, 0000000000000000
  01bf: JGE r1, r6, 0xfffffffffffffeac ; jump to LOOP
  01ca: PUSH r5
  01cc: SYSCALL 5 (fclose() operation)

EXIT:
  01ce: RET 
```

warriii's reversal w breakpoints
```css
INIT ptr = 0
START LOOP
k0, k1, k2, k3 = sDda
add(sDda, cnter=1) --> k1 = Dda
add(sDda, cnter=1) --> k2 = da
add(sDda, cnter=1) --> k3 = a
add(&aX, cnter=1) --> a (ADDRESS. doesn't alter anything)
?? --> cnter = ptxt_1 = X now
and(k0, 0xff) --> k0 = s
and(pt0, 0xff) --> pt0 = a
mul(pt0, k0) --> pt0 = 0x2b93
and(k1, 0xff) --> k1 = D
mul(pt1, k1) --> pt1 = 0x1760
add(pt0, pt1) --> pt0 = 0x42f3
<collect g0 = googoogaagaa> (looks like we're cycling here)
add(g0, ptr = 0)
and(g0, 0xff) --> g0 = g
?? pt0 = 0xf3 (they mod 256 prob)
xor(pt0, g0) --> pt0 = 0x94
add(ptr, 1) --> ptr = 1
and(k2, 0xff) --> k2 = d
?? pt0, pt1 = aX, X
and(pt0, 0xff) --> pt0 = a
mul(pt0, k2) --> pt0 = 0x25e4
and(k3, 0xff) --> k3 = a
mul(pt1, k3) --> pt1 = 0x2158
add(pt0, pt1) --> pt0 = 0x473c
<collect g0 = googoogaagaa>
add(g0, ptr = 1) --> g0 = oo..
and(g0, 0xff) --> g0 = o
?? pt0 = 0x3c (they mod 256 prob)
xor(pt0, g0) --> pt0 = 0x53
add(ptr, 1) --> ptr = 2
sub(ptxtlen, 2)
REPEAT LOOP
```