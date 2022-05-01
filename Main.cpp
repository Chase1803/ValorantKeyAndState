byte* buffer = (byte*)VirtualAlloc(nullptr, nt.OptionalHeader.SizeOfCode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!buffer) {
			return false;
		}

uintptr_t uworld_addr = PatternScanner((uint8_t*)buffer, nt.OptionalHeader.SizeOfCode, (char*)"\x48\x8D\x05\x00\x00\x00\x00\x45\x8B\xD3\x4E\x8B\x04\xD8\xB8\x25\x49\x92\x24\x41\xF7\xE3", (char*)"xxx????xxxxxxxxxxxxxxx");
		if (!uworld_addr) { 
                        return false; 
                }

                uintptr_t decrypt_out = globals::image_base + 0x1000 + (uworld_addr - (uintptr_t)buffer);
                uint32_t data_offset = read<uint32_t>(decrypt_out + 0x3);

                uintptr_t world_state = decrypt_out + data_offset + 0x7;
                uintptr_t world_key = world_state + 0x38;
