#pragma once

class plugin {
    unsigned long long lib = reinterpret_cast<unsigned long long>(GetModuleHandle("ClientSA.dll"));
    unsigned int delay = 100;

    unsigned long long find_pattern(std::string_view pattern, std::string_view mask) {
        MEMORY_BASIC_INFORMATION mbi{ 0 };
        if (!VirtualQuery(reinterpret_cast<LPCVOID>(lib), &mbi, sizeof(mbi))) return 0;

        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(mbi.AllocationBase);
        auto pe = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<unsigned long long>(dos) + dos->e_lfanew);
        if (pe->Signature != IMAGE_NT_SIGNATURE) return 0;

        auto now = reinterpret_cast<uint8_t*>(mbi.AllocationBase);
        auto end = now + pe->OptionalHeader.SizeOfImage;

        unsigned long long i = 0;
        while (now < end) {
            for (i = 0; i < mask.size(); i++) {
                if (&now[i] >= end) break;

                auto character = mask[i];
                auto byte = static_cast<uint8_t>(pattern[i]);

                if (character == '?') continue;
                if (now[i] != byte) break;
            };

            if (!mask[i]) return reinterpret_cast<unsigned long long>(now);
            ++now;
        };

        return 0;
    };

    template<typename T>
        void write(void* addr, T value) {
            DWORD oldProt = 0;
            VirtualProtect(addr, sizeof(T), PAGE_EXECUTE_READWRITE, &oldProt);
            *reinterpret_cast<T*>(addr) = value;
            VirtualProtect(addr, sizeof(T), oldProt, NULL);
        };

    bool load_settings() {
        if(!std::filesystem::exists("connect.ini")) return false;
        this->delay = GetPrivateProfileInt("settings", "delay", 100, (std::filesystem::current_path() / "connect.ini").string().c_str());
        return true;
    };

    public:
        plugin() {
            if(!this->load_settings()) {
                mINI::INIFile file_settings("connect.ini");
                mINI::INIStructure settings;
                settings["settings"]["delay"] = "100";
                file_settings.generate(settings);
            };

            std::thread([&]{
                while((lib = reinterpret_cast<unsigned long long>(GetModuleHandle("ClientSA.dll"))) <= 0);

                this->write<unsigned int>((void*)(this->find_pattern("\x48\x05\x80\xC3\xC9\x01\xE9", "xxxxxxx") + 2), 0);
                this->write<unsigned int>((void*)(this->find_pattern("\x48\x05\xB0\x7A\x48\x00\xE9", "xxxxxxx") + 2), 0);
                this->write<unsigned short>((void*)(this->find_pattern("\x8D\x82\xE8\x03\x00\x00\x89\x43\x18", "xxxxxxxxx") + 2), delay);
            }).detach();
        };
};