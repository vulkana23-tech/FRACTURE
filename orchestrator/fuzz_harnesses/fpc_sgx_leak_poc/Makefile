SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= SIM
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

include $(SGX_SDK)/buildenv.mk

SGX_COMMON_FLAGS := -m64 -O0 -g -Wall
SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -std=c11
SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -std=c++11

SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

Urts_Library_Name := sgx_urts_sim
Trts_Library_Name := sgx_trts_sim
Service_Library_Name := sgx_tservice_sim
Crypto_Library_Name := sgx_tcrypto

######## App ########

App_Cpp_Files := App/App.cpp
App_Include_Paths := -IApp -I$(SGX_SDK)/include
App_Cpp_Flags := -fPIC $(App_Include_Paths) -DDEBUG -UNDEBUG -UEDEBUG
App_Link_Flags := -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread
App_Cpp_Objects := App/App.o App/Enclave_u.o
App_Name := app

######## Enclave ########

Enclave_Cpp_Files := Enclave/testleak.cpp Enclave/base64.cpp
Enclave_C_Files := Enclave/parson.c
Enclave_Include_Paths := -IEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx

Enclave_C_Flags := $(Enclave_Include_Paths) -nostdinc -fno-builtin -fvisibility=hidden -fpie -fstack-protector
Enclave_Cpp_Flags := $(Enclave_C_Flags) -nostdinc++

Enclave_Link_Flags := -Wl,-z,relro,-z,now,-z,noexecstack \
    -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
    -Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
    -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
    -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
    -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
    -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections \
    -Wl,--version-script=Enclave/Enclave.lds

Enclave_Cpp_Objects := Enclave/testleak.o Enclave/base64.o Enclave/parson.o Enclave/Enclave_t.o

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := Enclave/Enclave.config.xml
Enclave_Test_Key := Enclave/Enclave_private_test.pem

.PHONY: all clean

all: $(App_Name) $(Signed_Enclave_Name)

App/Enclave_u.h: Enclave/Enclave.edl
	@cd App && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

App/Enclave_u.c: App/Enclave_u.h
App/Enclave_u.o: App/Enclave_u.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(App_Cpp_Flags) -c $< -o $@

App/App.o: App/App.cpp App/Enclave_u.h
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(App_Cpp_Flags) -c $< -o $@

$(App_Name): $(App_Cpp_Objects)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

Enclave/Enclave_t.h: Enclave/Enclave.edl
	@cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl --search-path . --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

Enclave/Enclave_t.c: Enclave/Enclave_t.h
Enclave/Enclave_t.o: Enclave/Enclave_t.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(Enclave_C_Flags) -c $< -o $@

Enclave/parson.o: Enclave/parson.c Enclave/Enclave_t.h
	@$(CC) $(SGX_COMMON_CFLAGS) $(Enclave_C_Flags) -c $< -o $@

Enclave/%.o: Enclave/%.cpp Enclave/Enclave_t.h
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(Enclave_Cpp_Flags) -c $< -o $@

Enclave/Enclave.lds:
	@printf 'enclave.so\n{\n    global:\n        g_global_data_sim;\n        g_global_data;\n        enclave_entry;\n        g_peak_heap_used;\n        g_peak_rsrv_mem_committed;\n    local:\n        *;\n};\n' > $@

$(Enclave_Name): Enclave/Enclave.lds $(Enclave_Cpp_Objects)
	@$(CXX) $(Enclave_Cpp_Objects) -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@[ -f $(Enclave_Test_Key) ] || openssl genrsa -out $(Enclave_Test_Key) -3 3072
	@$(SGX_ENCLAVE_SIGNER) sign -key $(Enclave_Test_Key) -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

clean:
	@rm -f $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) App/*.o App/Enclave_u.* Enclave/*.o Enclave/Enclave_t.* Enclave/Enclave.lds $(Enclave_Test_Key)
