######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64

SGX_COMMON_CFLAGS := -m64
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

SGX_COMMON_CFLAGS += -O3 -march=native

######## App Settings ########

Urts_Library_Name := sgx_urts

App_Cpp_Files := App/App.cpp

App_Include_Paths := -IInclude -IApp -I$(SGX_SDK)/include
Java_Include := -I/usr/lib/jvm/default-java/include/ -I/usr/lib/jvm/default-java/include/linux 

App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)
# App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread 
App_Link_Flags += -lsgx_uae_service

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

App_Name := app
sharedObjectJni := libseqencljni.so

######## Enclave Settings ########

Trts_Library_Name := sgx_trts
Service_Library_Name := sgx_tservice
Crypto_Library_Name := sgx_tcrypto

Enclave_Cpp_Files := Enclave/Enclave.cpp 
Misc_Files := ../prog/zpp/utils.c ../prog/zpp/crypto.c ../prog/zpp/base64.c

Enclave_Include_Paths := -IInclude -IEnclave -I../prog/zpp -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++03 -nostdinc++
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=Enclave/Enclave.lds

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)
Misc_Objects := $(Misc_Files:.c=.o) 

Enclave_Name := enclave-seq.so
Signed_Enclave_Name := enclave-seq.signed.so
Enclave_Config_File := Enclave/Enclave.config.xml

.PHONY: all run

all: $(App_Name) $(sharedObjectJni) $(Signed_Enclave_Name)

run: all
	@$(CURDIR)/$(App_Name)
	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"

######## App Objects ########

App/Enclave_u.c: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd App && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

App/Enclave_u.o: App/Enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

App/%.o: App/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"
	
$(App_Name): App/Enclave_u.o $(App_Cpp_Objects) JniInterface.o ../prog/zpp/utils.o
	@echo "LINK =>  $@"
	$(CXX) $^ -o $@ $(App_Link_Flags)

$(sharedObjectJni): App/Enclave_u.o $(App_Cpp_Objects) JniInterface.o ../prog/zpp/utils.o
	@echo "LINK =>  $@"
	$(CXX) $^ -shared -o $@ $(App_Link_Flags)

org_apache_zookeeper_server_SeqEnclave.h: 
	javah -classpath ../zookeeper-3.5.1-alpha/build/classes org.apache.zookeeper.server.SeqEnclave

JniInterface.o: org_apache_zookeeper_server_SeqEnclave.h JniInterface.c
	@echo "CC => $@"
	$(CC) $(App_C_Flags) -I. -I../prog/zpp $(Java_Include) -c JniInterface.c -o $@ 

######## Enclave Objects ########

Enclave/Enclave_t.c: $(SGX_EDGER8R) Enclave/Enclave.edl
	@echo "GEN  =>  $@"
	@cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include

Enclave/Enclave_t.o: Enclave/Enclave_t.c
	@echo "CC   <=  $<"
	@$(CC) $(Enclave_C_Flags) -c $< -o $@

Enclave/%.o: Enclave/%.cpp
	@echo "CXX  <=  $<"
	$(CXX) $(Enclave_Cpp_Flags) -fno-builtin -c $< -o $@

../prog/zpp/%.o: ../prog/zpp/%.c 
	@echo "CC (trusted object build) <= $<"
	$(CC) $(Enclave_C_Flags) -fno-builtin -c $< -o $@

$(Enclave_Name): Enclave/Enclave_t.o $(Enclave_Cpp_Objects) $(Misc_Objects) 
	@echo "LINK =>  $@"
	$(CXX) $^ -o $@ $(Enclave_Link_Flags)

$(Signed_Enclave_Name): $(Enclave_Name)
	@echo "SIGN =>  $@"
	@$(SGX_ENCLAVE_SIGNER) sign -key Enclave/Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)

.PHONY: clean

clean:
	@rm -f $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) App/Enclave_u.* $(Enclave_Cpp_Objects) Enclave/Enclave_t.* org_apache_zookeeper_server_SeqEnclave.h JniInterface.o $(sharedObjectJni) 
	@rm -f zpp/*.o

