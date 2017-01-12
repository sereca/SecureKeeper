######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64

SGX_COMMON_CFLAGS := -m64
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

SGX_COMMON_CFLAGS += -O3 -march=native -rdynamic

######## App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

App_Cpp_Files := App/App.cpp

App_Include_Paths := -IInclude -IApp -I$(SGX_SDK)/include

App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)
#App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread
ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

App_Name := app
ZPP_so_Name := libzppjni.so

Zpp_Untrusted_Objects := $(Zpp_Untrusted_C_Files:.c=.o)

Java_Include := -I/usr/lib/jvm/default-java/include/ -I/usr/lib/jvm/default-java/include/linux 

######## Enclave Settings ########


ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
	Crypto_Library_Name := sgx_tcrypto
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
	Crypto_Library_Name := sgx_tcrypto
endif

Enclave_Cpp_Files := Enclave/Enclave.cpp # Enclave/EnclaveCode.cpp
#Zpp_C_Files := $(wildcard zpp/*.c)
Zpp_C_Files := zpp/inputHandler.c zpp/requestHandler.c zpp/responseHandler.c zpp/zookeeper.jute.c zpp/recordio.c zpp/list.c zpp/crypto.c zpp/utils.c zpp/base64.c

Enclave_Include_Paths := -IInclude -IEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport

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
Zpp_C_Objects := $(Zpp_C_Files:.c=.o)

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := Enclave/Enclave.config.xml

.PHONY: all run

all: $(App_Name) $(ZPP_so_Name) $(Signed_Enclave_Name)

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
	
zpp/networkIO.o: zpp/networkIO.c
	@echo "CC (untrusted object build) <= $<"
	$(CC) $(App_C_Flags) -c $< -o $@

$(App_Name): App/Enclave_u.o $(App_Cpp_Objects) $(Zpp_Untrusted_Objects) ZppInterface.o zpp/utils.o
	@echo "LINK =>  $@"
	$(CXX) $^ -o $@ $(App_Link_Flags)

$(ZPP_so_Name): App/Enclave_u.o $(App_Cpp_Objects) $(Zpp_Untrusted_Objects) ZppInterface.o zpp/utils.o
	@echo "LINK =>  $@"
	$(CXX) $^ -shared -o $@ $(App_Link_Flags)

org_apache_zookeeper_server_Zpp.h: 
	javah -classpath ../zookeeper-3.5.1-alpha/build/classes org.apache.zookeeper.server.Zpp

ZppInterface.o: org_apache_zookeeper_server_Zpp.h ZppInterface.c
	@echo "CC => $@"
	$(CC) $(App_C_Flags) -I. $(Java_Include) -c ZppInterface.c -o $@ 

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

zpp/%.o: zpp/%.c 
	@echo "CC (trusted object build) <= $<"
	$(CC) $(Enclave_C_Flags) -fno-builtin -c $< -o $@

$(Enclave_Name): Enclave/Enclave_t.o $(Enclave_Cpp_Objects) $(Zpp_C_Objects) 
	@echo "LINK =>  $@"
	$(CXX) $^ -o $@ $(Enclave_Link_Flags)

$(Signed_Enclave_Name): $(Enclave_Name)
	@echo "SIGN =>  $@"
	@$(SGX_ENCLAVE_SIGNER) sign -key Enclave/Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)

.PHONY: clean

clean:
	@rm -f $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) App/Enclave_u.* $(Enclave_Cpp_Objects) Enclave/Enclave_t.* org_apache_zookeeper_server_Zpp.h ZppInterface.o $(ZPP_so_Name) 
	@rm -f zpp/*.o

