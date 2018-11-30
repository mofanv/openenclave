include ../../../oe_sub.mk

# Workaround for oeoverintelsgx_t.h:53:1: error: function declaration isn't a prototype [-Werror=strict-prototypes]
WARNS=0

ROOT_RELATIVE_PATH = ../../../

../oeoverintelsgx_t.c: ../../oeoverintelsgx.edl
	$(SGX_EDGER8R) --trusted --search-path "../..$(SGX_PATHSEP)$(ROOT_RELATIVE_PATH)$(SGX_RELATIVE_PATH)include" --trusted-dir ".."  ../../oeoverintelsgx.edl

../oeoverintelsgx_t.h: ../../oeoverintelsgx.edl
	$(SGX_EDGER8R) --trusted --search-path "../..$(SGX_PATHSEP)$(ROOT_RELATIVE_PATH)$(SGX_RELATIVE_PATH)include" --trusted-dir ".."  ../../oeoverintelsgx.edl

CFLAGS += -DOE_USE_OPTEE -D__OPTEE__

global-incdirs-y += ..
global-incdirs-y += ../..
global-incdirs-y += ../../../include/optee/Trusted
global-incdirs-y += ../../../include/optee
global-incdirs-y += ../../../include
global-incdirs-y += $(OpteeDir)lib/libutee/include
global-incdirs-y += $(RIoTDir)CyReP/cyrep
global-incdirs-y += $(RIoTDir)CyReP/tcps
global-incdirs-y += $(RIoTDir)External/tinycbor/src
global-incdirs-y += $(OE_SDK_ROOT_PATH)include
global-incdirs-y += $(OE_SDK_ROOT_PATH)3rdparty/mbedtls/mbedtls/include
global-incdirs-y += $(NEW_PLATFORMS_PATH)src/Trusted

srcs-y += ../oeoverintelsgx_t.c
srcs-y += ../../buffer.c
srcs-y += ../CallbackHelper.c
srcs-y += ../cborhelper.c
srcs-y += ../Io.c
srcs-y += ../keygen.c
srcs-y += ../../oeresult.c
srcs-y += ../../optee_common.c
srcs-y += ../oeshim_t.c
srcs-y += ../logapp.c
srcs-y += ../log_ocall_file.c
srcs-y += ../string_t.c

srcs-y += ctype_optee.c
srcs-y += cyres_optee.c
srcs-y += except_optee.c
srcs-y += keygen_optee.c
srcs-y += rand_optee.c
srcs-y += report_optee.c
srcs-y += strings_optee.c
srcs-y += time_optee.c
srcs-y += trpc_optee.c
srcs-y += helper_optee.c
srcs-y += oeresult_optee.c

srcs-y += $(RIoTDir)CyReP/RiotAes128.c
srcs-y += $(RIoTDir)CyReP/RiotBase64.c
srcs-y += $(RIoTDir)CyReP/RiotCrypt.c
srcs-y += $(RIoTDir)CyReP/RiotDerEnc.c
srcs-y += $(RIoTDir)CyReP/RiotEcc.c
srcs-y += $(RIoTDir)CyReP/RiotHmac.c
srcs-y += $(RIoTDir)CyReP/RiotKdf.c
srcs-y += $(RIoTDir)CyReP/RiotSha256.c

srcs-y += $(RIoTDir)CyReP/tcps/TcpsId.c
srcs-y += $(RIoTDir)External/tinycbor/src/cborencoder.c
srcs-y += $(RIoTDir)External/tinycbor/src/cborparser.c
