# allow to use Host cuda functions in C/C++
DEF_INCLUDES = @CUDA_INCLUDES@

if WANT_JANSSON
JANSSON_INCLUDES= -I$(top_srcdir)/compat/jansson
else
JANSSON_INCLUDES=
endif

EXTRA_DIST		= autogen.sh README.txt LICENSE.txt \
			  cudaminer.sln cudaminer.vcxproj cudaminer.vcxproj.filters \
			  compat/gettimeofday.c compat/getopt/getopt_long.c cudaminer-config.h.in

SUBDIRS = compat

bin_PROGRAMS = cudaminer

cudaminer_SOURCES	= elist.h miner.h compat.h \
			  compat/inttypes.h compat/stdbool.h compat/unistd.h \
			  compat/sys/time.h compat/getopt/getopt.h \
			  crc32.cpp sha256.cpp \
			  cudaminer.cpp util.cpp log.cpp \
			  api.cpp hashlog.cpp nvml.cpp stats.cpp sysinfos.cpp cuda.cpp \
			  neoscrypt.h neoscrypt.c \
			  neoscrypt/scanhash_neoscrypt.cpp neoscrypt/cuda_neoscrypt.cu

if HAVE_NVML
nvml_defs = -DUSE_WRAPNVML
nvml_libs = -ldl
endif

if HAVE_WINDOWS
cudaminer_SOURCES += compat/winansi.c
endif

cudaminer_LDFLAGS  = $(PTHREAD_FLAGS) @CUDA_LDFLAGS@
cudaminer_LDADD    = -lcurl @JANSSON_LIBS@ @PTHREAD_LIBS@ @WS2_LIBS@ @CUDA_LIBS@ @OPENMP_CFLAGS@ @LIBS@ $(nvml_libs)
cudaminer_CPPFLAGS = @OPENMP_CFLAGS@ $(CPPFLAGS) $(PTHREAD_FLAGS) -fno-strict-aliasing $(JANSSON_INCLUDES) $(DEF_INCLUDES) $(nvml_defs)

nvcc_ARCH = -gencode=arch=compute_50,code=\"sm_50,compute_50\"
#nvcc_ARCH  += -gencode=arch=compute_52,code=\"sm_52,compute_52\"
#nvcc_ARCH  += -gencode=arch=compute_61,code=\"sm_61,compute_61\"

nvcc_FLAGS = $(nvcc_ARCH) @CUDA_INCLUDES@ -I. @CUDA_CFLAGS@
nvcc_FLAGS += $(JANSSON_INCLUDES) --ptxas-options="-v"

# we're now targeting all major compute architectures within one binary.
.cu.o:
	$(NVCC) $(nvcc_FLAGS) --maxrregcount=128 -o $@ -c $<
