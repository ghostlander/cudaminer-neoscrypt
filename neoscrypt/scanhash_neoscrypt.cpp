#include <string.h>

#include <cuda.h>
#include <cuda_runtime.h>

#include "../neoscrypt.h"

#include "miner.h"
#include "log.h"

#ifdef _MSC_VER
#define __func__ __FUNCTION__
#include <stdio.h>
#endif

static uint *gmem[MAX_GPUS];
static uint *hash0[MAX_GPUS];
static uint *hash1[MAX_GPUS];
static uint *hash2[MAX_GPUS];

extern void neoscrypt_init(uint thr_id, uint *gmem,
  uint *hash0, uint *hash1, uint *hash2);
extern void neoscrypt_prehash(uint *data, const uint *ptarget);
extern uint neoscrypt_hash(uint thr_id, uint throughput, uint startNonce, uint hash_mode);

extern "C" int scanhash_neoscrypt(int thr_id, uint *pdata, const uint *ptarget,
  uint max_nonce, uint64_t *hashes_done, uint hash_mode) {
    const uint first_nonce = pdata[19];
    uint foundNonce;

    if(opt_benchmark)
      ((uint *) ptarget)[7] = 0x01FF;

    uint intensity = 1, throughput = 0;
    cudaDeviceProp props;
    cudaGetDeviceProperties(&props, device_map[thr_id]);
    if(strstr(props.name, "TITAN Xp")) {
        throughput = 30 * 128 * 32;
        if(!hash_mode) hash_mode = 3;
    }
    else if(strstr(props.name, "1080 Ti")) {
        throughput = 28 * 128 * 32;
        if(!hash_mode) hash_mode = 3;
    }
    else if(strstr(props.name, "1080")) {
        throughput = 20 * 128 * 32;
        if(!hash_mode) hash_mode = 3;
    }
    else if(strstr(props.name, "1070 Ti")) {
        throughput = 19 * 128 * 32;
        if(!hash_mode) hash_mode = 2;
    }
    else if(strstr(props.name, "1070")) {
        throughput = 15 * 128 * 64;
        if(!hash_mode) hash_mode = 2;
    }
    else if(strstr(props.name, "1060 6GB")) {
        throughput = 10 * 128 * 64;
        if(!hash_mode) hash_mode = 2;
    }
    else if(strstr(props.name, "1060 3GB")) {
        throughput = 9 * 128 * 32;
        if(!hash_mode) hash_mode = 2;
    }
    else if(strstr(props.name, "TITAN X")) {
        throughput = 24 * 128 * 32;
        if(!hash_mode) hash_mode = 1;
    }
    else if(strstr(props.name, "980 Ti")) {
        throughput = 22 * 128 * 32;
        if(!hash_mode) hash_mode = 1;
    }
    else if(strstr(props.name, "980")) {
        throughput = 16 * 128 * 32;
        if(!hash_mode) hash_mode = 1;
    }
    else if(strstr(props.name, "970")) {
        throughput = 13 * 128 * 32;
        if(!hash_mode) hash_mode = 1;
    }
    else if(strstr(props.name, "960")) {
        throughput = 8 * 128 * 32;
        if(!hash_mode) hash_mode = 1;
    }
    else if(strstr(props.name, "950")) {
        throughput = 6 * 128 * 64;
        if(!hash_mode) hash_mode = 1;
    }
    else if(strstr(props.name, "750 Ti")) {
        throughput = 5 * 128 * 64;
        if(!hash_mode) hash_mode = 1;
    }
    else if(strstr(props.name, "750")) {
        throughput = 4 * 128 * 64;
        if(!hash_mode) hash_mode = 1;
    }
    else if(strstr(props.name, "TITAN Z")) {
        throughput = 15 * 192 * 32;
        if(!hash_mode) hash_mode = 1;
    }
    else if(strstr(props.name, "TITAN Black")) {
        throughput = 15 * 192 * 32;
        if(!hash_mode) hash_mode = 1;
    }
    else if(strstr(props.name, "TITAN")) {
        throughput = 14 * 192 * 32;
        if(!hash_mode) hash_mode = 1;
    }
    else if(strstr(props.name, "780 Ti")) {
        throughput = 15 * 192 * 16;
        if(!hash_mode) hash_mode = 1;
    }
    else if(strstr(props.name, "780")) {
        throughput = 12 * 192 * 16;
        if(!hash_mode) hash_mode = 1;
    }
    else
      intensity = 14;

    if(!throughput) throughput = 1U << intensity;

#if defined(_WIN32) && !defined(_WIN64)
    if(throughput > 49152) throughput = 49152;
#endif

    throughput = device_intensity(device_map[thr_id], __func__, throughput) / 2;

    static bool init[MAX_GPUS] = { 0 };

    if(!init[thr_id]) {
        cudaSetDevice(device_map[thr_id]);
        cudaDeviceReset();
        cudaSetDeviceFlags(cudaDeviceScheduleBlockingSync);
        cudaDeviceSetCacheConfig(cudaFuncCachePreferL1);
        cudaGetLastError();

        gpulog(LOG_INFO, thr_id, "Intensity set to %g, %u CUDA threads",
          throughput2intensity(throughput * 2), throughput * 2);

        cudaMalloc(&gmem[thr_id], 2 * 32768 * throughput);
        cudaMalloc(&hash0[thr_id], 256 * throughput);
        cudaMalloc(&hash1[thr_id], 256 * throughput);
        cudaMalloc(&hash2[thr_id], 256 * throughput);

        neoscrypt_init(thr_id, gmem[thr_id],
          hash0[thr_id], hash1[thr_id], hash2[thr_id]);

        init[thr_id] = true;
    }

    /* Input data must be little endian already */

    uint data[20];
    uint i;

    for(i = 0; i < 20; i++)
      data[i] = pdata[i];

    neoscrypt_prehash(data, ptarget);

    while(!work_restart[thr_id].restart &&
     ((ullong)max_nonce > ((ullong)(pdata[19]) + (ullong)throughput))) {

        foundNonce = neoscrypt_hash(thr_id, throughput, pdata[19], hash_mode);

        if(foundNonce != 0xFFFFFFFF) {

            if(opt_benchmark)
              gpulog(LOG_INFO, thr_id, "nonce 0x%08X found", foundNonce);

            uint vhash64[8];
            data[19] = foundNonce;

            neoscrypt((uchar *) data, (uchar *) vhash64);

            if(vhash64[7] <= ptarget[7]) {
                pdata[19] = foundNonce;
                *hashes_done = foundNonce - first_nonce + 1;
                return(1);
            } else {
                *hashes_done = foundNonce - first_nonce + 1;
                gpulog(LOG_INFO, thr_id, "nonce 0x%08X fails CPU verification!", foundNonce);
            }

        }

        pdata[19] += throughput;

    } 

    *hashes_done = pdata[19] - first_nonce + 1;
    return(0);
}
