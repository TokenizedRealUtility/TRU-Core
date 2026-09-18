#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#ifndef CL_TARGET_OPENCL_VERSION
#define CL_TARGET_OPENCL_VERSION 200
#endif
#include <CL/cl.h>
#endif

#include "gpu_miner.h"

#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <cstring>
#include <cassert>
#include <cstdint>

// ---------------------------------------------------------------------
// 1)     CLDeviceInfo 
// ---------------------------------------------------------------------
struct CLDeviceInfo {
    cl_platform_id   platform;
    cl_device_id     device;
    std::string      platformName;
    std::string      deviceName;
};

// A couple of shared globals for solution found
static std::atomic<bool> g_found(false);
static std::mutex        g_mutex;
static uint64_t          g_foundNonce     = 0;
static std::vector<unsigned char> g_foundHash(32);

// ---------------------------------------------------------------------
// KERNEL_SRC => plain double-SHA256 (no +21E8 in the kernel)
// Note: Inside this string literal, "uchar" is valid OpenCL type
// ---------------------------------------------------------------------
static const char *KERNEL_SRC = R"CLC(

__constant uint K[64] = {
  0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5,
  0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5,
  0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3,
  0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174,
  0xE49B69C1,0xEFBE4786,0x0FC19DC6,0x240CA1CC,
  0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA,
  0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7,
  0xC6E00BF3,0xD5A79147,0x06CA6351,0x14292967,
  0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13,
  0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85,
  0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3,
  0xD192E819,0xD6990624,0xF40E3585,0x106AA070,
  0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5,
  0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3,
  0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208,
  0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2
};

inline uint ROR(uint x, uint n)
{
    return (x >> n) | (x << (32 - n));
}

inline void sha256_compress(uint state[8], const uint w[16])
{
    uint s[64];
    // expand
    for(int i=0; i<16; i++){
        s[i] = w[i];
    }
    for(int i=16; i<64; i++){
        uint s0 = ROR(s[i-15], 7) ^ ROR(s[i-15],18) ^ (s[i-15] >> 3);
        uint s1 = ROR(s[i-2], 17) ^ ROR(s[i-2],19) ^ (s[i-2] >> 10);
        s[i]    = s[i-16] + s0 + s[i-7] + s1;
    }

    // init
    uint a= state[0], b= state[1], c= state[2], d= state[3];
    uint e= state[4], f= state[5], g= state[6], h= state[7];

    // rounds
    for(int i=0; i<64; i++){
        uint S1   = ROR(e, 6) ^ ROR(e,11) ^ ROR(e,25);
        uint ch   = (e & f) ^ (~e & g);
        uint tmp1 = h + S1 + ch + K[i] + s[i];

        uint S0   = ROR(a, 2) ^ ROR(a,13) ^ ROR(a,22);
        uint maj  = (a & b) ^ (a & c) ^ (b & c);
        uint tmp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + tmp1;
        d = c;
        c = b;
        b = a;
        a = tmp1 + tmp2;
    }

    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

/**
 * doubleSha256_no21E8:
 *   plain 2x SHA-256, no puzzle tweak
 */
inline void doubleSha256_no21E8(__private const uchar *hdr80,
                                __private uchar *out32)
{
    // 1st pass => process 80 bytes => 2 chunks
    uint s1[8] = {
        0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,
        0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U
    };
    // chunk0 => first 64 bytes
    uint w[16];
    for(int i=0; i<16; i++){
        w[i] = ((uint)hdr80[4*i+0] <<24)
             | ((uint)hdr80[4*i+1] <<16)
             | ((uint)hdr80[4*i+2] << 8)
             | ((uint)hdr80[4*i+3] << 0);
    }
    sha256_compress(s1, w);

    // chunk1 => last 16 bytes + padding => total=640 bits
    uchar chunk1[64];
    for(int i=0; i<16; i++){
        chunk1[i] = hdr80[64 + i];
    }
    chunk1[16] = 0x80;
    for(int i=17; i<56; i++){
        chunk1[i] = 0x00;
    }
    // length=640 => big-endian => 0x00000280
    chunk1[56]=0x00; chunk1[57]=0x00; chunk1[58]=0x00; chunk1[59]=0x00;
    chunk1[60]=0x00; chunk1[61]=0x00; chunk1[62]=0x02; chunk1[63]=0x80;

    for(int i=0; i<16; i++){
        w[i] = ((uint)chunk1[4*i+0]<<24)
             | ((uint)chunk1[4*i+1]<<16)
             | ((uint)chunk1[4*i+2]<< 8)
             | ((uint)chunk1[4*i+3]<< 0);
    }
    sha256_compress(s1, w);

    // s1 => 32-byte intermediate
    // 2nd pass => standard single-chunk (256 bits)
    uint s2[8] = {
        0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,
        0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U
    };
    // make 32 big-endian bytes from s1
    uchar temp[32];
    for(int i=0; i<8; i++){
        temp[4*i+0] = (uchar)((s1[i]>>24)&0xFF);
        temp[4*i+1] = (uchar)((s1[i]>>16)&0xFF);
        temp[4*i+2] = (uchar)((s1[i]>> 8)&0xFF);
        temp[4*i+3] = (uchar)( s1[i]      &0xFF);
    }
    // pad => length=256 bits => 0x0100
    uchar chunk2[64];
    for(int i=0; i<32; i++){
        chunk2[i] = temp[i];
    }
    chunk2[32] = 0x80;
    for(int i=33;i<56;i++){
        chunk2[i] = 0x00;
    }
    chunk2[56]=0x00; chunk2[57]=0x00; chunk2[58]=0x00; chunk2[59]=0x00;
    chunk2[60]=0x00; chunk2[61]=0x00; chunk2[62]=0x01; chunk2[63]=0x00;

    for(int i=0; i<16; i++){
        w[i] = ((uint)chunk2[4*i+0]<<24)
             | ((uint)chunk2[4*i+1]<<16)
             | ((uint)chunk2[4*i+2]<< 8)
             | ((uint)chunk2[4*i+3]<< 0);
    }
    sha256_compress(s2, w);

    // s2 => final => store big-endian to out32
    for(int i=0;i<8;i++){
        out32[4*i+0]=(uchar)((s2[i]>>24)&0xFF);
        out32[4*i+1]=(uchar)((s2[i]>>16)&0xFF);
        out32[4*i+2]=(uchar)((s2[i]>> 8)&0xFF);
        out32[4*i+3]=(uchar)( s2[i]     &0xFF);
    }
}

/**
 * adv_sha256_21e8_miner (but no puzzle)
 * => each thread => plain 2x sha256, compare to target
 */
__kernel void adv_sha256_21e8_miner(
    __global uchar* header80,
    ulong startNonce,
    ulong maxNonce,
    __global const uchar* targetBE,
    __global int* foundFlag,
    __global ulong* foundNonce,
    __global uchar* foundHash
)
{
    ulong gid = get_global_id(0);
    if( atomic_cmpxchg(foundFlag,0,0)!=0 ) return;

    ulong nonce= startNonce+ gid;
    if(nonce> maxNonce) return;

    // local copy
    uchar localHdr[80];
    for(int i=0;i<80;i++){
        localHdr[i]= header80[i];
    }
    // overwrite nonce in LE
    localHdr[76]=(uchar)((nonce    )&0xFF);
    localHdr[77]=(uchar)((nonce>>8 )&0xFF);
    localHdr[78]=(uchar)((nonce>>16)&0xFF);
    localHdr[79]=(uchar)((nonce>>24)&0xFF);

    // plain double sha256
    uchar finalHashLocal[32];
    doubleSha256_no21E8(localHdr, finalHashLocal);

    // FIX(patch10): apply the 21E8 tweak to the last 32-bit word (bytes 28..31,
    // big-endian) EXACTLY as the node's verifyBlockDifficulty and the CPU miner
    // do. Without this the GPU solves a different puzzle than the chain accepts.
    {
        uint lastWord = ((uint)finalHashLocal[28] << 24) |
                        ((uint)finalHashLocal[29] << 16) |
                        ((uint)finalHashLocal[30] <<  8) |
                        ((uint)finalHashLocal[31]);
        lastWord = (lastWord + 0x21E8u);
        finalHashLocal[28] = (uchar)((lastWord >> 24) & 0xFF);
        finalHashLocal[29] = (uchar)((lastWord >> 16) & 0xFF);
        finalHashLocal[30] = (uchar)((lastWord >>  8) & 0xFF);
        finalHashLocal[31] = (uchar)( lastWord        & 0xFF);
    }
/*                NEW PATCH
    // FIX(patch10): compare in the SAME order as the node's compare256LE, which
    // iterates byte 31 (most significant) down to byte 0. targetBE is now built
    // in node order (see bitsToTargetArrayFree fix), so this matches consensus.
    bool below=false;
    for(int i=31; i>=0; i--){
        uchar h= finalHashLocal[i];
        uchar t= targetBE[i];
        if(h< t){ below=true; break; }
        if(h> t){ break; }
    }
    if(below){
        if( atomic_cmpxchg(foundFlag,0,1)==0 ){
            *foundNonce= nonce;
            for(int i=0;i<32;i++){
                foundHash[i]= finalHashLocal[i];
            }
        }
    }
}

*/

    bool valid = true;

    for (int i = 31; i >= 0; i--) {
        uchar h = finalHashLocal[i];
        uchar t = targetBE[i];

        if (h < t) {
            valid = true;
            break;
        }

        if (h > t) {
            valid = false;
            break;
        }
    }

    if (valid) {
        if (atomic_cmpxchg(foundFlag, 0, 1) == 0) {
            *foundNonce = nonce;

            for (int i = 0; i < 32; i++) {
                foundHash[i] = finalHashLocal[i];
            }
        }
    }
}

)CLC";

// ---------------------------------------------------------------------
// Here in HOST code, we must use "unsigned char" rather than "uchar."
// ---------------------------------------------------------------------
static void bitsToTargetArrayFree(uint32_t bits, unsigned char out[32])
{
    std::memset(out, 0, 32);

    unsigned int exponent = bits >> 24;
    unsigned int mantissa = bits & 0x007fffff;

    if (exponent < 3) {
        std::memset(out, 0xff, 32);
        return;
    }

    int start = exponent - 3;

    if (start > 29) {
        std::memset(out, 0xff, 32);
        return;
    }

    // Little-endian target
    out[start] = (unsigned char)(mantissa & 0xff);

    if (start + 1 < 32)
        out[start + 1] =
            (unsigned char)((mantissa >> 8) & 0xff);

    if (start + 2 < 32)
        out[start + 2] =
            (unsigned char)((mantissa >> 16) & 0xff);
/*
    // FIX(patch10): use the NODE's exact target layout (utils.cpp) so the target
    // handed to the kernel matches consensus. Node writes the mantissa starting
    // at index (exponent - 3), and compare256LE treats byte 31 as most
    // significant. The previous GPU layout (idx = 32 - exponent) was the mirror
    // image, producing a different target for the same bits.
    std::memset(out, 0, 32);
    unsigned int exponent = bits >> 24;
    unsigned int mantissa = bits & 0x007fffff;

    if (exponent < 3) {
        std::memset(out, 0xff, 32);
        return;
    }
    int start = (int)exponent - 3;
    if (start > 29) {
        std::memset(out, 0xff, 32);
    } else {
        out[start] = (unsigned char)((mantissa >> 16) & 0xff);
        if (start + 1 < 32) out[start + 1] = (unsigned char)((mantissa >> 8) & 0xff);
        if (start + 2 < 32) out[start + 2] = (unsigned char)(mantissa & 0xff);
    }

*/
}

// ---------------------------------------------------------------------
// runDeviceLoop => plain double-SHA256 scanning
// ---------------------------------------------------------------------
static void runDeviceLoop(
    const CLDeviceInfo &info,
    const std::vector<unsigned char> &header80,
    const std::vector<unsigned char> &targetBE,
    uint64_t startNonce,
    uint64_t maxNonce,
    size_t   globalWorkSize,
    size_t   localWorkSize
)
{
    if(g_found.load()) return;

    cl_int err;
    cl_context_properties props[3] = {
        CL_CONTEXT_PLATFORM,
        (cl_context_properties)info.platform,
        0
    };
    cl_context ctx = clCreateContext(props, 1, &info.device, nullptr, nullptr, &err);
    if(err != CL_SUCCESS){
        std::cerr << "[" << info.deviceName << "] clCreateContext error=" << err << "\n";
        return;
    }

#if CL_VERSION_2_0
    cl_command_queue queue = clCreateCommandQueueWithProperties(ctx, info.device, nullptr, &err);
#else
    cl_command_queue queue = clCreateCommandQueue(ctx, info.device, 0, &err);
#endif
    if(err != CL_SUCCESS){
        std::cerr << "[" << info.deviceName << "] clCreateCommandQueue error=" << err << "\n";
        clReleaseContext(ctx);
        return;
    }

    // Build program
    const char *src = KERNEL_SRC;
    size_t srclen   = std::strlen(src);
    cl_program prog = clCreateProgramWithSource(ctx, 1, &src, &srclen, &err);
    if(err != CL_SUCCESS){
        std::cerr << "[" << info.deviceName << "] clCreateProgramWithSource error=" << err << "\n";
        clReleaseCommandQueue(queue);
        clReleaseContext(ctx);
        return;
    }
    err = clBuildProgram(prog, 1, &info.device, nullptr, nullptr, nullptr);
    if(err != CL_SUCCESS){
        size_t logSize = 0;
        clGetProgramBuildInfo(prog, info.device, CL_PROGRAM_BUILD_LOG, 0, nullptr, &logSize);
        std::vector<char> buildLog(logSize + 1);
        clGetProgramBuildInfo(prog, info.device, CL_PROGRAM_BUILD_LOG, logSize, buildLog.data(), nullptr);
        buildLog[logSize] = 0;
        std::cerr << "[" << info.deviceName << "] Build error:\n" << buildLog.data() << "\n";
        clReleaseProgram(prog);
        clReleaseCommandQueue(queue);
        clReleaseContext(ctx);
        return;
    }

    cl_kernel kernel = clCreateKernel(prog, "adv_sha256_21e8_miner", &err);
    if(err != CL_SUCCESS){
        std::cerr << "[" << info.deviceName << "] clCreateKernel error=" << err << "\n";
        clReleaseProgram(prog);
        clReleaseCommandQueue(queue);
        clReleaseContext(ctx);
        return;
    }

    // Create buffers
    cl_mem bufHdr = clCreateBuffer(
        ctx,
        CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR,
        80,
        (void*)header80.data(),
        &err
    );
    cl_mem bufTarg = clCreateBuffer(
        ctx,
        CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR,
        32,
        (void*)targetBE.data(),
        &err
    );
    cl_int zeroI = 0;
    cl_mem bufFoundFlag = clCreateBuffer(ctx,
        CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR,
        sizeof(cl_int),
        &zeroI,
        &err
    );
    cl_ulong zero64 = 0;
    cl_mem bufFoundNonce = clCreateBuffer(ctx,
        CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR,
        sizeof(cl_ulong),
        &zero64,
        &err
    );
    // Use std::vector<unsigned char> in host code
    std::vector<unsigned char> tmpHash(32, 0);
    cl_mem bufFoundHash = clCreateBuffer(ctx,
        CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR,
        32,
        tmpHash.data(),
        &err
    );

    // Set kernel args
    clSetKernelArg(kernel, 0, sizeof(cl_mem), &bufHdr);
    clSetKernelArg(kernel, 1, sizeof(cl_ulong), &startNonce);
    clSetKernelArg(kernel, 2, sizeof(cl_ulong), &maxNonce);
    clSetKernelArg(kernel, 3, sizeof(cl_mem), &bufTarg);
    clSetKernelArg(kernel, 4, sizeof(cl_mem), &bufFoundFlag);
    clSetKernelArg(kernel, 5, sizeof(cl_mem), &bufFoundNonce);
    clSetKernelArg(kernel, 6, sizeof(cl_mem), &bufFoundHash);

    // Adjust globalWorkSize
    size_t adjGWS = ((globalWorkSize + localWorkSize -1)/ localWorkSize)* localWorkSize;
    err = clEnqueueNDRangeKernel(queue, kernel, 1, nullptr, &adjGWS, &localWorkSize, 0, nullptr, nullptr);
    clFinish(queue);
    if(err != CL_SUCCESS){
        std::cerr << "[" << info.deviceName << "] clEnqueueNDRangeKernel err=" << err << "\n";
    }

    // Check if found
    cl_int finalFlag = 0;
    clEnqueueReadBuffer(queue, bufFoundFlag, CL_TRUE, 0, sizeof(cl_int), &finalFlag, 0, nullptr, nullptr);
    if(finalFlag == 1 && !g_found.load()){
        cl_ulong finalN = 0;
        clEnqueueReadBuffer(queue, bufFoundNonce, CL_TRUE, 0, sizeof(cl_ulong), &finalN, 0, nullptr, nullptr);

        std::vector<unsigned char> fH(32);
        clEnqueueReadBuffer(queue, bufFoundHash, CL_TRUE, 0, 32, fH.data(), 0, nullptr, nullptr);

        std::lock_guard<std::mutex> lk(g_mutex);
        if(!g_found.load()){
            g_found = true;
            g_foundNonce = (uint64_t)finalN;
            g_foundHash  = fH;
            std::cout << "[" << info.deviceName << "] Found nonce=" << finalN << "\n";
        }
    }
    else {
        std::cout << "[" << info.deviceName << "] No solution in the given range.\n";
    }

    // cleanup
    clReleaseMemObject(bufHdr);
    clReleaseMemObject(bufTarg);
    clReleaseMemObject(bufFoundFlag);
    clReleaseMemObject(bufFoundNonce);
    clReleaseMemObject(bufFoundHash);
    clReleaseKernel(kernel);
    clReleaseProgram(prog);
    clReleaseCommandQueue(queue);
    clReleaseContext(ctx);
}

// ---------------------------------------------------------------------
// 6) The main function that enumerates GPU devices & spawns threads
// ---------------------------------------------------------------------
bool mineBlockOpenCLAdvanced(
    const std::vector<unsigned char>& header80,
    const std::vector<unsigned char>& targetBE,
    uint64_t startNonce,
    uint64_t maxNonce,
    size_t   globalWorkSize,
    size_t   localWorkSize,
    int      numPipelines,
    int      numRoundsPerThread,
    uint64_t &foundNonce,
    std::vector<unsigned char>& finalHash
)
{
    (void)numPipelines;
    (void)numRoundsPerThread;

    g_found.store(false);
    {
        std::lock_guard<std::mutex> lk(g_mutex);
        g_foundNonce = 0;
        g_foundHash.assign(32, 0);
    }

    // Discover platforms
    cl_uint numPlat = 0;
    clGetPlatformIDs(0, nullptr, &numPlat);
    if(numPlat == 0){
        std::cerr << "[OpenCL] No platforms found.\n";
        return false;
    }
    std::vector<cl_platform_id> plats(numPlat);
    clGetPlatformIDs(numPlat, plats.data(), nullptr);

    // Gather GPU devices
    std::vector<CLDeviceInfo> allDevs;
    for(auto p : plats){
        char pName[256] = {0};
        clGetPlatformInfo(p, CL_PLATFORM_NAME, sizeof(pName), pName, nullptr);
        std::string platName(pName);

        cl_uint numDev=0;
        clGetDeviceIDs(p, CL_DEVICE_TYPE_GPU, 0, nullptr, &numDev);
        if(numDev == 0) continue;
        std::vector<cl_device_id> devs(numDev);
        clGetDeviceIDs(p, CL_DEVICE_TYPE_GPU, numDev, devs.data(), nullptr);

        for(auto d : devs){
            char dName[256] = {0};
            clGetDeviceInfo(d, CL_DEVICE_NAME, sizeof(dName), dName, nullptr);

            CLDeviceInfo info;
            info.platform     = p;
            info.device       = d;
            info.platformName = platName;
            info.deviceName   = dName;
            allDevs.push_back(info);
        }
    }

    if(allDevs.empty()){
        std::cerr << "No GPU devices.\n";
        return false;
    }
    std::cout << "[OpenCL] Found " << allDevs.size() << " GPU device(s).\n";

    // spawn threads
    std::vector<std::thread> threads;
    threads.reserve(allDevs.size());
    for(const auto &dev : allDevs){
        threads.emplace_back([&, dev]() {
            runDeviceLoop(
                dev,
                header80,
                targetBE,
                startNonce,
                maxNonce,
                globalWorkSize,
                localWorkSize
            );
        });
    }
    for(auto &t : threads){
        t.join();
    }

    if(g_found.load()){
        foundNonce = g_foundNonce;
        finalHash  = g_foundHash;
        return true;
    }
    return false;
}
