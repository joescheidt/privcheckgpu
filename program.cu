#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <iomanip>
#include <cstring>

#define __GMP_DECLSPEC_XX
#include <gmp.h>

extern "C" {
    #define HAVE_CONFIG_H
    #include "libsecp256k1-config.h"
    #include "secp256k1.c"
    #include "ecmult_big_impl.h"
    #include "secp256k1_batch_impl.h"
}
#include <cuda.h>
#include <cuda_runtime.h>
#include <device_functions.h>
#include <device_launch_parameters.h>

#include "hash.cuh"
#include "bloom.cuh"

struct gpu_t {
    int device;
    int threadsPerBlock;
    int blocksPerGrid;
};
gpu_t getGPUConfiguration(int deviceId) {
    cudaDeviceProp deviceProp;
    cudaGetDeviceProperties(&deviceProp, deviceId);

    // Determine your configuration parameters based on device properties
    int maxThreadsPerBlock = deviceProp.maxThreadsPerBlock;
    int maxBlocksPerGrid = deviceProp.multiProcessorCount;

    // Adjust these values based on your specific requirements
    int threadsPerBlock = 1024;  // Choose an appropriate number based on your kernel requirements
    int blocksPerGrid = maxBlocksPerGrid;

    // Ensure the configuration adheres to device limits
    threadsPerBlock = std::min(threadsPerBlock, maxThreadsPerBlock);
    blocksPerGrid = std::min(blocksPerGrid, maxBlocksPerGrid);

    gpu_t gpuConfig;
    gpuConfig.device = deviceId;
    gpuConfig.threadsPerBlock = threadsPerBlock;
    gpuConfig.blocksPerGrid = blocksPerGrid;

    return gpuConfig;
}

__device__ int KeyFound;

__global__ void pub_check_hash(const unsigned char* bloom, uint8_t *ppubKey , uint32_t *pdigest_c)
{
	unsigned id = blockDim.x * blockIdx.x + threadIdx.x;
    if (KeyFound != -1)
		return;
    hash160(ppubKey + (id * 32), 33, pdigest_c + (id * 5));
    if (bloom_chk_hash160(bloom, pdigest_c)) {
        // Only one thread should set KeyFound to 1.
        atomicExch(&KeyFound, 1);
        
    } else {
        atomicMax(&KeyFound, id);
    }
}

void increment_private_key(unsigned char* privkey) {
    privkey[30] - 1;
    for (int i = 31; i >= 0; i--) {
        if (privkey[i] < 0xFF) {
            privkey[i]++;
            break;
        } else {
            privkey[i] = 0x00;
        }
    }
}

void saveKeyToFile(const unsigned char* privateKey, const uint8_t* pubKey, const uint32_t* hash) {
    // Save to a file (adjust file handling as needed)
    std::ofstream outFile("matching_key.txt");
    if (outFile.is_open()) {
        outFile << "Private Key: ";
        for (int i = 0; i < 32; ++i) {
            outFile << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(privateKey[i]);
        }
        outFile << std::dec << std::endl;

        outFile << "Public Key: ";
        for (int i = 0; i < 33; ++i) {  // Assuming 33 bytes for compressed public key
            outFile << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(pubKey[i]);
        }
        outFile << std::dec << std::endl;

        outFile << "Hash: ";
        for (int i = 0; i < 5; ++i) {
            outFile << std::hex << std::setw(8) << std::setfill('0') << hash[i];
        }
        outFile << std::dec << std::endl;

        outFile.close();
    } else {
        std::cerr << "Error: Failed to open output file." << std::endl;
        // Handle the error as needed
    }
}

void printHash(const uint32_t* hash, int length) {
    printf("Hash: ");
    const uint8_t* hashBytes = reinterpret_cast<const uint8_t*>(hash);
    for (int i = 0; i < length * sizeof(uint32_t); ++i) {
        printf("%02x", hashBytes[i]);
    }
    printf("\n");
}
void printPrivateKey(const unsigned char* privkey, size_t length) {
    if (privkey == nullptr) {
        std::cout << "Private key is null." << std::endl;
        return;
    }

    std::cout << "Private Key: ";
    for (size_t i = 0; i < length; i++) {
        std::cout << std::setfill('0') << std::setw(2) << std::hex << (int)privkey[i];
    }
    std::cout << std::dec << std::endl;
}
void printPubKey(const unsigned char* privkey, size_t length) {
    if (privkey == nullptr) {
        std::cout << "Private key is null." << std::endl;
        return;
    }

    std::cout << "Pubkey Key: ";
    for (size_t i = 0; i < length; i++) {
        std::cout << std::setfill('0') << std::setw(2) << std::hex << (int)privkey[i];
    }
    std::cout << std::dec << std::endl;
}
// Global variables
std::vector<std::string> privateKeys;
std::atomic<int> count(0);
std::mutex mutex;
std::condition_variable cv;
bool finished = false;
std::atomic<bool> keyFound(false);
uint8_t pubkeyFound[33];
unsigned char* bloom_data = nullptr;

void initializeBloomData() {
    std::lock_guard<std::mutex> lock(mutex);

    // Load the bloom data from a file or any other source
    std::ifstream bloomFile("bloom_filter.bin", std::ios::binary);

    if (bloomFile) {
        bloomFile.seekg(0, std::ios::end);
        size_t bloomSize = bloomFile.tellg();
        bloomFile.seekg(0, std::ios::beg);
        unsigned char* bloomData = new unsigned char[bloomSize];
        bloomFile.read(reinterpret_cast<char*>(bloomData), bloomSize);
        // Allocate memory on the CUDA device
        cudaMalloc((void**)&bloom_data, bloomSize);

        // Copy the data from host to device
        cudaMemcpy(bloom_data, bloomData, bloomSize, cudaMemcpyHostToDevice);
        delete[] bloomData; 

        bloomFile.close();
    } else {
        std::cerr << "Error: failed to open bloom filter file." << std::endl;
        // Handle the error as needed
    }
}

// Function to free CUDA memory for bloom_data
void cleanupBloomData() {
    cudaFree(bloom_data);
}

void searchForMatchingKey(const secp256k1_context* ctx, const secp256k1_ecmult_big_context* bmul, gpu_t gpu) {
    
    cudaSetDevice(gpu.device);
    int BLOCK_SIZE = gpu.threadsPerBlock * gpu.blocksPerGrid;

    uint8_t* pubKey = new uint8_t[33];
    uint32_t* hash = new uint32_t[5];

    uint8_t* d_publicKey;
    uint32_t* d_digest_c;

    cudaError_t cudaStatus = cudaMalloc((void**)&d_publicKey, BLOCK_SIZE * (sizeof(uint8_t) * 33));
    if (cudaStatus != cudaSuccess) {
        std::cerr << "cudaMalloc failed: " << cudaGetErrorString(cudaStatus) << std::endl;
        // Handle the error as needed
    }
    cudaError_t cudaStatus1 = cudaMalloc((void**)&d_digest_c, BLOCK_SIZE * (sizeof(uint32_t) * 5));
    if (cudaStatus1 != cudaSuccess) {
        std::cerr << "cudaMalloc failed: " << cudaGetErrorString(cudaStatus) << std::endl;
        // Handle the error as needed
    }

    
    dim3 blockdim(gpu.threadsPerBlock, 1, 1);
    dim3 griddim(gpu.blocksPerGrid, 1, 1);
    std::cout << "GPU Configuration ..";
    int localCount = 0;

    while (true) {
        std::string privateKey;
        {
            std::unique_lock<std::mutex> lock(mutex);
            cv.wait(lock, [] { return !privateKeys.empty() || finished; });
            if (privateKeys.empty() && finished) {
                break;
            }
            privateKey = privateKeys.back();
            privateKeys.pop_back();
        }
    
        std::vector<unsigned char> privateKeyData(32, 0); // Initialize a 32-byte array

        // Convert the hexadecimal string to unsigned char array
        for (int i = 0; i < 32; ++i) {
            std::string byteStr = privateKey.substr(2 * i, 2);
            privateKeyData[i] = static_cast<unsigned char>(std::stoi(byteStr, nullptr, 16));
        }

        unsigned char* privateKeyBytes = privateKeyData.data();
        int nKeyFound = -1;
        cudaMemcpyToSymbol((const void *)&KeyFound, &nKeyFound, sizeof(int), 0, cudaMemcpyHostToDevice);
        for (int i = 0; i < 0x10000; ++i) {
            secp256k1_ec_pubkey_create_serialized(ctx, bmul, pubKey, privateKeyBytes, 1);

            cudaMemcpy(d_publicKey, pubKey,  BLOCK_SIZE * (sizeof(uint8_t) * 33) , cudaMemcpyHostToDevice);
            pub_check_hash<<<griddim, blockdim>>>(bloom_data, d_publicKey, d_digest_c);
            cudaDeviceSynchronize();
            cudaMemcpyFromSymbol(&nKeyFound, (const void *)&KeyFound, sizeof(int), 0, cudaMemcpyDeviceToHost);
            
            if (nKeyFound != -1) {
                std::cout << "Matching key found!" << std::endl;
                printPrivateKey(privateKeyBytes, 32);
                printPubKey(pubKey, 32);
                cudaMemcpy(hash, d_digest_c, sizeof(uint32_t) * 5, cudaMemcpyDeviceToHost);
                printHash(hash, 5);
                saveKeyToFile(privateKeyBytes, pubKey, hash);

                cudaFree(d_publicKey);
                cudaFree(d_digest_c);
                keyFound = true;
                // Notify other threads that this thread has finished
                cv.notify_all();

                break;
            }
            
            increment_private_key(privateKeyBytes);
        }
        cudaFree(d_publicKey);
        delete[] pubKey;

        ++localCount;
        if (localCount % 1000 == 0) {
            std::unique_lock<std::mutex> lock(mutex);
            std::cout << "Thread " << std::this_thread::get_id() << ": Progress: " << count << " checks" << std::endl;
            printPrivateKey(privateKeyBytes, 32);
        }
    }

    std::unique_lock<std::mutex> lock(mutex);
    count -= localCount;
    cv.notify_all();
    cudaFree(d_publicKey);
    cudaFree(d_digest_c);
}

int main() {
    int ngpu;
    cudaGetDeviceCount(&ngpu);

    if (ngpu == 0) {
        std::cerr << "No CUDA devices found." << std::endl;
        return 1;
    }

    // Allocate an array of GPU configurations
    gpu_t* gpuConfigs = new gpu_t[ngpu];

    // Set up GPU configurations for each device
    for (int i = 0; i < ngpu; ++i) {
        gpuConfigs[i] = getGPUConfiguration(i);
    }
    dim3* griddims = new dim3[ngpu];
    dim3* blockdims = new dim3[ngpu];

    for (int i = 0; i < ngpu; ++i) {
        griddims[i].x = gpuConfigs[i].blocksPerGrid;
        griddims[i].y = griddims[i].z = 1;

        blockdims[i].x = gpuConfigs[i].threadsPerBlock;
        blockdims[i].y = blockdims[i].z = 1;
    }

    // Example usage: Print GPU configurations
    for (int i = 0; i < ngpu; ++i) {
        gpu_t gpu = getGPUConfiguration(gpuConfigs[i].device);
        std::cout << "GPU " << i << " Configuration:" << std::endl;
        std::cout << "  Device ID: " << gpu.device << std::endl;
        std::cout << "  Threads per Block: " << gpu.threadsPerBlock << std::endl;
        std::cout << "  Blocks per Grid: " << gpu.blocksPerGrid << std::endl;
        std::cout << "  Grid Dimensions: " << griddims[i].x << " x " << griddims[i].y << " x " << griddims[i].z << std::endl;
        std::cout << "  Block Dimensions: " << blockdims[i].x << " x " << blockdims[i].y << " x " << blockdims[i].z << std::endl;
        std::cout << std::endl;
    }

     // Get the total number of CPU cores
     const int numCores = std::thread::hardware_concurrency();

     // Set the number of threads to the total number of CPU cores multiplied by 2
     const int numThreads = numCores * 2;
 
     // Start the worker threads
     std::vector<std::thread> threads;
     initializeBloomData();
     std::cout << "  Bloom initialize..";
     secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
     unsigned int bmul_size = 24;
     secp256k1_ecmult_big_context* bmul = secp256k1_ecmult_big_create(ctx, bmul_size);
     std::cout << "  secp256k1_ecmult_big_context done!";
     for (int i = 0; i < numThreads; ++i) {
         threads.emplace_back(searchForMatchingKey, ctx, bmul, gpuConfigs[0]);
     }
 
     // Read private keys from standard input
     std::string privateKey;
     while (std::getline(std::cin, privateKey)) {
         {
             std::lock_guard<std::mutex> lock(mutex);
             privateKeys.push_back(privateKey);
         }
         ++count;
         cv.notify_one();
     }
 
     {
         std::lock_guard<std::mutex> lock(mutex);
         finished = true;
     }
     cv.notify_all();
 
     // Wait for all threads to finish
     for (auto& thread : threads) {
         thread.join();
     }
     cleanupBloomData();
     // Free resources used by the secp256k1 library
     secp256k1_context_destroy(ctx);
     secp256k1_ecmult_big_destroy(bmul);
     delete[] gpuConfigs;
     delete[] griddims;
     delete[] blockdims;
     return 0;
 }
