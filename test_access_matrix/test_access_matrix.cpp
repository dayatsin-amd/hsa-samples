#include <cstdio>
#include <iostream>
#include <vector>
#include <hsa/hsa.h>
#include <hsa/hsa_ext_amd.h>

#define HSA_CALL2(cmd) \
do { \
        hsa_status_t error = (cmd);\
        if (error != HSA_STATUS_SUCCESS) {\
                const char* errorStr;\
                hsa_status_string(error, &errorStr);\
                std::cout << "Encountered HSA error (" << errorStr << ") at line " << __LINE__ << " in file " << __FILE__ << "\n";\
                exit(-1);\
        }\
} while (0)

hsa_status_t find_gpu_agents(hsa_agent_t agent, void* data) {
	hsa_status_t status;
	hsa_device_type_t device_type;
        status = hsa_agent_get_info(agent, HSA_AGENT_INFO_DEVICE, &device_type);
        if (status == HSA_STATUS_SUCCESS && device_type == HSA_DEVICE_TYPE_GPU) {
                std::vector<hsa_agent_t>* agents = reinterpret_cast<std::vector<hsa_agent_t>*>(data);
                agents->push_back(agent);
	}
	return HSA_STATUS_SUCCESS;
}
                
                
int main() {
        HSA_CALL2(hsa_init());
        std::vector<hsa_agent_t> agents;
        HSA_CALL2(hsa_iterate_agents(find_gpu_agents, &agents));
        size_t numAgents = agents.size();                
        std::vector<std::vector<hsa_amd_memory_pool_access_t>> accessMatrix(numAgents, std::vector<hsa_amd_memory_pool_access_t>(numAgents));
        for (size_t i = 0; i < numAgents; ++i) {
                hsa_agent_t srcAgent = agents[i];
                for (size_t j = 0; j < numAgents; ++j) {
                        hsa_agent_t dstAgent = agents[j];
                        hsa_amd_memory_pool_t dstPool;
                        HSA_CALL2(hsa_amd_agent_iterate_memory_pools(dstAgent, [](hsa_amd_memory_pool_t pool, void* data) -> hsa_status_t {
                                hsa_amd_memory_pool_t* poolPtr = reinterpret_cast<hsa_amd_memory_pool_t*>(data);
                                *poolPtr = pool;
                                return HSA_STATUS_SUCCESS;
                        }, &dstPool));
                        HSA_CALL2(hsa_amd_agent_memory_pool_get_info(srcAgent, dstPool, HSA_AMD_AGENT_MEMORY_POOL_INFO_ACCESS, &accessMatrix[i][j]));
                }
        }
        printf("+");
        for (size_t i = 0; i < numAgents; ++i) {
                printf("--------+");
                }
                printf("\n");
                for (size_t i = 0; i < numAgents; ++i) {
                        printf("|");
                        for (size_t j = 0; j < numAgents; ++j) {
				printf(" %6s |", accessMatrix[i][j] == HSA_AMD_MEMORY_POOL_ACCESS_NEVER_ALLOWED ? "NEVER" :
                                         accessMatrix[i][j] == HSA_AMD_MEMORY_POOL_ACCESS_ALLOWED_BY_DEFAULT ? "ALLOW" :
                                         "DISALLOW");
                        }
                        printf("\n");
                        printf("+");
                        for (size_t i = 0; i < numAgents; ++i) {
                                printf("--------+");
                        }
                        printf("\n");                
                }
        HSA_CALL2(hsa_shut_down());
        return 0;
}
