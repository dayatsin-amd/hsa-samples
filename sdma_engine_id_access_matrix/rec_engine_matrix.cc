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
        std::vector<std::vector<uint32_t>> recEngineMatrix(numAgents, std::vector<uint32_t>(numAgents));
        std::vector<std::vector<uint32_t>> engineStatusMatrix(numAgents, std::vector<uint32_t>(numAgents));
        for (size_t i = 0; i < numAgents; ++i) {
                hsa_agent_t srcAgent = agents[i];
                for (size_t j = 0; j < numAgents; ++j) {
                        hsa_agent_t dstAgent = agents[j];
			HSA_CALL2(hsa_amd_memory_get_preferred_copy_engine(dstAgent, srcAgent, &recEngineMatrix[i][j]));
			HSA_CALL2(hsa_amd_memory_copy_engine_status(dstAgent, srcAgent, &engineStatusMatrix[i][j]));
			printf("srcAgent:%08lx dstAgent:%08lx engine-status:%08x preferred-engines-mask:%08x\n", srcAgent.handle, dstAgent.handle, engineStatusMatrix[i][j], recEngineMatrix[i][j]);
                }
		printf("\n");
        }
	printf("\n\nCopy Engine Status (hsa_amd_memory_copy_engine_status)\n");
        printf("+");
        for (size_t i = 0; i < numAgents; ++i) {
                printf("------------+");
                }
                printf("\n");
                for (size_t i = 0; i < numAgents; ++i) {
                        printf("|");
                        for (size_t j = 0; j < numAgents; ++j) {
                                printf(" 0x%08x |", engineStatusMatrix[i][j]);
                        }
                        printf("\n");
                        printf("+");
                        for (size_t i = 0; i < numAgents; ++i) {
                                printf("------------+");
                        }
                        printf("\n");
                }

	printf("\n\nPreferred Copy Engines (hsa_amd_memory_get_preferred_copy_engine)\n");
        printf("+");
        for (size_t i = 0; i < numAgents; ++i) {
                printf("------------+");
                }
                printf("\n");
                for (size_t i = 0; i < numAgents; ++i) {
                        printf("|");
                        for (size_t j = 0; j < numAgents; ++j) {
				if (!recEngineMatrix[i][j])
                               		printf("     --     |");
				else
	                                printf(" 0x%08x |", recEngineMatrix[i][j]);
                        }
                        printf("\n");
                        printf("+");
                        for (size_t i = 0; i < numAgents; ++i) {
                                printf("------------+");
                        }
                        printf("\n");
                }
        HSA_CALL2(hsa_shut_down());
        return 0;
}

