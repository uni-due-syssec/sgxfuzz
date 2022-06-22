
#include <utility>

#include "NativeEnclave.h"
#include "InputNode.hpp"

#ifndef NATIVE_SGX_RUNNER_INPUTMUTATOR_H
#define NATIVE_SGX_RUNNER_INPUTMUTATOR_H

enum MutatorStage {
    DETERMINISTIC,
    RANDOM,
    TESTCASE_BASED,
};

class InputMutator {
    std::function<void(InputNode&)> post = [](InputNode&) {};
    MutatorStage stage = DETERMINISTIC;

    static const int MAX_RND_TESTS = 100;
    int rnd_tests = MAX_RND_TESTS;

    std::vector<char> base_testcase;
    int base_test_mutation_offset = 0;
public:
    static void fillRandom(InputNode& in, uint64_t seed = 0);
    static void fillDeterministic(InputNode& in);

    void setPostProcess(std::function<void(InputNode&)> f) { post = std::move(f); }

    void setStageDeterministic() { stage = DETERMINISTIC; }
    void setStageRandom(int tests = MAX_RND_TESTS) { stage = RANDOM, rnd_tests = tests; }
    void setStageTestcase(std::vector<char> testcase = {}) { stage = TESTCASE_BASED, base_test_mutation_offset = 0, base_testcase = std::move(testcase); }

    bool mutate(InputNode& in, uintptr_t fault);
private:
    bool mutateFromBase(InputNode& in);
};


#endif //NATIVE_SGX_RUNNER_INPUTMUTATOR_H
