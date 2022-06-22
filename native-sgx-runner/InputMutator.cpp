
#include <random>
#include <iostream>
#include "InputMutator.h"

void InputMutator::fillDeterministic(InputNode& in) {
    fillRandom(in, reinterpret_cast<uint64_t>(in.get_cbuf()));
}

void InputMutator::fillRandom(InputNode& in, uint64_t seed) {
    std::random_device rd;
    std::mt19937 gen(rd());
    if (seed)
        gen.seed(seed);
    std::uniform_int_distribution<> distrib(0, 0xff);

    std::vector<char> data;
    data.reserve(in.getDataSize());
    for (int i = 0; i < in.getDataSize(); ++i)
        data.push_back(distrib(gen));
    in.fillWithData(data.data());
}

bool increaseGuardPage(InputNode& in, uintptr_t fault) {
    if (in.getBuf().isInGuardPage((void*) fault)) {
//        printf("Increase %p\n", in.get_cbuf());
        return in.set_data(in.getSize(), nullptr, 4);
    }
    for (auto&[off, in_c] : in.getChildMap()) {
        if (increaseGuardPage(in_c, fault))
            return true;
    }
    return false;
}

bool makePtrFromData(InputNode& in, uintptr_t fault) {
    constexpr uintptr_t mask = ~(-1L << 47 | 0xff);

    bool found = false;
    int found_idx = 0;
    for (int i = 0; i + 7 < in.getSize(); i++) {
        if ((*(uintptr_t*) &in.get_cbuf()[i] & mask) == (fault & mask)) {
            if (found)
                return false; //double found
            found = true;
            found_idx = i;
        }
    }

    for (auto& p : in.getChildMap())
        if (makePtrFromData(p.second, fault) && found)
            return false; // child would also make ptr

    if (!found)
        return false; // not found
    if (in.getChildMap().contains(found_idx))
        return false; // already pointer

    InputNode& ptr = in.make_ptr(found_idx);
//    printf("Make ptr %p+%d = %p\n", in.get_cbuf(), found_idx, ptr.get_cbuf());
    return true;
}

bool InputMutator::mutateFromBase(InputNode& in) {
    size_t len = in.getDataSize();
    if (base_test_mutation_offset >= len)
        return false;

    base_testcase.resize(len + 4, 0);
    std::vector<char> testcase = base_testcase;
    testcase[base_test_mutation_offset] = 0x42;
    testcase[base_test_mutation_offset + 1] = 0x52;
    testcase[base_test_mutation_offset + 2] = 0x62;
    testcase[base_test_mutation_offset + 3] = 0x72;
    in.fillWithData(testcase.data());
    base_test_mutation_offset++;
    return true;
}

bool InputMutator::mutate(InputNode& in, uintptr_t fault) {
//    printf("FAULT: %p\n", fault);
    if (fault != -1 && increaseGuardPage(in, fault))
        goto next_test;

    {
        bool struct_updated = fault != -1 && makePtrFromData(in, fault);

//        printf("S=%d U=%d\n", stage, struct_updated);
//        if (struct_updated)
//            std::cout << in.serialize() << std::endl;

        while (true) {
            switch (stage) {
                case DETERMINISTIC:
                    if (struct_updated) {
                        fillDeterministic(in);
                        goto next_test;
                    }
//                    printf("Start Zero Test\n");
                    setStageTestcase();
                    continue;
                case RANDOM:
                    if (struct_updated) {
                        // found smth, try testcase
                        std::vector<char> buf;
                        in.getDataBytes(buf);
                        setStageTestcase(buf);
                        continue;
                    }
                    if (--rnd_tests > 0) {
                        // found nothing
                        fillRandom(in);
                        goto next_test;
                    }
                    return false;
                case TESTCASE_BASED:
                    if (mutateFromBase(in))
                        goto next_test;
                    else if (rnd_tests) { // random tests left?
                        setStageRandom(rnd_tests);
                        continue;
                    }
                default:
                    return false;
            }
        }
    }

    next_test:
    post(in);
    return true;
}
