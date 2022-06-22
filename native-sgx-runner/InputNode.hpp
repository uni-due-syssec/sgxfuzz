#ifndef NATIVE_SGX_RUNNER_INPUTNODE_HPP
#define NATIVE_SGX_RUNNER_INPUTNODE_HPP

#include <cassert>
#include <memory>
#include <numeric>
#include <map>
#include <cstring>
#include <algorithm>
#include <cstdio>
#include <sstream>
#include <memory>

#include "buffer/GuardedBuffer.h"
#include "buffer/InEnclaveBuffer.h"
#include "buffer/PartialEnclaveBuffer.h"

class InputNode;

class SpecialField {
public:
    [[nodiscard]] virtual char getType() const = 0;
    [[nodiscard]] virtual size_t getSizeInParent() const = 0;

    virtual void serialize_extended(std::stringstream& out) const = 0;
    virtual void show(const InputNode& parent, int indent) const { printf("Field %c", getType()); }
    virtual void apply(InputNode& parent, size_t offset) = 0;
};

class SizeOfField : public SpecialField {
protected:
    size_t buffer_offset;
public:
    explicit SizeOfField(char** buf) { buffer_offset = std::strtoul(*buf, buf, 10); }
    [[nodiscard]] char getType() const override { return 'S'; }
    [[nodiscard]] size_t getSizeInParent() const override { return sizeof(size_t); }
    void serialize_extended(std::stringstream& out) const override { out << buffer_offset; }
    void show(const InputNode& parent, int indent) const override { printf("sizeof(*0x%zx): %lu", buffer_offset, getValue(parent)); };
    void apply(InputNode& parent, size_t offset) override;

    [[nodiscard]] size_t getValue(const InputNode& parent) const;
};

class StrlenField : public SpecialField {
protected:
    size_t buffer_offset;
public:
    explicit StrlenField(char** buf) { buffer_offset = std::strtoul(*buf, buf, 10); }
    [[nodiscard]] char getType() const override { return 'L'; }
    [[nodiscard]] size_t getSizeInParent() const override { return sizeof(size_t); }
    void serialize_extended(std::stringstream& out) const override { out << buffer_offset; }
    void show(const InputNode& parent, int indent) const override { printf("strlen(*0x%zx): %lu", buffer_offset, getValue(parent)); };
    void apply(InputNode& parent, size_t offset) override;

    [[nodiscard]] size_t getValue(const InputNode& parent) const;
};

class InputNode {
private:
    char type;
    NativeEnclave* enclave;

    std::unique_ptr<Buffer> buf;
    std::map<size_t, InputNode> childPtr; // offset -> InputNode
    std::map<size_t, std::unique_ptr<SpecialField>> specialFields; // offset -> SpecialField

public:
    explicit InputNode(NativeEnclave* enclave, char type, size_t init_len = 0) : type(type), enclave(enclave) {
        switch (type) {
            case 'I':
            case 'i':
                buf = std::make_unique<InEnclaveBuffer>(enclave, ::isupper(type));
                break;
            case 'P':
            case 'p':
                buf = std::make_unique<PartialEnclaveBuffer>(enclave, ::isupper(type));
                break;
            case 'Z':
            case 'z':
//                buf = std::make_unique<NullptrBuffer>(enclave, ::isupper(type));
                break;
            case 'C':
            default:
                buf = std::make_unique<GuardedBuffer>();
                break;
        }
        if (!buf->resize(init_len))
            throw std::runtime_error("Cannot allocate buffer");
    }

    [[nodiscard]] auto& getChildMap() { return childPtr; }
    [[nodiscard]] const auto& getCChildMap() const { return childPtr; }
    [[nodiscard]] const auto& getBuf() const { return *buf; }
    [[nodiscard]] size_t getSize() const { return buf->getLen(); }
    [[nodiscard]] char* get_cbuf() const { return buf->getBuf(); }
    [[nodiscard]] char getType() const { return type; }

    [[nodiscard]] bool set_data(size_t offset, const char* data, size_t len) { return buf->set_data(offset, data, len); }
    InputNode& make_ptr(char type_, size_t offset) {
        const auto& ptr = std::find_if(childPtr.cbegin(), childPtr.cend(), [offset](const auto& a) { return a.first <= offset && offset < a.first + sizeof(void*); });
        assert(ptr == childPtr.cend());
        if (!set_data(offset, nullptr, sizeof(void*)))
            throw std::logic_error("Overlapping pointer fields");
//        return childPtr.emplace(std::piecewise_construct, std::forward_as_tuple(offset), std::forward_as_tuple(enclave_base, 'C')).first->second;
        return childPtr.try_emplace(offset, enclave, type_).first->second;
    }

    char* generate() {
        for (auto&[off, child] : childPtr)
            *(void**) (&buf->getBuf()[off]) = child.generate();
        for (auto&[off, field]:specialFields)
            field->apply(*this, off);
        return buf->getBuf();
    }

    [[nodiscard]] size_t getDataSize() const {
        return getSize()
               - childPtr.size() * sizeof(void*)
               - std::accumulate(specialFields.cbegin(), specialFields.cend(), 0, [](const auto a, const auto& b) { return a + b.second->getSizeInParent(); })
               + std::accumulate(childPtr.cbegin(), childPtr.cend(), 0, [](const auto a, const auto& b) { return a + b.second.getDataSize(); });
    }

    /// Fill non-pointer bytes from buf, has to have a size of at least getDataSize().
    /// \param buf
    /// \return consumed bytes
    size_t fillWithData(const char* in_buf) {
        size_t in_i = 0;
        auto itChild = getChildMap().cbegin();
        auto itField = specialFields.cbegin();
        for (uint i = 0; i < getSize(); i++) {
            if (itChild != getChildMap().cend() && itChild->first == i) {
                i += sizeof(void*) - 1;
                ++itChild;
                assert(itChild == getChildMap().cend() || itChild->first > i);
                continue;
            }
            if (itField != specialFields.cend() && itField->first == i) {
                i += itField->second->getSizeInParent() - 1;
                ++itField;
                assert(itField == specialFields.cend() || itField->first > i);
                continue;
            }
            buf->set_data(i, &in_buf[in_i++], 1);
        }

        for (auto& p:getChildMap())
            in_i += p.second.fillWithData(in_buf + in_i);
        return in_i;
    }

    void getDataBytes(std::vector<char>& dst) const {
        auto itChild = childPtr.cbegin();
        auto itField = specialFields.cbegin();
        for (uint i = 0; i < getSize(); i++) {
            if (itChild != childPtr.cend() && itChild->first == i) {
                i += sizeof(void*) - 1;
                ++itChild;
                continue;
            }
            if (itField != specialFields.cend() && itField->first == i) {
                i += itField->second->getSizeInParent() - 1;
                ++itField;
                continue;
            }
            dst.push_back(buf->getBuf()[i]);
        }

        for (auto& p : childPtr)
            p.second.getDataBytes(dst);
    }

/*    std::vector<uint>& serialize(std::vector<uint>& out) const {
        out.push_back(getSize());
        out.push_back(childPtr.size());
        for (auto &[off, ptr] : childPtr) {
            out.push_back(off);
            ptr.serialize(out);
        }
        return out;
    }

    std::string serialize() const {
        std::vector<uint> s;
        serialize(s);

        std::stringstream out;
        for (auto e : s)
            out << e << ",";
        return out.str();
    }*/

    void serialize_extended(std::stringstream& out) const {
        out << getSize() << ":" << (void*) get_cbuf() << " " << childPtr.size() + specialFields.size();
        for (auto &[off, ptr] : childPtr) {
            out << " " << ptr.getType() << off << " ";
            ptr.serialize_extended(out);
        }
        for (auto &[off, ptr] : specialFields) {
            out << " " << ptr->getType() << off << " ";
            ptr->serialize_extended(out);
        }
    }

    [[nodiscard]] std::string serialize_extended() const {
        std::stringstream out;
        serialize_extended(out);
        return out.str();
    }

    const char* deserialize(const char* data) {
        char* end = const_cast<char*>(data);
        assert(set_data(0, nullptr, std::strtoul(end, &end, 10))); // set size
        for (uint childs = std::strtoul(end, &end, 10); childs > 0; --childs) {
            while (*end == ' ') end++;
            char type_ = *end++;
            unsigned long offset = std::strtoul(end, &end, 10);
            switch (type_) {
                // @formatter:off
                case 'C':
                case 'I': case 'i':
                case 'P': case 'p':
                case 'Z': case 'z':
                // @formatter:on
                    end = const_cast<char*>(make_ptr(type_, offset).deserialize(end));
                    break;
                case 'S':
                    specialFields[offset] = std::make_unique<SizeOfField>(&end);
                    break;
                case 'L':
                    specialFields[offset] = std::make_unique<StrlenField>(&end);
                    break;
                default:
                    throw std::logic_error("Unknown child type");
            }
        }
        return end;
    }

    void show() const {
        show(0);
        printf("\n");
    }
private:
    void show(int indent) const {
        printf("%p:\n", buf->getBuf());
        for (uint i = 0; i < getSize(); i++) {
            if (i % 8 == 0) {
                if (i > 0) printf("\n");
                for (int ind = 0; ind < indent; ind++) printf(" ");
                printf("%04x: ", i);
            } else if (i % 8 == 4) {
                printf(" ");
            }
            if (auto c = childPtr.find(i); c != childPtr.end()) {
                c->second.show(indent + 4);
                i += sizeof(void*) - 1;
            } else if (auto s = specialFields.find(i); s != specialFields.end()) {
                s->second->show(*this, indent);
                i += s->second->getSizeInParent() - 1;
            } else {
                if (buf->isReadable())
                    printf("%02x ", (unsigned char) buf->getBuf()[i]);
                else
                    printf("xx ");
            }
        }
    };
};


size_t SizeOfField::getValue(const InputNode& parent) const {
    return parent.getCChildMap().at(buffer_offset).getSize();
}
void SizeOfField::apply(InputNode& parent, size_t offset) {
    *(size_t*) (&parent.get_cbuf()[offset]) = getValue(parent);
}

size_t StrlenField::getValue(const InputNode& parent) const {
    const InputNode& target = parent.getCChildMap().at(buffer_offset);
    if (target.getSize() == 0)
        return 0;
    return strnlen(target.get_cbuf(), target.getSize() - 1) + 1; // SGX SDK includes NULL-Byte in size
}
void StrlenField::apply(InputNode& parent, size_t offset) {
    InputNode& target = parent.getChildMap().at(buffer_offset);
    if (target.getSize() > 0)
        target.get_cbuf()[target.getSize() - 1] = '\0';
    *(size_t*) (&parent.get_cbuf()[offset]) = getValue(parent);
}

#endif //NATIVE_SGX_RUNNER_INPUTNODE_HPP
