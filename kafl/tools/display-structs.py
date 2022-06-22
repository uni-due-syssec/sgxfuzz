import os
import sys
import msgpack
from treelib import Node, Tree


def read_binary_file(filename):
    with open(filename, 'rb') as f:
        return f.read()

def print_evolves(metadata_dir, ecall=None):
    for filename in os.listdir(metadata_dir):
        metadata_path = metadata_dir + "/" + filename
        metadata = msgpack.unpackb(read_binary_file(metadata_path), raw=False, strict_map_key=False)
        if metadata["info"]["struct"]["ecall"] != ecall:
            continue

        for evolve in metadata["info"]["struct"]["evolves"]:
            evolve_from = evolve["from"].decode()
            evolve_to = evolve["to"].decode()
            evolve_parent = evolve["parent"].decode()
            print(evolve["parent_id"], "->", evolve["id"])
            print(evolve_from, "->", evolve_to)

            if evolve_from != evolve_parent:
                print(evolve_from, "->", evolve_to)

                if evolve_from != evolve_parent:
                    print()
                    print("ALERT: from != parent")
                    print("ALERT:", evolve_from, "!=", evolve_parent)

def print_id_tree(metadata_dir, ecall=None):
    tree = Tree()

    ids = [id[5:] for id in os.listdir(metadata_dir)]
    ids.sort()

    devnull = open(os.devnull, 'w')
    stder = sys.stderr
    sys.stderr = devnull

    for node_id in ids:
        metadata_path = metadata_dir + "/node_" + node_id

        metadata = msgpack.unpackb(read_binary_file(metadata_path), raw=False, strict_map_key=False)

        if metadata["info"]["struct"]["ecall"] != ecall:
            continue

        parent_id = int(metadata["info"]["parent"])
        node_id = int(node_id)

        node_struct = metadata["info"]["struct"]["data"].decode()

        # print("TEST")
        # if node_struct == "40 1 C0 4 0 ":
        #     print(node_id)

        # print(parent_id, "->", node_id)

        if not tree:
            tree.create_node(parent_id, parent_id)

        if node_id not in tree:
            tree.create_node(node_struct, node_id, parent=parent_id)
        #     siblings = tree.siblings(node_id)
        #     if any(sib.tag == node_struct for sib in tree.siblings(node_id)):
        #         tree.remove_node(node_id)

    # for _ in range(0, 100):
    #     for leave in tree.leaves():
    #         # print(leave.identifier)
    #         if any(sib.tag == leave.tag for sib in tree.siblings(leave.identifier)):
    #             tree.remove_node(leave.identifier)
    #
    #     for leave in tree.leaves():
    #         if leave.tag == tree.get_node(leave.bpointer).tag:
    #             tree.remove_node(leave.identifier)

        # for leave in tree.leaves():
        #     parent_siblings = tree.siblings(tree.get_node(leave.bpointer).identifier)

    sys.stder = stder

    tree.show()

def print_evolve_tree(metadata_dir, ecall=None):
    evolve_tree = Tree()
    # tree.create_node("Harry", "harry")

    ids = [id[5:] for id in os.listdir(metadata_dir)]
    ids.sort()

    for filename in ids:  # os.listdir(metadata_dir)
        metadata_path = metadata_dir + "/node_" + filename
        print(metadata_path)
        metadata = msgpack.unpackb(read_binary_file(metadata_path), raw=False, strict_map_key=False)

        if metadata["info"]["struct"]["ecall"] != ecall:
            continue

        print(metadata["info"]["parent"], int(filename))

        # print(filename)
        for evolve in metadata["info"]["struct"]["evolves"]:
            # evolve_from = evolve["from"].decode()
            # evolve_to = evolve["to"].decode()
            evolve_from = int(evolve["parent_id"])
            evolve_to = int(evolve["id"])

            evolve_parent = evolve["parent"].decode()
            print(evolve_from, "->", evolve_to)

            if not evolve_tree:
                print("Adding Root:", evolve_from)
                evolve_tree.create_node(evolve_from, evolve_from)

            # if evolve_from not in evolve_tree:

                # evolve_tree.show()
            if evolve_to not in evolve_tree.subtree(evolve_from):
                print("Adding Child:", evolve_to)
                evolve_tree.create_node(evolve_to, evolve_to, parent=evolve_from)

            # if evolve_from != evolve_parent:
            #     print()
            #     print("ALERT: from != parent")
            #     print("ALERT:", evolve_from, "!=", evolve["parent"])
        # print()

    evolve_tree.show()

def main(workdir, ecall=None):
    metadata_dir = workdir + "/metadata"
    # print_evolves(metadata_dir, ecall)
    # print_evolve_tree(metadata_dir, ecall)
    print_id_tree(metadata_dir, ecall)


if __name__ == "__main__":
    if len(sys.argv) == 2:
        main(sys.argv[1])
    elif len(sys.argv) == 3:
        main(sys.argv[1], ecall=int(sys.argv[2]))
    else:
        print("Missing arguments. Usage:\n\n\t%s </path/to/workdir>\n" % sys.argv[0])
        sys.exit()
