# Copyright 2019-2020 Intel Corporation
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Funny Experimental Scheduler. Appears better than original kAFL
scheduler especially for slow targets.

Idea is to favorize nodes based on speed, depth, number of new edges. Weights
are tuned such that initial/redq/grim stages are processed first for all fav
nodes, then non-favs start getting processed while at the same time the
high-scoring fav nodes will also go through deterministic stages. Particularly
strong fav nodes may overcome the stage buff and go all the way to havoc before
others are done.

Queue sorting can become a bottleneck on large queues or very fast
execution/finding rate.

"""


from fuzzer.technique.helper import rand
from math import log, log2, ceil

# scale arbitrarily large / small inputs down to interval [1,scale]
# supply alternative log to get a better fit
def log_scale(value, scale=1, base=2):

    if value <= base:
        return 1

    if base == 2:
        val = log2(value)
    else:
        val = log(value, base)

    return ceil(scale*val-scale+1)


class Scheduler:

    def __init__(self):
        pass

    # TODO: node skipping by p(x) conflicts with queue sorting..
    def should_be_scheduled(self, queue, node):
        SKIP_CRASHING_PROB = 95
        SKIP_NONFAV_PROB = 95

        if node.get_exit_reason() != "regular":
            if rand.int(100) < SKIP_CRASHING_PROB:
                return False

        if not node.is_favorite() and rand.int(100) < SKIP_NONFAV_PROB:
            return False
        return True

    def score_speed(self, node):
        USEC_PER_SEC = 1000000
        # score = weight*log(time)+log(size), scaled to range of 0-100 (100=best)
        # assume min/max runtime of 1usec to 10sec
        t_max = 10*USEC_PER_SEC
        t_min = 1
        # assume min/max payload size between 1 and 128<<10byte (see config)
        l_max = 128<<10
        l_min = 1

        node_size = min(l_max, max(l_min, node.get_payload_len()))
        node_time = min(t_max, max(t_min, USEC_PER_SEC*node.get_performance()))

        assert(node_size <= l_max), "Payload size %db > %d" % (node.get_payload_len(), l_max)
        assert(node_time <= t_max), "Payload time %ds > %d" % (node.get_performance(), t_max)

        weight = 1.5
        scale = 3
        score = scale * ( weight*log(t_max/node_time) + log(l_max/node_size) )
        return int(score)

    def score_impact(self, node):
        # determine relative desired workload based on fav bits
        # use log scale with small base, and normalize the result to start at 1x
        fav_base = 1.5
        fav_bits = len(node.get_fav_bits())
        return log_scale(fav_bits+fav_base, base=fav_base)

    def score_priority_favs(self, node):
        # determine relative desired workload based on fav bits
        # use log scale with small base, and normalize the result to start at 1x
        #fav_base = 1.5
        #fav_bits = len(node.get_fav_bits())
        #fav_factor = log_scale(favs+fav_base, base=fav_base)
        fav_factor = node.get_fav_factor()

        # extra time in minutes to spend for every fav_factor
        t_fuzz = 60
        
        # time spent fuzzing this node so far
        t_done = max(1, node.node_struct.get("attention_secs",0)//60)

        # Compute node priority for this node, basically the fraction of t_fuzz that still need to be done
        #
        # This is the current 'priority' of each node and sufficiently dynamic so that
        # the queue sorting will prioritize nodes that are lacking behind compared to others,
        # without having to compare a global average to compare against.
        #
        # The algo ensures that nodes which are freshly added end up high in the
        # queue until they are reaching their relative work/time level compared
        # to others.  Also, nodes that get their favs removed down the line are
        # immediately de-prioritized until others are catching up
        prio = fav_factor * t_fuzz/t_done
        
        # avoid filling the queue with busy nodes. really the slaves should handle this..
        return (1-node.is_busy(), prio)
