import hashlib

class MerkleTree:
    def __init__(self, data_blocks):
        self.leaves = [hashlib.sha256(data).hexdigest() for data in data_blocks]
        self.root = self.build_tree(self.leaves)

    def build_tree(self, nodes):
        if len(nodes) == 1:
            return nodes[0]
        new_level = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i + 1] if i + 1 < len(nodes) else nodes[i]  # Handle odd number of leaves
            new_level.append(hashlib.sha256((left + right).encode()).hexdigest())
        return self.build_tree(new_level)

# Example usage
data = [b"block0", b"block1", b"block2", b"block3", b"block4", b"block5", b"block6", b"block7"]
tree = MerkleTree(data)
print("Merkle Root Hash:", tree.root)