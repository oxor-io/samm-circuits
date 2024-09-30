mod merkle_tree;

use dep::std;
use merkle_tree::compute_merkle_root;

global LEVELS: Field = 5; // Depth of the tree

fn main(
    root: pub Field,
    leaf: Field,
    path_indices: [Field; LEVELS],
    path_elements: [Field; LEVELS],
) {

    // generate merkle root
    let new_root = compute_merkle_root(leaf, path_indices, path_elements);
    assert(new_root == root);
}
