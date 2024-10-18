const { getInclusionProof } = require("./merkleTree.js");
const { resolve } = require("path");

const { stringify: tomlStringify } = require("@iarna/toml");
const { writeFile } = require("fs");

const TEST_EMAIL_ADDRESSES = [
    'Dry 914 <dry-914@yandex.com>',
    "aa@oxor.io",
    "ab@oxor.io",
    "ac@oxor.io",
    "ad@oxor.io"
]
const TREE_HIGHT = 8;

function prepareForSerialization(obj) {
    if (obj instanceof Uint8Array) obj = Array.from(obj);

    const typeOfObj = typeof obj;

    if (typeOfObj === "bigint" || typeOfObj === "number") {
        return obj.toString();
    }

    if (Array.isArray(obj)) {
        return obj.map((element) => prepareForSerialization(element));
    }

    if (typeOfObj === "object" && obj !== null) {
        const result = {};
        for (const [key, value] of Object.entries(obj)) {
            result[key] = prepareForSerialization(value);
        }
        return result;
    }

    return obj;
}

function writeProverTOML(inputs, writeTo) {
    inputs = prepareForSerialization(inputs);
    const tomlString = tomlStringify(inputs);

    writeFile(writeTo, tomlString, (err) => {
        if (err) throw err;
        console.log("The Prover file has been saved!");
    });
}

(async function () {
    // convert email address to BigInt
    let members = TEST_EMAIL_ADDRESSES.map((val) => Array.from(Buffer.from(val, 'utf8')));
    members = members.map(val => BigInt('0x' + val.reduce((acc, byte) => acc + byte.toString(16).padStart(2, '0'), '')));

    const { proof, tree } = await getInclusionProof(members[0], members, TREE_HIGHT);

    let data = {
        root: tree.root.toString(),
        path_elements: proof.pathElements,
        path_indices: proof.pathIndices,
        leaf: members[0],
    };
    const pathToWrite = resolve("./Prover_tree.toml");
    writeProverTOML(data, pathToWrite);
})();
