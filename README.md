# SAMM Circuits

## Dependencies

Noir v0.35.0 <> BB v0.57.0

## Compilation

```
  nargo check
```

## Run tests

```
  nargo test
```

## Generate/verify proof
0. Open build with 2048 signature:
    ```
        cd builds/samm_2048
    ```

1. Generate witness of your Noir program running:
    ```
        nargo execute witness-samm
    ```

2. Prove the valid execution of your Noir program running:
    ```
        bb prove_ultra_honk -b ./target/samm_2048.json -w ./target/witness-samm.gz -o ./target/proof
    ```
    For Solidity Verifier run:
    ```
        bb prove_ultra_keccak_honk -b ./target/samm_2048.json -w ./target/witness-samm.gz -o ./target/proof2048
    ```

3. Compute the verification key for your Noir program running:
    ```
        bb write_vk_ultra_honk -b ./target/samm_2048.json -o ./target/vk
    ```

4. Verify your proof running:
    ```
        bb verify_ultra_honk -k ./target/vk -p ./target/proof
    ```
    If successful, the verification will complete in silence; if unsuccessful, the command will trigger logging of the corresponding error.

5. Generate Solidity Verifier contract:
    ```
        bb contract_ultra_honk -k ./target/vk -c $CRS_PATH -b ./target/samm_2048.json -o ./target/Verifier.sol
    ```

## Helpers

### Parse email

``` 
    cd helpers/email_parser
```

```
    cargo run --release
```

### Generate Merkle Tree

``` 
    cd helpers/member_tree_generator
```

```
    npm install
```

```
    npx run scripts/generateDataForTest.js
```

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.